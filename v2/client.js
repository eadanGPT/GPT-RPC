// client.single.js
// Single-file client implementing pinning, activation, signed RPC, and protected module fetch.

import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { WebSocket } from 'ws';
import { v4 as uuidv4 } from 'uuid';

const CONFIG = {
  url: 'wss://127.0.0.1:8443',
  protocolVersion: '1.0',
  licenseKey: process.env.LICENSE_KEY || 'LIC-TRIAL-123',
  machineId: hash(`${os.platform()}|${os.arch()}|${os.hostname()}`),
  pinPath: './client.pin', // stores pinned Ed25519 SPKI (base64)
  tokenCachePath: './client.token',
  bindWindowMs: 60_000,
  skewMs: 60_000,
};

// ---------- small helpers ----------
function canonical(obj) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object' && v.constructor === Object) {
      return Object.keys(v).sort().reduce((acc, k) => {
        acc[k] = sort(v[k]);
        return acc;
      }, {});
    }
    return v;
  };
  return JSON.stringify(sort(obj));
}

function b64(b) { return Buffer.from(b).toString('base64'); }
function b64ToBuf(s) { return Buffer.from(s, 'base64'); }
function nowMs() { return Date.now(); }
function hash(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function header(typ) {
  return {
    msgId: uuidv4(),
    nonce: uuidv4(),
    ts: nowMs(),
    typ,
    ver: CONFIG.protocolVersion,
  };
}

// ---------- Pin Store ----------
const PinStore = {
  ensurePinned(pubB64) {
    if (!fs.existsSync(CONFIG.pinPath)) {
      fs.writeFileSync(CONFIG.pinPath, pubB64, 'utf8');
      return;
    }
    const curr = fs.readFileSync(CONFIG.pinPath, 'utf8').trim();
    if (curr !== pubB64) throw new Error('Pinned key mismatch');
  },
  getPinned() {
    if (!fs.existsSync(CONFIG.pinPath)) return null;
    return fs.readFileSync(CONFIG.pinPath, 'utf8').trim();
  }
};

// ---------- Token Cache ----------
const TokenCache = {
  load() {
    if (!fs.existsSync(CONFIG.tokenCachePath)) return null;
    try {
      return JSON.parse(fs.readFileSync(CONFIG.tokenCachePath, 'utf8'));
    } catch { return null; }
  },
  save(token, exp, rotateAfter) {
    fs.writeFileSync(CONFIG.tokenCachePath, JSON.stringify({ token, exp, rotateAfter }), 'utf8');
  }
};

// ---------- Sig Verify ----------
async function verifyServerSig(pinnedSpkiB64, kid, payloadStr, sigB64) {
  const spkiPem = Buffer.from(pinnedSpkiB64, 'base64').toString('utf8');
  const pubKey = crypto.createPublicKey(spkiPem);
  return crypto.verify(null, Buffer.from(payloadStr, 'utf8'), pubKey, b64ToBuf(sigB64));
}

// ---------- WS Client ----------
async function run() {
  const ws = new WebSocket(CONFIG.url, { rejectUnauthorized: false, // dev only; keep cert verification in prod
    // You can set headers / subprotocols as needed
  });

  const pending = new Map(); // msgId => resolver
  let pinned = PinStore.getPinned();
  let tokenRec = TokenCache.load();

  ws.on('message', async (raw) => {
    const msg = JSON.parse(raw.toString('utf8'));
    if (msg.typ === 'hello') {
      console.log('[hello]', msg);
      PinStore.ensurePinned(msg.ed25519PublicKeyB64);
      pinned = msg.ed25519PublicKeyB64;
      // Ensure token
      await ensureToken(ws);
      // Demo: call RPC, then get module
      const r = await rpc(ws, 'priceModel', { base: 13, multiplier: 2.5 });
      console.log('[rpc result]', r);
      const mod = await fetchModule(ws);
      console.log('[module loaded] hello("world") =', mod.hello('world'));
      ws.close();
      return;
    }

    // Response routing for request/response
    const res = pending.get(msg.msgId);
    if (res) {
      pending.delete(msg.msgId);
      res(msg);
    }
  });

  ws.on('open', () => console.log('WS open'));
  ws.on('close', () => console.log('WS closed'));
  ws.on('error', (e) => console.error('WS error', e));

  function sendAndWait(obj, expectTyp) {
    return new Promise((resolve, reject) => {
      const id = obj.msgId;
      pending.set(id, (msg) => {
        if (expectTyp && msg.typ !== expectTyp) {
          return reject(new Error(`Unexpected typ ${msg.typ}`));
        }
        resolve(msg);
      });
      ws.send(JSON.stringify(obj));
      // Optional timeout
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error('Timeout'));
        }
      }, 10_000);
    });
  }

  async function ensureToken(ws) {
    tokenRec = TokenCache.load();
    const soon = tokenRec && (tokenRec.exp * 1000 - nowMs() > 60_000);
    if (soon) return;

    const act = {
      ...header('activate'),
      licenseKey: CONFIG.licenseKey,
      machineId: CONFIG.machineId,
      deviceInfo: {
        os: os.platform(),
        arch: os.arch(),
        appVer: '1.0.0',
        hwHash: hash(os.cpus().map(c => c.model).join('|')),
      },
    };
    const res = await sendAndWait(act, 'activated');
    PinStore.ensurePinned(res.ed25519PublicKeyB64);
    tokenRec = { token: res.token, exp: res.exp, rotateAfter: res.rotateAfter };
    TokenCache.save(tokenRec.token, tokenRec.exp, tokenRec.rotateAfter);
  }

  async function rpc(ws, method, params) {
    await ensureToken(ws);
    const msg = { ...header('rpc'), token: tokenRec.token, method, params };
    const res = await sendAndWait(msg, 'rpc_result');
    // Verify signature
    const payloadStr = canonical({
      method,
      result: res.result,
      nonce: res.nonce,
      ts: res.ts,
    });
    const ok = await verifyServerSig(pinned, res.kid, payloadStr, res.sigB64);
    if (!ok) throw new Error('Bad server signature on rpc_result');
    return res.result;
  }

  async function fetchModule(ws) {
    await ensureToken(ws);

    // X25519 ephemeral keypair
    const { privateKey: clientPriv, publicKey: clientPub } = crypto.generateKeyPairSync('x25519');
    const clientPubPem = clientPub.export({ type: 'spki', format: 'pem' });

    const bind = { exp: nowMs() + CONFIG.bindWindowMs, watermark: `lic:${CONFIG.licenseKey}|mac:${CONFIG.machineId}` };
    const msg = { ...header('get_module'), token: tokenRec.token, clientPubX25519Pem: clientPubPem, bind };
    const res = await sendAndWait(msg, 'module');

    // Verify envelope signature
    const payloadStr = canonical({ enc: res.enc, bind, serverPubX25519: res.serverKeys.pubX25519Pem });
    const ok = await verifyServerSig(pinned, res.serverKeys.kid, payloadStr, res.envSigB64);
    if (!ok) throw new Error('Bad server signature on module envelope');

    // Derive session key and decrypt
    const serverPub = crypto.createPublicKey(res.serverKeys.pubX25519Pem);
    const secret = crypto.diffieHellman({ privateKey: clientPriv, publicKey: serverPub });
    const sessionKey = crypto.hkdfSync('sha256', secret, Buffer.from('mod_v2'), Buffer.alloc(0), 32);

    const iv = b64ToBuf(res.enc.iv);
    const ctFull = b64ToBuf(res.enc.ciphertext);
    const ct = ctFull.slice(0, ctFull.length - 16);
    const tag = ctFull.slice(ctFull.length - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    const source = plain.toString('utf8');

    // Basic binding checks
    if (!source.includes(bind.watermark)) throw new Error('Watermark missing');
    if (!source.includes(msg.nonce)) throw new Error('Nonce missing');
    if (!source.includes(String(bind.exp))) throw new Error('Bind exp missing');

    // Load module dynamically from memory
    // The obfuscator returns a self-decoding string; evaluate to get the real module text:
    const decoded = eval(source); // returns original JS module text

    // Create a data URL and import
    const modUrl = 'data:text/javascript;base64,' + Buffer.from(decoded, 'utf8').toString('base64');
    const mod = await import(modUrl);
    return mod;
  }
}

run().catch((e) => {
  console.error('Client error:', e);
  process.exit(1);
});
