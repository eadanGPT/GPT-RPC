import WebSocket from 'ws';
import { v4 as uuidv4 } from 'uuid';
import { generateKeyPairSync, createPrivateKey, createPublicKey, diffieHellman, webcrypto } from 'crypto';
import { writeFileSync, mkdtempSync } from 'fs';
import os from 'os';
import { pathToFileURL } from 'url';

const API_KEY = process.env.API_KEY || 'dev_key_123';
const URL = process.env.URL || `ws://localhost:8080?apiKey=${API_KEY}`;
const LICENSE_KEY = process.env.LICENSE_KEY || 'DEMO-123-456';

let ws;
let PINNED_PUBKEY_B64 = null;
let token = null;

function enc(s){ return new TextEncoder().encode(s); }
function dec(b){ return new TextDecoder().decode(b); }

async function verifySig(pubB64, dataStr, sigB64) {
  const pub = await webcrypto.subtle.importKey('spki', Buffer.from(pubB64,'base64'), { name:'Ed25519' }, false, ['verify']);
  return webcrypto.subtle.verify('Ed25519', pub, Buffer.from(sigB64,'base64'), enc(dataStr));
}

async function deriveKeyAesGcm256(clientPrivPem, serverPubPem) {
  const clientPriv = createPrivateKey(clientPrivPem);
  const serverPub = createPublicKey(serverPubPem);
  const secret = diffieHellman({ privateKey: clientPriv, publicKey: serverPub });
  const baseKey = await webcrypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return webcrypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt: Buffer.from('ws_salt_v1'), info: new Uint8Array([]) },
    baseKey,
    { name:'AES-GCM', length:256 },
    false,
    ['encrypt','decrypt']
  );
}

async function aesGcmDecrypt(key, encObj) {
  const pt = await webcrypto.subtle.decrypt({ name:'AES-GCM', iv: Buffer.from(encObj.iv,'base64') }, key, Buffer.from(encObj.ciphertext,'base64'));
  return dec(pt);
}

function send(type, body={}) {
  ws.send(JSON.stringify({ type, ...body }));
}

function run() {
  ws = new WebSocket(URL);
  ws.on('open', () => {
    console.log('WS connected, requesting hello...');
  });

  ws.on('message', async (raw) => {
    const msg = JSON.parse(String(raw));
    if (msg.type === 'hello') {
      console.log('Server hello:', { hasPubKey: !!msg.ed25519PublicKeyB64 });
      PINNED_PUBKEY_B64 = msg.ed25519PublicKeyB64;
      // Activate
      send('activate', { licenseKey: LICENSE_KEY, machineId: uuidv4() });
      return;
    }

    if (msg.type === 'activated') {
      console.log('Activated:', { exp: msg.exp, plan: msg.plan });
      token = msg.token;

      // Do a signed RPC
      const nonce = uuidv4();
      send('rpc', { token, method:'priceModel', params:{ qty: 250, base: 1.99, regionFactor:1.2, userTier:'pro' }, nonce });
      return;
    }

    if (msg.type === 'rpc_result') {
      console.log('RPC result:', msg.result);
      if (!msg.signatureB64 || !PINNED_PUBKEY_B64) console.warn('No signature or pinned key');
      // Fetch protected module
      const { privateKey, publicKey } = generateKeyPairSync('x25519');
      const clientPrivPem = privateKey.export({ type:'pkcs8', format:'pem' }).toString();
      const clientPubPem = publicKey.export({ type:'spki', format:'pem' }).toString();
      const nonce = uuidv4();
      const exp = Date.now() + 60_000;
      const watermark = `client:${process.pid}:${nonce}`;
      ws._clientPrivPem = clientPrivPem; // stash for decrypt step
      send('get_module', { token, clientPublicKeyPem: clientPubPem, nonce, exp, watermark });
      return;
    }

    if (msg.type === 'module') {
      const toSign = JSON.stringify({ enc: msg.enc, nonce: undefined, exp: undefined }).replace('undefined','"ignored"'); // demo
      // Verify signature on the correct string
      const ok = await (async ()=>{
        const payload = JSON.stringify({ enc: msg.enc, nonce: msg.__nonce, exp: msg.__exp });
        try {
          return await verifySig(PINNED_PUBKEY_B64, payload, msg.signatureB64);
        } catch { return false; }
      })();
      if (!ok) console.warn('Module signature verification failed (demo continues).');

      const aesKey = await deriveKeyAesGcm256(ws._clientPrivPem, msg.server.ecdhPublicKeyPem);
      const moduleSource = await aesGcmDecrypt(aesKey, msg.enc);

      // Load module
      const tmp = mkdtempSync(os.tmpdir() + '/wsmod-');
      const modPath = `${tmp}/mod.mjs`;
      writeFileSync(modPath, moduleSource, 'utf8');
      const mod = await import(pathToFileURL(modPath).href);
      const out = mod.transform('SensitiveModule');
      console.log('Protected module output:', out, { nonce: mod.__nonce, exp: mod.__exp, wm: mod.__watermark });

      ws.close();
      return;
    }

    if (msg.type === 'error' || msg.type === 'rpc_error' || msg.type === 'module_error') {
      console.error('Server error:', msg.error);
    }
  });

  ws.on('close', () => {
    console.log('WS closed');
  });
}

run();
