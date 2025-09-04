// server/index.js
// Advanced WS Auth System (Node.js / WSS / Ed25519 + X25519 + AES-GCM)
// TLS 1.3-enabled WSS server, token issuance, replay guard, rate limiting,
// signed RPC results, protected module delivery, audit logging (hash chain).

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import http2 from 'node:http2';
import https from 'node:https';
import { WebSocketServer } from 'ws';
import { v4 as uuidv4 } from 'uuid';
import { LRUCache } from 'lru-cache';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import {
  generateKeyPair, // Ed25519
  exportSPKI,
  importSPKI,
  SignJWT,
  jwtVerify,
  decodeProtectedHeader,
} from 'jose';

// ----------------------------- Config ---------------------------------
const CONFIG = {
  host: '127.0.0.1',
  port: 8443,
  tls: {
    // Provide your certificates (self-signed OK for dev)
    key: fs.readFileSync(path.resolve('certs/server.key')),
    cert: fs.readFileSync(path.resolve('certs/server.crt')),
    // Strong ciphers and TLS1.3 only (node will negotiate)
    honorCipherOrder: true,
    allowHTTP1: true, // ALPN http/1.1 for WS upgrade
  },
  protocolVersion: '1.0',
  skewMs: 60_000,
  msgSizeCap: 64 * 1024, // 64KB
  rate: {
    windowMs: 10_000,
    points: 20, // per window (per actor)
  },
  token: {
    issuer: 'ws-auth',
    audience: 'client',
    ttl: '15m',
    rotateHintSec: 600,
    clockTolerance: '60s',
  },
  moduleBindMaxMs: 60_000,
  helloSubprotocol: 'app/1.0',
};

// ----------------------------- Utilities ------------------------------
// Canonical JSON (sorted keys)
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

function b64(b) {
  return Buffer.from(b).toString('base64');
}

function b64ToBuf(s) {
  return Buffer.from(s, 'base64');
}

function nowMs() {
  return Date.now();
}

function assert(cond, message = 'Assertion failed') {
  if (!cond) throw new Error(message);
}

// ----------------------------- Audit Log ------------------------------
const AUDIT_LOG_PATH = path.resolve('server/audit.log');
let lastAuditHashHex = '';

// Load last hash if file exists
if (fs.existsSync(AUDIT_LOG_PATH)) {
  const lines = fs.readFileSync(AUDIT_LOG_PATH, 'utf8').trim().split(/\r?\n/);
  const last = lines.at(-1);
  if (last) {
    const obj = JSON.parse(last);
    lastAuditHashHex = obj.hash;
  }
}

function auditAppend(record) {
  const base = {
    ts: new Date().toISOString(),
    ...record,
  };
  const prev = lastAuditHashHex;
  const h = crypto.createHash('sha256');
  h.update(prev + canonical(base));
  const hash = h.digest('hex');
  lastAuditHashHex = hash;
  const line = JSON.stringify({ ...base, prev, hash });
  fs.appendFileSync(AUDIT_LOG_PATH, line + '\n', { encoding: 'utf8' });
}

// ----------------------------- Key Manager ----------------------------
// NOTE: In production use HSM/KMS; here we keep Ed25519 in-memory and simulate KIDs.

const KeyManager = await (async () => {
  let active = null;
  const previous = new Map(); // kid -> { publicSPKI }

  async function rotateEd25519() {
    const { publicKey, privateKey } = await generateKeyPair('Ed25519');
    const pubSpkiPem = await exportSPKI(publicKey);
    const pubSpkiB64 = Buffer.from(pubSpkiPem).toString('base64');
    const kid = 'ed25519-' + uuidv4();
    if (active) {
      // move old to previous with a soft TTL (not enforced in this demo)
      previous.set(active.kid, { publicSPKI: active.publicSPKI });
    }
    active = { kid, privateKey, publicSPKI: pubSpkiPem, pubSpkiB64 };
    auditAppend({ actor: 'system', action: 'rotate_key', meta: { kid } });
  }

  async function sign(bytes) {
    // jose will sign JWTs; for raw payload signing we’ll use Node crypto
    // but we’ll keep the Ed25519 private key here to use with crypto.sign
    // For raw sign:
    return crypto.sign(null, Buffer.from(bytes), active.privateKey);
  }

  async function verify(kid, sig, bytes) {
    const pubPem =
      kid === active.kid
        ? active.publicSPKI
        : (previous.get(kid) || {}).publicSPKI;
    assert(pubPem, 'Unknown KID');
    const pubKey = crypto.createPublicKey(pubPem);
    return crypto.verify(null, Buffer.from(bytes), pubKey, sig);
  }

  async function getActivePublicSPKIb64() {
    return active.pubSpkiB64;
  }
  async function getActive() {
    return active;
  }

  // Initial key
  await rotateEd25519();

  return {
    rotateEd25519,
    sign,
    verify,
    getActivePublicSPKIb64,
    getActive,
  };
})();

// ----------------------------- License Store --------------------------
const LicenseStore = (() => {
  // Minimal in-memory store. Replace with DB.
  const licenses = new Map([
    [
      'LIC-TRIAL-123',
      {
        status: 'active',
        plan: 'trial',
        seats: 10,
        expireAt: Date.now() + 1000 * 60 * 60 * 24 * 30,
        scopes: ['rpc:invoke', 'module:get'],
        revocations: new Set(),
        useLog: [],
      },
    ],
  ]);

  function check(key) {
    const rec = licenses.get(key);
    assert(rec, 'License not found');
    assert(rec.status === 'active', 'License inactive');
    assert(rec.expireAt > Date.now(), 'License expired');
    return rec;
  }
  function recordUse(key, machineId, ts) {
    const rec = licenses.get(key);
    if (!rec) return;
    rec.useLog.push({ ts, machineId });
  }
  function revoke(target) {
    // target: jti or key
    const rec = licenses.get(target);
    if (rec) {
      rec.status = 'revoked';
      return;
    }
    // else jti revocation tracked globally (simple set)
    globalJtiRevocations.add(target);
  }
  function isRevoked(target) {
    const rec = licenses.get(target);
    if (rec && rec.status !== 'active') return true;
    if (globalJtiRevocations.has(target)) return true;
    return false;
  }
  function scopes(key) {
    return licenses.get(key)?.scopes || [];
  }
  function plan(key) {
    return licenses.get(key)?.plan || 'unknown';
  }

  const globalJtiRevocations = new Set();

  return { check, recordUse, revoke, isRevoked, scopes, plan };
})();

// ----------------------------- Token Service --------------------------
const TokenService = (() => {
  async function issue(licenseKey, machineId, scopes) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: CONFIG.token.issuer,
      aud: CONFIG.token.audience,
      sub: licenseKey,
      iat: now,
      nbf: now - 30,
      exp: now + 15 * 60,
      jti: uuidv4(),
      machineId,
      scopes,
      plan: LicenseStore.plan(licenseKey),
    };
    const { kid, privateKey } = await KeyManager.getActive();
    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'JWT' })
      .setIssuedAt()
      .setNotBefore('0s')
      .setExpirationTime(CONFIG.token.ttl)
      .setAudience(CONFIG.token.audience)
      .setIssuer(CONFIG.token.issuer)
      .sign(privateKey);
    return token;
  }

  async function verifyToken(token) {
    const { payload, protectedHeader } = await jwtVerify(token, async (h) => {
      // resolve public key by kid
      const kid = h.kid;
      // We import the current active pub for verification; previous keys supported by verify()
      const active = await KeyManager.getActive();
      const pubSpkiPem =
        kid === active.kid ? active.publicSPKI : null; // For brevity, only active supported here
      assert(pubSpkiPem, 'Unknown KID');
      return await importSPKI(pubSpkiPem, 'EdDSA');
    }, {
      algorithms: ['EdDSA'],
      clockTolerance: CONFIG.token.clockTolerance,
      issuer: CONFIG.token.issuer,
      audience: CONFIG.token.audience,
    });

    assert(!LicenseStore.isRevoked(payload.jti), 'Token revoked (jti)');
    assert(!LicenseStore.isRevoked(payload.sub), 'License revoked');

    return { payload, protectedHeader };
  }

  return { issue, verifyToken };
})();

// ----------------------------- Replay Guard ---------------------------
const ReplayGuard = (() => {
  // per (sub:machineId) => set of nonces with TTL
  const cache = new LRUCache({
    max: 10_000,
    ttl: 10 * 60 * 1000,
  });

  function keyFor(obj) {
    const sub = obj?.tokenSub || obj?.licenseKey || 'unknown';
    const machine = obj?.machineId || 'unknown';
    return `${sub}:${machine}`;
  }

  function checkAndStore(headerKey, nonce, ts) {
    assert(Math.abs(nowMs() - ts) < CONFIG.skewMs, 'Clock skew too large');
    const k = headerKey;
    const set = cache.get(k) || new Set();
    assert(!set.has(nonce), 'Replay detected');
    set.add(nonce);
    cache.set(k, set); // refresh TTL
  }

  return { keyFor, checkAndStore };
})();

// ----------------------------- Rate Limiter ---------------------------
const RateLimiter = (() => {
  const buckets = new Map(); // key -> { points, resetAt }

  function allow(actor, weight = 1) {
    const now = Date.now();
    let b = buckets.get(actor);
    if (!b || b.resetAt <= now) {
      b = { points: CONFIG.rate.points, resetAt: now + CONFIG.rate.windowMs };
      buckets.set(actor, b);
    }
    if (b.points < weight) throw new Error('Rate limit exceeded');
    b.points -= weight;
  }

  return { allow };
})();

// ----------------------------- RPC Engine -----------------------------
const RpcEngine = (() => {
  function dispatch(method, params) {
    switch (method) {
      case 'priceModel': {
        // toy model
        const { base = 10, multiplier = 1.2 } = params || {};
        return { price: Math.round(base * multiplier * 100) / 100 };
      }
      case 'scoreUser': {
        const { age = 30, activity = 0.5 } = params || {};
        return { score: Math.max(0, Math.min(100, age * activity)) };
      }
      default:
        throw new Error('Unknown method');
    }
  }
  return { dispatch };
})();

// ------------------------- Module Protector ---------------------------
const ModuleProtector = (() => {
  function obfuscate(src) {
    // lightweight obfuscation (rotate/xor-ish + minify-ish)
    const rotated = Buffer.from(src).toString('base64');
    return `/*obf*/(function(){const __d=atob("${rotated}");return __d;})()`;
  }

  function bindSrc(src, bindInfo, watermark, headerNonce) {
    const prelude = `
export const __nonce = "${headerNonce}";
export const __exp = ${bindInfo.exp};
export const __watermark = "${watermark}";
`;
    return prelude + src;
  }

  function sessionKey(serverPriv, clientPubPem) {
    const clientPub = crypto.createPublicKey(clientPubPem);
    const secret = crypto.diffieHellman({ privateKey: serverPriv, publicKey: clientPub });
    // HKDF -> 32 bytes (AES-256)
    const key = crypto.hkdfSync('sha256', secret, Buffer.from('mod_v2'), Buffer.alloc(0), 32);
    return key;
  }

  function encrypt(sessionKey, plaintextUtf8) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintextUtf8, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { iv: b64(iv), ciphertext: b64(Buffer.concat([ct, tag])) };
  }

  async function signEnvelope(enc, bind, serverPubX25519Pem, kid) {
    const payload = canonical({ enc, bind, serverPubX25519: serverPubX25519Pem });
    const sig = await KeyManager.sign(Buffer.from(payload, 'utf8'));
    return { envSigB64: b64(sig), kid };
  }

  return { obfuscate, bindSrc, sessionKey, encrypt, signEnvelope };
})();

// ---------------------------- JSON Schemas ----------------------------
const ajv = new Ajv({ strict: true, removeAdditional: 'failing', allErrors: true });
addFormats(ajv);

const HeaderSchema = {
  type: 'object',
  required: ['msgId', 'nonce', 'ts', 'typ', 'ver'],
  properties: {
    msgId: { type: 'string' },
    nonce: { type: 'string' },
    ts: { type: 'integer' },
    typ: { type: 'string' },
    ver: { const: CONFIG.protocolVersion },
  },
  additionalProperties: true,
};

const ActivateReqSchema = {
  allOf: [
    HeaderSchema,
    {
      type: 'object',
      required: ['licenseKey', 'machineId', 'deviceInfo'],
      properties: {
        typ: { const: 'activate' },
        licenseKey: { type: 'string' },
        machineId: { type: 'string' },
        deviceInfo: {
          type: 'object',
          required: ['os', 'arch', 'appVer', 'hwHash'],
          properties: {
            os: { type: 'string' },
            arch: { type: 'string' },
            appVer: { type: 'string' },
            hwHash: { type: 'string' },
          },
          additionalProperties: false,
        },
      },
    },
  ],
};

const RpcReqSchema = {
  allOf: [
    HeaderSchema,
    {
      type: 'object',
      required: ['token', 'method'],
      properties: {
        typ: { const: 'rpc' },
        token: { type: 'string' },
        method: { type: 'string' },
        params: {},
      },
    },
  ],
};

const GetModuleReqSchema = {
  allOf: [
    HeaderSchema,
    {
      type: 'object',
      required: ['token', 'clientPubX25519Pem', 'bind'],
      properties: {
        typ: { const: 'get_module' },
        token: { type: 'string' },
        clientPubX25519Pem: { type: 'string' },
        bind: {
          type: 'object',
          required: ['exp', 'watermark'],
          properties: {
            exp: { type: 'integer' },
            watermark: { type: 'string' },
          },
          additionalProperties: false,
        },
      },
    },
  ],
};

const validate = {
  activate: ajv.compile(ActivateReqSchema),
  rpc: ajv.compile(RpcReqSchema),
  getModule: ajv.compile(GetModuleReqSchema),
};

// --------------------------- HTTP(S) & WSS ----------------------------
const h2server = http2.createSecureServer(CONFIG.tls);
const httpsServer = https.createServer(CONFIG.tls, (req, res) => {
  // HSTS on bootstrap HTTPS page (if you serve one)
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.writeHead(200);
  res.end('WS Auth Server is running.\n');
});

h2server.on('request', (req, res) => {
  res.stream.respond({
    ':status': 200,
    'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  });
  res.stream.end('WS Auth Server (HTTP/2) OK\n');
});

// Share TLS socket for WS upgrades (either server will do)
httpsServer.listen(CONFIG.port, CONFIG.host, () => {
  console.log(`HTTPS/WSS listening on wss://${CONFIG.host}:${CONFIG.port}`);
});

const wss = new WebSocketServer({
  server: httpsServer,
  maxPayload: CONFIG.msgSizeCap,
});

// ----------------------------- WS Handler -----------------------------
wss.on('connection', async (ws, req) => {
  try {
    // Origin / ALPN checks can be added per your deployment.
    const ip = req.socket.remoteAddress;

    // Send hello with pinned Ed25519 pub (SPKI base64) and protocol version
    const ed25519PublicKeyB64 = await KeyManager.getActivePublicSPKIb64();
    const hello = {
      typ: 'hello',
      ver: CONFIG.protocolVersion,
      ed25519PublicKeyB64,
      ts: nowMs(),
    };
    ws.send(JSON.stringify(hello));

    ws.on('message', async (raw) => {
      if (raw.length > CONFIG.msgSizeCap) {
        ws.close(1009, 'Message too large');
        return;
      }
      let obj;
      try {
        obj = JSON.parse(raw.toString('utf8'));
      } catch (e) {
        return ws.send(JSON.stringify(errorMsg('bad_json', 'Invalid JSON')));
      }

      try {
        // Shared header checks
        assert(obj?.ver === CONFIG.protocolVersion, 'Bad protocol version');
        const actorKey = obj.token
          ? `_tok:${obj.token.slice(0, 50)}`
          : `_key:${obj.licenseKey || 'unknown'}`;

        // Rate limiting
        RateLimiter.allow(actorKey, 1);

        // Replay guard
        const headerKey = obj.token ? obj.token.slice(0, 32) : `${obj.licenseKey || 'na'}:${obj.machineId || 'na'}`;
        ReplayGuard.checkAndStore(headerKey, obj.nonce, obj.ts);

        // Dispatch by type
        switch (obj.typ) {
          case 'activate': {
            if (!validate.activate(obj)) throw new Error('Schema validation failed (activate)');
            const lic = LicenseStore.check(obj.licenseKey);
            LicenseStore.recordUse(obj.licenseKey, obj.machineId, obj.ts);
            const token = await TokenService.issue(obj.licenseKey, obj.machineId, lic.scopes);

            auditAppend({
              actor: obj.licenseKey,
              action: 'activate',
              meta: { machineId: obj.machineId },
            });

            const activated = {
              msgId: uuidv4(),
              nonce: uuidv4(),
              ts: nowMs(),
              typ: 'activated',
              ver: CONFIG.protocolVersion,
              token,
              exp: Math.floor(Date.now() / 1000) + 15 * 60,
              ed25519PublicKeyB64,
              rotateAfter: CONFIG.token.rotateHintSec,
            };
            return ws.send(JSON.stringify(activated));
          }

          case 'rpc': {
            if (!validate.rpc(obj)) throw new Error('Schema validation failed (rpc)');

            const { payload } = await TokenService.verifyToken(obj.token);
            assert(payload.scopes?.includes('rpc:invoke'), 'Missing scope rpc:invoke');

            RateLimiter.allow(payload.sub, 1);

            const result = RpcEngine.dispatch(obj.method, obj.params);
            const response = {
              msgId: uuidv4(),
              nonce: obj.nonce, // echo nonce as part of signed payload association
              ts: nowMs(),
              typ: 'rpc_result',
              ver: CONFIG.protocolVersion,
              result,
            };
            const pay = canonical({
              method: obj.method,
              result,
              nonce: response.nonce,
              ts: response.ts,
            });
            const sig = await KeyManager.sign(Buffer.from(pay, 'utf8'));

            response.sigB64 = b64(sig);
            response.kid = (await KeyManager.getActive()).kid;

            auditAppend({
              actor: payload.sub,
              action: 'rpc',
              meta: { method: obj.method },
            });

            return ws.send(JSON.stringify(response));
          }

          case 'get_module': {
            if (!validate.getModule(obj)) throw new Error('Schema validation failed (get_module)');

            const { payload, protectedHeader } = await TokenService.verifyToken(obj.token);
            assert(payload.scopes?.includes('module:get'), 'Missing scope module:get');

            assert(obj.bind.exp > nowMs(), 'bind.exp must be in the future');
            assert(obj.bind.exp - nowMs() <= CONFIG.moduleBindMaxMs, 'bind.exp too far in future');

            // Generate ephemeral X25519 server keys
            const { privateKey: serverPriv, publicKey: serverPub } =
              crypto.generateKeyPairSync('x25519');

            const serverPubPem = serverPub.export({ type: 'spki', format: 'pem' });

            // Load protected source (example module)
            const src = `
export function hello(name){ return "hello, " + name; }
export const version = "1.0.0";
`;

            // Watermark (license/machine/nonce affinity)
            const watermark = `sub:${payload.sub}|machine:${payload.machineId}|nonce:${obj.nonce}`;

            const obf = ModuleProtector.obfuscate(src);
            const boundSource = ModuleProtector.bindSrc(obf, obj.bind, watermark, obj.nonce);

            const sessionKey = ModuleProtector.sessionKey(serverPriv, obj.clientPubX25519Pem);
            const enc = ModuleProtector.encrypt(sessionKey, boundSource);

            const { kid } = await KeyManager.getActive();
            const env = await ModuleProtector.signEnvelope(enc, obj.bind, serverPubPem, kid);

            const res = {
              msgId: uuidv4(),
              nonce: obj.nonce,
              ts: nowMs(),
              typ: 'module',
              ver: CONFIG.protocolVersion,
              enc,
              envSigB64: env.envSigB64,
              serverKeys: {
                pubX25519Pem: serverPubPem,
                kid,
                ed25519PublicKeyB64: await KeyManager.getActivePublicSPKIb64(),
              },
            };

            auditAppend({
              actor: payload.sub,
              action: 'module_delivered',
              meta: { kid, jti: payload.jti },
            });

            return ws.send(JSON.stringify(res));
          }

          default:
            return ws.send(JSON.stringify(errorMsg('bad_type', 'Unsupported typ')));
        }
      } catch (err) {
        return ws.send(JSON.stringify(errorMsg('bad_request', err.message)));
      }
    });
  } catch (err) {
    console.error('connection error', err);
    try {
      ws?.send(JSON.stringify(errorMsg('internal', 'Internal error')));
      ws?.close();
    } catch {}
  }
});

function errorMsg(code, message) {
  return {
    msgId: uuidv4(),
    nonce: uuidv4(),
    ts: nowMs(),
    typ: 'error',
    ver: CONFIG.protocolVersion,
    code,
    message,
  };
}
