import { WebSocketServer } from 'ws';
import { randomUUID } from 'crypto';
import { generateX25519, deriveKeyAesGcm256, aesGcmEncrypt } from './crypto.js';
import { priceModel, scoreUser, protectedModuleSource } from './sensitive.js';
import { initKeys, getPubKeyB64, getPrivKeyB64, issueToken } from './license.js';
import { ed25519ImportPriv } from './utils.js';

const PORT = process.env.PORT || 8080;
const API_KEY = process.env.API_KEY || 'dev_key_123';

const serverEcdh = generateX25519();
await initKeys();

const wss = new WebSocketServer({ port: PORT }, () => {
  console.log('WS server listening on ws://localhost:'+PORT);
});

function send(ws, type, data){
  ws.send(JSON.stringify({ type, ...data }));
}

wss.on('connection', (ws, req) => {
  // Simple API key gate for connection (optional)
  const url = new URL(req.url, 'http://localhost');
  const key = url.searchParams.get('apiKey');
  if (key !== API_KEY) {
    ws.close(1008, 'unauthorized');
    return;
  }

  send(ws, 'hello', { ok:true, ed25519PublicKeyB64: getPubKeyB64() });

  ws.on('message', async (raw) => {
    let msg = {};
    try { msg = JSON.parse(String(raw)); } catch { return; }

    try {
      if (msg.type === 'activate') {
        const { licenseKey, machineId } = msg;
        const r = await issueToken({ licenseKey, machineId });
        return send(ws, 'activated', { ok:true, ...r });
      }

      if (msg.type === 'rpc') {
        const { token, method, params, nonce } = msg;
        // (Demo) trust token; production should verify exp & signature
        let result;
        if (method==='priceModel') result = priceModel(params);
        else if (method==='scoreUser') result = scoreUser(params);
        else return send(ws, 'rpc_error', { error:'unknown_method' });

        const payload = JSON.stringify({ method, result, nonce, ts: Date.now() });
        const priv = await ed25519ImportPriv(getPrivKeyB64());
        const sig = Buffer.from(await (await import('crypto')).webcrypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(payload))).toString('base64');
        return send(ws, 'rpc_result', { ok:true, result, signatureB64: sig, ed25519PublicKeyB64: getPubKeyB64() });
      }

      if (msg.type === 'get_module') {
        const { token, clientPublicKeyPem, nonce, exp, watermark } = msg;
        if (!clientPublicKeyPem || !nonce || !exp) return send(ws, 'module_error', { error: 'missing_fields' });
        const now = Date.now();
        if (exp < now || exp > now + 5*60_000) return send(ws, 'module_error', { error:'bad_expiry' });

        const aesKey = await deriveKeyAesGcm256(serverEcdh.privPem, clientPublicKeyPem, Buffer.from('ws_salt_v1'));
        const obf = protectedModuleSource;
        const src = obf.split('').map((c,i)=>String.fromCharCode(c.charCodeAt(0)^(i%7))).join('');
        const bound = `export const __nonce=${JSON.stringify(nonce)};\nexport const __exp=${JSON.stringify(exp)};\nexport const __watermark=${JSON.stringify(watermark||'')};\n${src}`;
        const enc = await aesGcmEncrypt(aesKey, bound);
        const toSign = JSON.stringify({ enc, nonce, exp });
        const priv = await ed25519ImportPriv(getPrivKeyB64());
        const sig = Buffer.from(await (await import('crypto')).webcrypto.subtle.sign('Ed25519', priv, new TextEncoder().encode(toSign))).toString('base64');
        return send(ws, 'module', { ok:true, enc, signatureB64: sig, server: { ecdhPublicKeyPem: serverEcdh.pubPem, ed25519PublicKeyB64: getPubKeyB64() } });
      }

    } catch (e) {
      return send(ws, 'error', { error: e.message || 'server_error' });
    }
  });
});
