import { webcrypto } from 'crypto';

export function b64url(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return b.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
export function b64urldecode(str) {
  const pad = 4 - (str.length % 4 || 4);
  return Buffer.from(str.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat(pad), 'base64');
}

export async function ed25519Generate() {
  const kp = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign','verify']);
  const pub = await webcrypto.subtle.exportKey('spki', kp.publicKey);
  const prv = await webcrypto.subtle.exportKey('pkcs8', kp.privateKey);
  return { pubB64: Buffer.from(pub).toString('base64'), prvB64: Buffer.from(prv).toString('base64') };
}
export async function ed25519ImportPriv(pkcs8b64) {
  return webcrypto.subtle.importKey('pkcs8', Buffer.from(pkcs8b64,'base64'), { name:'Ed25519' }, false, ['sign']);
}
export async function ed25519ImportPub(spkib64) {
  return webcrypto.subtle.importKey('spki', Buffer.from(spkib64,'base64'), { name:'Ed25519' }, false, ['verify']);
}
export async function edSign(privKey, dataBytes) {
  return Buffer.from(await webcrypto.subtle.sign('Ed25519', privKey, dataBytes));
}
export async function edVerify(pubKey, sigBytes, dataBytes) {
  return webcrypto.subtle.verify('Ed25519', pubKey, sigBytes, dataBytes);
}

export async function createTokenEd25519(privKey, payload) {
  const header = { alg:'EdDSA', typ:'JWT' };
  const enc = new TextEncoder();
  const h = b64url(Buffer.from(JSON.stringify(header)));
  const p = b64url(Buffer.from(JSON.stringify(payload)));
  const sig = await edSign(privKey, enc.encode(h + '.' + p));
  return h + '.' + p + '.' + b64url(sig);
}
