import { generateKeyPairSync, createPublicKey, createPrivateKey, diffieHellman, webcrypto, randomBytes } from 'crypto';

export function generateX25519() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  return {
    privPem: privateKey.export({ type:'pkcs8', format:'pem' }).toString(),
    pubPem: publicKey.export({ type:'spki', format:'pem' }).toString()
  };
}

export async function deriveKeyAesGcm256(privPem, peerPubPem, salt) {
  const priv = createPrivateKey(privPem);
  const pub = createPublicKey(peerPubPem);
  const secret = diffieHellman({ privateKey: priv, publicKey: pub });
  const baseKey = await webcrypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return webcrypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt, info: new Uint8Array([]) },
    baseKey,
    { name:'AES-GCM', length:256 },
    false,
    ['encrypt','decrypt']
  );
}

export async function aesGcmEncrypt(key, plaintext) {
  const iv = randomBytes(12);
  const bytes = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const ct = await webcrypto.subtle.encrypt({ name:'AES-GCM', iv }, key, bytes);
  return { iv: Buffer.from(iv).toString('base64'), ciphertext: Buffer.from(ct).toString('base64') };
}
