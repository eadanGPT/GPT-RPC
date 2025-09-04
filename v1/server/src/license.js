import { ed25519Generate, ed25519ImportPriv, createTokenEd25519 } from './utils.js';

export const LICENSE_DB = new Map([
  ['DEMO-123-456', { plan:'pro', seats:5, status:'active' }]
]);

let edKeys = null;
export async function initKeys(){
  if(!edKeys) edKeys = await ed25519Generate();
  return edKeys;
}
export function getPubKeyB64(){ return edKeys?.pubB64; }
export function getPrivKeyB64(){ return edKeys?.prvB64; }

export async function issueToken({ licenseKey, machineId }){
  if(!LICENSE_DB.has(licenseKey)) throw new Error('invalid_license');
  const lic = LICENSE_DB.get(licenseKey);
  if(lic.status!=='active') throw new Error('inactive_license');
  const now = Math.floor(Date.now()/1000);
  const exp = now + 15*60;
  const payload = { iss:'ws-auth-demo', sub:licenseKey, aud:'ws-auth-client', iat:now, exp, machineId };
  const priv = await ed25519ImportPriv(edKeys.prvB64);
  const token = await createTokenEd25519(priv, payload);
  return { token, exp, plan: lic.plan };
}
