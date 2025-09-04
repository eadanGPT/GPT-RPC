# WS Auth System (Node.js)

A compact authentication system over **WebSocket** with:
- **License activation** (Ed25519-signed compact JWT-style token).
- **Signed messages** from server (client verifies with pinned public key).
- **Protected module delivery** over WS using **X25519 ECDH + HKDF → AES-GCM**,
  bound to a **nonce + expiry + watermark**.
- Simple **RPC** calls executed on the server.

> This is a demo that raises the bar against reverse-engineering, but does **not** guarantee secrecy if code runs client-side. Keep your crown-jewel logic on the server when possible.

## Quick start
```bash
# 1) Install deps
cd server && npm i
cd ../client && npm i

# 2) Run server
cd ../server
API_KEY=dev_key_123 node src/server.js

# 3) Run client (separate terminal)
cd ../client
LICENSE_KEY=DEMO-123-456 node src/client.js
```

Expected client output:
- Activates via WS, receives a token and pins server's Ed25519 public key.
- Performs signed RPC (`priceModel`, `scoreUser`).
- Requests and executes the protected module delivered over WS.
