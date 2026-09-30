# ChainSeal
Hardware-rooted blockchain for tamper-proof real-world data. Smart India Hackathon 2026, SIH26211, Team Circuit Cartels.

## Run
    npm install
    npm start          # http://localhost:3000
Phone test: open http://<your-pc-ip>:3000 on the same Wi-Fi.

## Deploy (backend needed for Live sections)
Render / Railway: connect the GitHub repo, build `npm install`, start `npm start`. Or `docker build -t chainseal . && docker run -p 3000:3000 chainseal`.
GitHub Pages hosts only `public/` (hero demo works, ledger and live sections need the backend).

## What is inside
- `public/` website: in-browser SHA-256 + ECDSA demo, live telemetry chart, ledger explorer, QR verify page
- `server.js` API: device registry + revoke, signature and replay checks, Merkle batching, hash-linked ledger, inclusion proofs, cold-chain alerts, ERC-721 passport metadata, SSE stream, rate limit
- `contracts/ChainSealPassport.sol` ERC-721 batch passport with on-chain Merkle verify
- `firmware/chainseal_node.ino` ESP32 + ATECC608 node sketch (needs NTP time and a real shock sensor before field use)

## API
POST /api/devices, GET /api/devices, POST /api/devices/:id/revoke, POST /api/readings, POST /api/batches/seal, POST /api/simulate,
GET /api/batches, GET /api/batches/:id, GET /api/verify/:id, GET /api/batches/:id/proof/:index, GET /api/batches/:id/passport,
GET /api/batches/:id/qr, GET /api/stats, GET /api/stream (SSE)

## Honest scope
The ledger is a hash-linked JSON store standing in for Hyperledger Fabric, and the tamper route is demo-only. The firmware and contract are unbuilt reference code: test them on hardware and a testnet before claiming a working prototype.
