// ChainSeal backend: Express + Node crypto. Storage is a JSON file (swap for MongoDB/Fabric later).
const express = require("express"), cors = require("cors"), crypto = require("crypto");
const QRCode = require("qrcode"), fs = require("fs"), path = require("path");

const DB = path.join(__dirname, "data.json");
const db = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB, "utf8")) : { devices: {}, nonces: [], pending: [], batches: [] };
const save = () => fs.writeFileSync(DB, JSON.stringify(db, null, 2));
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const canon = r => [r.deviceId, r.ts, r.nonce, r.temp, r.hum, r.shock, r.lat, r.lng].join("|");

function merkle(leaves) {
  let lvl = leaves.slice();
  if (!lvl.length) return sha("");
  while (lvl.length > 1) {
    const nxt = [];
    for (let i = 0; i < lvl.length; i += 2) nxt.push(sha(lvl[i] + (lvl[i + 1] || lvl[i])));
    lvl = nxt;
  }
  return lvl[0];
}
function sigValid(reading, sigB64, pem) {
  try {
    return crypto.verify("sha256", Buffer.from(canon(reading)),
      { key: pem, dsaEncoding: "ieee-p1363" }, Buffer.from(sigB64, "base64"));
  } catch { return false; }
}
function acceptReading(reading, signature) {
  const dev = db.devices[reading.deviceId];
  if (!dev) return { ok: false, error: "Unknown device. Register its public key first." };
  if (dev.revoked) return { ok: false, error: "Device key revoked." };
  if (Math.abs(Date.now() - reading.ts) > 24 * 3600 * 1000) return { ok: false, error: "Timestamp too old or in the future." };
  if (db.nonces.includes(reading.nonce)) return { ok: false, error: "Replay rejected: nonce already used." };
  if (!sigValid(reading, signature, dev.publicKeyPem)) return { ok: false, error: "Invalid signature." };
  db.nonces.push(reading.nonce); if (db.nonces.length > 5000) db.nonces.shift();
  db.pending.push({ reading, signature });
  return { ok: true };
}
function sealPending() {
  if (!db.pending.length) return null;
  const items = db.pending.splice(0);
  const root = merkle(items.map(i => sha(canon(i.reading))));
  const prev = db.batches.length ? db.batches[db.batches.length - 1].blockHash : "0".repeat(64);
  const b = { id: crypto.randomBytes(4).toString("hex"), createdAt: Date.now(), items, root, prev };
  b.blockHash = sha(prev + root + b.createdAt);   // hash-linked ledger (stand-in for Fabric anchor)
  db.batches.push(b); save();
  return b;
}
function checkBatch(b) {
  const bad = [];
  b.items.forEach((it, i) => {
    const dev = db.devices[it.reading.deviceId];
    if (!dev || !sigValid(it.reading, it.signature, dev.publicKeyPem)) bad.push(i);
  });
  const rootOk = merkle(b.items.map(i => sha(canon(i.reading)))) === b.root;
  const idx = db.batches.indexOf(b);
  const chainOk = idx === 0 ? b.prev === "0".repeat(64) : b.prev === db.batches[idx - 1].blockHash;
  return { valid: !bad.length && rootOk && chainOk, rootOk, chainOk, badSignatures: bad };
}
const alertsOf = b => b.items.flatMap((it, i) => {
  const r = it.reading, a = [];
  if (r.temp < 2 || r.temp > 8) a.push({ index: i, type: "Cold-chain excursion", value: r.temp + " \u00B0C" });
  if (r.shock > 0.5) a.push({ index: i, type: "Shock event", value: r.shock + " g" });
  return a;
});
const summary = b => ({ id: b.id, createdAt: b.createdAt, root: b.root, blockHash: b.blockHash, readings: b.items.length, alerts: alertsOf(b).length });
function proofFor(leaves, idx) {          // Merkle inclusion proof, same pairing rule as merkle()
  const path = []; let lvl = leaves.slice(), i = idx;
  while (lvl.length > 1) {
    path.push({ hash: i % 2 ? lvl[i - 1] : (lvl[i + 1] || lvl[i]), left: i % 2 === 1 });
    const nxt = []; for (let k = 0; k < lvl.length; k += 2) nxt.push(sha(lvl[k] + (lvl[k + 1] || lvl[k])));
    lvl = nxt; i = Math.floor(i / 2);
  }
  return path;
}

// Demo device: its private key lives only in server memory, like a chip that never exports it.
const demo = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
db.devices["CS-DEMO-01"] = { publicKeyPem: demo.publicKey.export({ type: "spki", format: "pem" }), registeredAt: Date.now() };

const hits = {};
const app = express();
app.use(cors(), express.json({ limit: "100kb" }));
app.use((req, res, next) => {             // security headers + simple per-IP rate limit (120 req/min on /api)
  res.set({ "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer" });
  if (!req.path.startsWith("/api")) return next();
  const k = req.ip, now = Date.now(); hits[k] = (hits[k] || []).filter(t => now - t < 60000);
  if (hits[k].push(now) > 120) return res.status(429).json({ error: "Too many requests. Slow down." });
  next();
});
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/devices", (req, res) => {
  const { deviceId, publicKeyPem } = req.body || {};
  if (!deviceId || !publicKeyPem) return res.status(400).json({ error: "deviceId and publicKeyPem required." });
  if (db.devices[deviceId]) return res.status(409).json({ error: "Device already registered." });
  db.devices[deviceId] = { publicKeyPem, registeredAt: Date.now() }; save();
  res.status(201).json({ ok: true });
});
app.post("/api/readings", (req, res) => {
  const { reading, signature } = req.body || {};
  if (!reading || !signature) return res.status(400).json({ error: "reading and signature required." });
  const r = acceptReading(reading, signature);
  if (r.ok) save();
  res.status(r.ok ? 202 : 400).json(r);
});
app.post("/api/batches/seal", (req, res) => {
  const b = sealPending();
  b ? res.status(201).json(summary(b)) : res.status(400).json({ error: "No pending readings." });
});
app.post("/api/simulate", (req, res) => {          // demo: simulated node signs 4 samples, then seals
  for (let i = 0; i < 4; i++) {
    const reading = { deviceId: "CS-DEMO-01", ts: Date.now() - (3 - i) * 60000, nonce: crypto.randomBytes(8).toString("hex"),
      temp: +(2 + Math.random() * 6).toFixed(1), hum: Math.round(40 + Math.random() * 30),
      shock: +(Math.random() * 0.6).toFixed(2), lat: +(18.52 + Math.random() * 0.01).toFixed(4), lng: +(73.85 + Math.random() * 0.01).toFixed(4) };
    const signature = crypto.sign("sha256", Buffer.from(canon(reading)), { key: demo.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
    acceptReading(reading, signature);
  }
  const b = sealPending();
  b ? res.status(201).json(summary(b)) : res.status(400).json({ error: "No readings accepted. Is the device key revoked?" });
});
app.get("/api/batches", (req, res) => res.json(db.batches.slice(-10).reverse().map(summary)));
app.get("/api/batches/:id", (req, res) => {
  const b = db.batches.find(x => x.id === req.params.id);
  b ? res.json({ ...summary(b), readings: b.items.map(i => i.reading), verification: checkBatch(b) }) : res.status(404).json({ error: "Batch not found." });
});
app.get("/api/verify/:id", (req, res) => {
  const b = db.batches.find(x => x.id === req.params.id);
  b ? res.json({ id: b.id, ...checkBatch(b) }) : res.status(404).json({ error: "Batch not found." });
});
app.post("/api/batches/:id/tamper", (req, res) => {   // DEMO ONLY: edits stored data so verification fails
  const b = db.batches.find(x => x.id === req.params.id);
  if (!b) return res.status(404).json({ error: "Batch not found." });
  b.items[0].reading.temp = +(b.items[0].reading.temp + 6).toFixed(1); save();
  res.json({ ok: true });
});
app.get("/api/batches/:id/qr", async (req, res) => {
  const url = `${req.protocol}://${req.get("host")}/?batch=${req.params.id}#ledger`;
  res.json({ url, qr: await QRCode.toDataURL(url, { margin: 1, width: 240 }) });
});

app.get("/api/devices", (req, res) => res.json(Object.entries(db.devices).map(([id, d]) => ({ deviceId: id, registeredAt: d.registeredAt, revoked: !!d.revoked }))));
app.post("/api/devices/:id/revoke", (req, res) => {
  const d = db.devices[req.params.id];
  if (!d) return res.status(404).json({ error: "Device not found." });
  d.revoked = true; save(); res.json({ ok: true });
});
app.get("/api/stats", (req, res) => res.json({
  devices: Object.keys(db.devices).length, batches: db.batches.length, pending: db.pending.length,
  readings: db.batches.reduce((n, b) => n + b.items.length, 0), alerts: db.batches.reduce((n, b) => n + alertsOf(b).length, 0) }));
app.get("/api/batches/:id/proof/:index", (req, res) => {   // lets anyone verify ONE reading without the whole batch
  const b = db.batches.find(x => x.id === req.params.id), i = Number(req.params.index);
  if (!b || !Number.isInteger(i) || i < 0 || i >= b.items.length) return res.status(404).json({ error: "Batch or reading not found." });
  const leaves = b.items.map(x => sha(canon(x.reading)));
  res.json({ leafIndex: i, reading: b.items[i].reading, path: proofFor(leaves, i), root: b.root });
});
app.get("/api/batches/:id/passport", (req, res) => {       // ERC-721 style metadata for the batch digital passport
  const b = db.batches.find(x => x.id === req.params.id);
  if (!b) return res.status(404).json({ error: "Batch not found." });
  const t = b.items.map(x => x.reading.temp), v = checkBatch(b), al = alertsOf(b);
  res.json({ name: `ChainSeal Batch #${b.id}`, description: "Tamper-evident digital passport for a sensor-verified batch.",
    attributes: [
      { trait_type: "Merkle root", value: b.root }, { trait_type: "Block hash", value: b.blockHash },
      { trait_type: "Readings", value: b.items.length }, { trait_type: "Min temp (C)", value: Math.min(...t) },
      { trait_type: "Max temp (C)", value: Math.max(...t) }, { trait_type: "Alerts", value: al.length },
      { trait_type: "Integrity", value: v.valid ? "Verified" : "Tampering detected" }] });
});
app.get("/api/stream", (req, res) => {                     // live signed telemetry via Server-Sent Events
  res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" }); res.flushHeaders();
  let temp = 5;
  const t = setInterval(() => {
    temp = Math.min(10, Math.max(0, temp + (Math.random() - 0.5) * 1.6));
    const reading = { deviceId: "CS-DEMO-01", ts: Date.now(), nonce: crypto.randomBytes(8).toString("hex"), temp: +temp.toFixed(1),
      hum: Math.round(50 + Math.random() * 15), shock: +(Math.random() < 0.06 ? 0.6 + Math.random() * 0.5 : Math.random() * 0.2).toFixed(2), lat: 18.5204, lng: 73.8567 };
    const signature = crypto.sign("sha256", Buffer.from(canon(reading)), { key: demo.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
    const r = acceptReading(reading, signature);
    res.write(`data: ${JSON.stringify({ reading, verified: r.ok, pending: db.pending.length })}\n\n`);
  }, 1500);
  req.on("close", () => clearInterval(t));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ChainSeal running on http://localhost:${PORT}`));
