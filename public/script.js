(() => {
  const enc = new TextEncoder();
  const $ = id => document.getElementById(id);
  const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  const sha = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
  const short = h => h.slice(0, 10) + "\u2026" + h.slice(-6);
  const rnd = (a, b, d = 1) => (Math.random() * (b - a) + a).toFixed(d);

  let readings = [], sealed = null, keys = null, hasTampered = false;

  const makeReadings = () => [
    { name: "Temperature", value: rnd(2, 8) + " \u00B0C" },
    { name: "Humidity", value: rnd(40, 70, 0) + " %" },
    { name: "Shock", value: rnd(0, 0.6, 2) + " g" },
    { name: "GPS", value: rnd(18.4, 18.6, 4) + ", " + rnd(73.7, 73.95, 4) }
  ];
  const line = (r, i) => `${i}|${r.name}|${r.value}|${sealed ? sealed.nonce : "pending"}`;

  async function merkle(leaves) {
    let level = leaves;
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) next.push(await sha(level[i] + (level[i + 1] || level[i])));
      level = next;
    }
    return level[0];
  }
  async function compute(nonce) {
    const leaves = await Promise.all(readings.map((r, i) => sha(`${i}|${r.name}|${r.value}|${nonce}`)));
    return { leaves, root: await merkle(leaves) };
  }

  async function render(changedIdx = -1) {
    const nonce = sealed ? sealed.nonce : "pending";
    const { leaves } = await compute(nonce);
    $("rows").innerHTML = readings.map((r, i) =>
      `<tr class="${i === changedIdx ? "changed" : ""}"><td>${r.name}</td><td>${r.value}</td><td><code>${short(leaves[i])}</code></td></tr>`).join("");
  }
  const setStatus = (t, c) => { const s = $("status"); s.textContent = t; s.className = "status " + (c || ""); };
  const setResult = (t, c) => { const r = $("result"); r.textContent = t; r.className = "result " + (c || ""); };

  async function newReadings() {
    readings = makeReadings(); sealed = null; hasTampered = false;
    $("root").textContent = "-"; $("sig").textContent = "-";
    $("btn-tamper").disabled = true; $("btn-verify").disabled = true; $("btn-seal").disabled = false;
    setStatus("Not sealed"); setResult("Seal the batch to lock these readings under one signed root.");
    await render();
  }

  async function seal() {
    const nonce = hex(crypto.getRandomValues(new Uint8Array(8)));
    const { root } = await compute(nonce);
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, enc.encode(root));
    sealed = { nonce, root, sig, snapshot: JSON.parse(JSON.stringify(readings)) };
    $("root").textContent = root; $("sig").textContent = short(hex(sig)) + " (ECDSA P-256)";
    $("btn-seal").disabled = true; $("btn-tamper").disabled = false; $("btn-verify").disabled = false;
    setStatus("Sealed", "sealed");
    setResult("Sealed. The root is signed by the device key and would now be anchored on the ledger. Try to cheat, then verify.");
    await render();
  }

  async function tamper() {
    const i = Math.floor(Math.random() * readings.length);
    if (i === 0) readings[0].value = (parseFloat(readings[0].value) + 6).toFixed(1) + " \u00B0C";
    else if (i === 1) readings[1].value = "45 %";
    else if (i === 2) readings[2].value = "0.00 g";
    else readings[3].value = "18.5204, 73.8567";
    hasTampered = true;
    setResult(`You edited the ${readings[i].name.toLowerCase()} reading. Now press Verify.`);
    await render(i);
  }

  async function verify() {
    const { root } = await compute(sealed.nonce);
    const sigOk = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, keys.publicKey, sealed.sig, enc.encode(sealed.root));
    if (sigOk && root === sealed.root) {
      setStatus("Verified", "ok"); setResult("Verified. The signature is valid and the recomputed root matches the sealed root. These readings are untouched.", "ok");
    } else {
      setStatus("Tampering detected", "bad");
      setResult(`Rejected. The signature on the sealed root is ${sigOk ? "valid" : "invalid"}, but the readings now produce a different root (${short(root)}). The edit is caught.`, "bad");
    }
  }

  (async () => {
    if (!window.crypto || !crypto.subtle) {
      setResult("This demo needs a secure context. Open the page over HTTPS or localhost.", "bad");
      document.querySelectorAll(".actions button").forEach(b => b.disabled = true); return;
    }
    keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    $("btn-new").onclick = newReadings; $("btn-seal").onclick = seal;
    $("btn-tamper").onclick = tamper; $("btn-verify").onclick = verify;
    await newReadings();
  })();
})();
