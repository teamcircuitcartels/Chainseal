(() => {
  const $ = id => document.getElementById(id);
  const short = h => h ? h.slice(0, 10) + "\u2026" + h.slice(-6) : "-";
  let current = null;
  const say = (t, c) => { const r = $("l-result"); r.textContent = t; r.className = "result " + (c || ""); };
  const api = async (url, opt) => {
    const r = await fetch(url, opt); const d = await r.json();
    if (!r.ok) throw new Error(d.error || "Request failed");
    return d;
  };
  async function show(id) {
    const b = await api("/api/batches/" + id);
    current = b.id;
    $("l-id").textContent = b.id; $("l-root").textContent = b.root; $("l-block").textContent = b.blockHash;
    $("l-tamper").disabled = false; $("l-verify").disabled = false;
    const q = await api(`/api/batches/${id}/qr`); $("l-qr").src = q.qr; $("l-qr").hidden = false;
    return b;
  }
  async function refresh() {
    const list = await api("/api/batches");
    $("l-list").innerHTML = list.length ? list.map(b =>
      `<li><button class="link" data-id="${b.id}">${b.id}</button> <span class="note">${b.readings} readings &middot; ${new Date(b.createdAt).toLocaleTimeString()}</span></li>`).join("")
      : '<li class="note">Nothing sealed yet.</li>';
  }
  const offline = () => say("Backend not reachable. Run npm start and open http://localhost:3000.", "bad");
  $("l-create").onclick = async () => {
    try { const b = await api("/api/simulate", { method: "POST" }); await show(b.id); await refresh();
      say("Sealed. Four signed readings are now under one root, linked to the previous block.", ""); } catch (e) { e.message === "Failed to fetch" ? offline() : say(e.message, "bad"); }
  };
  $("l-tamper").onclick = async () => {
    try { await api(`/api/batches/${current}/tamper`, { method: "POST" }); say("Stored data edited (first temperature +6 \u00B0C). Now verify.", ""); } catch (e) { say(e.message, "bad"); }
  };
  $("l-verify").onclick = async () => {
    try { const v = await api("/api/verify/" + current);
      v.valid ? say("Verified. All signatures are valid, the root matches and the chain link holds.", "ok")
        : say(`Tampering detected. ${v.badSignatures.length} reading(s) fail signature check; root ${v.rootOk ? "matches" : "does not match"}.`, "bad");
    } catch (e) { say(e.message, "bad"); }
  };
  $("l-list").onclick = async e => { const id = e.target.dataset && e.target.dataset.id; if (id) { await show(id); say("Loaded batch " + id + ". Press Verify."); } };
  // QR scan lands here with ?batch=ID and verifies automatically
  const id = new URLSearchParams(location.search).get("batch");
  refresh().catch(() => {});
  if (id) show(id).then(() => $("l-verify").click()).catch(() => say("Batch not found on this server.", "bad"));
})();
