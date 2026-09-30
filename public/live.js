(() => {
  const $ = id => document.getElementById(id);
  const enc = new TextEncoder();
  const sha = async s => [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))].map(b => b.toString(16).padStart(2, "0")).join("");
  const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const canon = r => [r.deviceId, r.ts, r.nonce, r.temp, r.hum, r.shock, r.lat, r.lng].join("|");

  /* ---------- live telemetry ---------- */
  const cv = $("t-canvas"), ctx = cv.getContext("2d");
  let es = null, pts = [], ok = 0, bad = 0, alerts = 0;
  function size() {
    const w = cv.parentElement.clientWidth - 2 * 19, d = window.devicePixelRatio || 1, h = Math.max(160, Math.round(w * 0.36));
    cv.style.width = w + "px"; cv.style.height = h + "px"; cv.width = w * d; cv.height = h * d; ctx.setTransform(d, 0, 0, d, 0, 0); draw();
  }
  function draw() {
    const W = cv.clientWidth, H = cv.clientHeight, y = t => H - 18 - (t / 10) * (H - 30);
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = css("--green") + "22"; ctx.fillRect(0, y(8), W, y(2) - y(8));
    ctx.fillStyle = css("--muted"); ctx.font = "12px " + css("--mono"); ctx.fillText("8 \u00B0C", 4, y(8) - 4); ctx.fillText("2 \u00B0C", 4, y(2) + 13);
    if (!pts.length) return;
    const step = W / 39;
    ctx.beginPath(); ctx.strokeStyle = css("--ink"); ctx.lineWidth = 2;
    pts.forEach((p, i) => { const x = W - (pts.length - 1 - i) * step; i ? ctx.lineTo(x, y(p.temp)) : ctx.moveTo(x, y(p.temp)); });
    ctx.stroke();
    pts.forEach((p, i) => { const x = W - (pts.length - 1 - i) * step; ctx.beginPath(); ctx.arc(x, y(p.temp), p.temp < 2 || p.temp > 8 ? 5 : 3, 0, 7); ctx.fillStyle = p.temp < 2 || p.temp > 8 ? css("--red") : css("--green"); ctx.fill(); });
  }
  const tsay = (t, c) => { const r = $("t-result"); r.textContent = t; r.className = "result " + (c || ""); };
  function onData(e) {
    const { reading: r, verified, pending } = JSON.parse(e.data);
    verified ? ok++ : bad++;
    pts.push(r); if (pts.length > 40) pts.shift();
    if (r.temp < 2 || r.temp > 8 || r.shock > 0.5) {
      alerts++; const li = document.createElement("li");
      li.textContent = `${new Date(r.ts).toLocaleTimeString()}: ${r.shock > 0.5 ? "Shock " + r.shock + " g" : "Temperature " + r.temp + " \u00B0C out of range"}`;
      $("t-list").prepend(li); while ($("t-list").children.length > 5) $("t-list").lastChild.remove();
    }
    $("t-ok").textContent = ok; $("t-bad").textContent = bad; $("t-pend").textContent = pending; $("t-alerts").textContent = alerts;
    $("t-seal").disabled = !pending; draw();
  }
  $("t-start").onclick = () => {
    es = new EventSource("/api/stream");
    es.onmessage = onData;
    es.onerror = () => { tsay("Backend not reachable. Run npm start and open http://localhost:3000.", "bad"); stop(); };
    $("t-start").disabled = true; $("t-stop").disabled = false; tsay("Streaming. Every reading is signed by the node and checked on arrival.", "ok");
  };
  function stop() { if (es) es.close(); es = null; $("t-start").disabled = false; $("t-stop").disabled = true; }
  $("t-stop").onclick = () => { stop(); tsay("Stream stopped."); };
  $("t-seal").onclick = async () => {
    try {
      const r = await fetch("/api/batches/seal", { method: "POST" }), d = await r.json();
      if (!r.ok) throw new Error(d.error);
      $("t-pend").textContent = 0; $("t-seal").disabled = true;
      tsay(`Sealed ${d.readings} readings (${d.alerts} alert${d.alerts === 1 ? "" : "s"}) as batch ${d.id}. Open it in the ledger below.`, "ok");
      const a = document.createElement("a"); a.href = `/?batch=${d.id}#ledger`; a.textContent = " Open batch"; $("t-result").append(a);
    } catch (e) { tsay(e.message, "bad"); }
  };
  addEventListener("resize", size); size();

  /* ---------- Merkle proof in the browser + NFT passport ---------- */
  const lsay = (t, c) => { const r = $("l-result"); r.textContent = t; r.className = "result " + (c || ""); };
  const cur = () => $("l-id").textContent;
  new MutationObserver(() => { const on = cur() !== "-"; $("l-proof").disabled = !on; $("l-pass").disabled = !on; $("l-json").hidden = true; })
    .observe($("l-id"), { childList: true });
  $("l-proof").onclick = async () => {
    try {
      const b = await (await fetch("/api/batches/" + cur())).json();
      const i = Math.floor(Math.random() * b.readings.length);
      const p = await (await fetch(`/api/batches/${cur()}/proof/${i}`)).json();
      let h = await sha(canon(p.reading));
      for (const s of p.path) h = await sha(s.left ? s.hash + h : h + s.hash);
      h === p.root ? lsay(`Reading ${i + 1} of ${b.readings.length} (${p.reading.temp} \u00B0C) is proven to be in the sealed batch using only ${p.path.length} hashes, checked in your browser.`, "ok")
        : lsay(`Proof failed for reading ${i + 1}. It does not lead to the sealed root, so the stored data was changed.`, "bad");
    } catch (e) { lsay(e.message, "bad"); }
  };
  $("l-pass").onclick = async () => {
    try {
      const d = await (await fetch(`/api/batches/${cur()}/passport`)).json();
      $("l-json").textContent = JSON.stringify(d, null, 2); $("l-json").hidden = false;
      lsay("Passport metadata generated. This is what the ERC-721 token for this batch points to.");
    } catch (e) { lsay(e.message, "bad"); }
  };
  fetch("/api/stats").then(r => r.json()).then(s => {
    $("l-stats").innerHTML = `<span>${s.devices} device${s.devices === 1 ? "" : "s"}</span><span>${s.batches} batches</span><span>${s.readings} readings sealed</span><span>${s.alerts} alerts</span>`;
  }).catch(() => {});
})();
