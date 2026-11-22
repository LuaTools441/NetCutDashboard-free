/* NetCut dashboard — talks to the local netcut_gui.py API. */
const { animate, stagger } = window.Motion || {};
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = (s, r = document) => r.querySelector(s);

const api = async (path, body) => {
  const r = await fetch(path, body ? {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  } : {});
  return r.json();
};

/* ---------- device kind -> icon ---------- */
function kindIcon(kind, isGw, isMe) {
  const k = (kind || "").toLowerCase();
  if (isGw) return "📶";
  if (isMe) return "🖥️";
  if (k.includes("iphone") || k.includes("phone") || k.includes("tablet")) return "📱";
  if (k.includes("tv") || k.includes("chromecast") || k.includes("media")) return "📺";
  if (k.includes("printer")) return "🖨️";
  if (k.includes("camera")) return "🎥";
  if (k.includes("console")) return "🎮";
  if (k.includes("nas") || k.includes("storage")) return "🗄️";
  if (k.includes("iot") || k.includes("smart home")) return "💡";
  if (k.includes("raspberry")) return "🍓";
  if (k.includes("computer") || k.includes("pc")) return "💻";
  return "❔";
}

/* ---------- toasts ---------- */
function toast(msg, kind = "", title = "") {
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.innerHTML = `<div class="bar"></div><div>${title ? `<b>${esc(title)}</b>` : ""}<span>${esc(msg)}</span></div>`;
  $("#toasts").appendChild(el);
  if (animate && !reduce) animate(el, { opacity: [0, 1], x: [40, 0] }, { duration: 0.35, ease: "easeOut" });
  const kill = () => {
    if (animate && !reduce) animate(el, { opacity: 0, x: 40 }, { duration: 0.25 }).finished.then(() => el.remove());
    else el.remove();
  };
  setTimeout(kill, 4200);
  el.onclick = kill;
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/* ---------- popover ---------- */
function popover(anchor, title, items) {
  const pop = $("#popover");
  pop.innerHTML = `<div class="pop-title">${esc(title)}</div>` +
    items.map((it, i) => `<button class="btn sm ${it.cls || "ghost"}" data-i="${i}">${esc(it.label)}</button>`).join("");
  pop.hidden = false;
  const r = anchor.getBoundingClientRect();
  pop.style.left = Math.min(r.left, innerWidth - pop.offsetWidth - 12) + "px";
  pop.style.top = (r.bottom + 6) + "px";
  if (animate && !reduce) animate(pop, { opacity: [0, 1], y: [-6, 0], scale: [0.96, 1] }, { duration: 0.18, ease: "easeOut" });
  pop.querySelectorAll("button").forEach((b) => b.onclick = () => { closePop(); items[+b.dataset.i].onPick(); });
  setTimeout(() => document.addEventListener("pointerdown", onAway, { once: true }), 0);
  function onAway(e) { if (!pop.contains(e.target)) closePop(); }
}
function closePop() { const p = $("#popover"); p.hidden = true; }

/* ---------- actions ---------- */
const NC = {
  busy: new Set(),
  stack: "both",
  async scan() { setScan(true); await api("/api/scan", {}); },
  async cut(ip) { await act(ip, () => api("/api/cut", { ip, stack: NC.stack }), `Cutting ${ip} (${NC.stack})`, "bad"); },
  async monitor(ip) { await act(ip, () => api("/api/monitor", { ip, stack: NC.stack }), `Watching ${ip}'s traffic`, "good"); },
  async setStack(ip, stack) { await act(ip, () => api("/api/stack", { ip, stack }), `${ip} → blocking ${stack}`, "warn"); },
  async clearTraffic(ip) { await api("/api/cleartraffic", { ip }); refresh(); },
  async addRule(from, to, scope, html) {
    const r = await api("/api/rule", { from, to, scope, html });
    if (r.ok) toast(`${from} → ${r.rule.kind} (${scope})${scope !== "all" ? " · auto-watching" : ""}`, "good", "Rule added");
    else toast(r.error || "failed", "bad", "Error");
    refresh();
  },
  async removeRule(from) { await api("/api/rule_remove", { from }); refresh(); },
  async blockDoh(on) { await api("/api/block_doh", { on }); toast(on ? "Encrypted DNS blocked" : "Encrypted DNS allowed", on ? "warn" : ""); refresh(); },
  async https(on) {
    const r = await api("/api/https", { on });
    toast(r.message || (on ? "HTTPS interception on" : "off"), r.ok ? (on ? "warn" : "") : "bad");
    refresh();
  },
  async weak(ip, strength) { await act(ip, () => api("/api/weakwifi", { ip, strength, stack: NC.stack }), `Weak-WiFi (${strength}) on ${ip}`, "warn"); },
  async resume(ip) { await act(ip, () => api("/api/resume", { ip }), ip === "all" ? "Resumed everyone" : `Resumed ${ip}`, "good"); },
  async level(ip, level) { await act(ip, () => api("/api/level", { ip, level }), `${ip} → attack level ${level}`, "warn"); },
  async shape(ip, down, up) {
    const d = +down || 0, u = +up || 0;
    const label = `${ip} → ${d ? d + " Mbps" : "∞"} down / ${u ? u + " Mbps" : "∞"} up`;
    await act(ip, () => api("/api/shape", { ip, down: d, up: u }), label, "warn");
  },
  async verify(ip) {
    toast(`Watching ${ip} for 4 seconds…`, "", "Verifying cut");
    const r = await api("/api/verify", { ip });
    const v = r.result;
    if (!v) return;
    if (v.intercepting)
      toast(`We are intercepting its traffic — ${v.intercepted_total} frames caught (level ${v.level}). It has no internet.`, "good", "Cut confirmed ✓");
    else
      toast(`No traffic captured. It is idle, or still connected. Escape attempts: ${v.escapes_now}. Try a higher level.`, "warn", "Not confirmed");
  },
  async protect(on) { const r = await api("/api/protect", { on }); toast(r.message || (on ? "Protection on" : "Protection off"), on ? "good" : ""); },
};
window.NC = NC;

async function act(ip, fn, msg, kind) {
  NC.busy.add(ip);
  try { const r = await fn(); if (r && r.ok === false) toast(r.error || "failed", "bad", "Error"); else toast(msg, kind); }
  catch (e) { toast(String(e), "bad", "Error"); }
  finally { NC.busy.delete(ip); refresh(); }
}

function setScan(busy) {
  const b = $("#scanBtn"); b.classList.toggle("is-busy", busy);
  $("#scanLabel").textContent = busy ? "Scanning…" : "Scan";
}

/* ---------- render ---------- */
const cards = new Map();  // ip -> element
let lastAdmin = null;

function render(state) {
  $("#netline").textContent = `${state.me}  ·  gateway ${state.gateway}  ·  ${state.network}`;
  setScan(state.scanning);

  // chips
  $("#chips").innerHTML = [
    chip(state.admin ? "ok" : "bad", "Admin", state.admin ? "yes" : "no"),
    chip(state.scapy ? "ok" : "bad", "Npcap", state.scapy ? "ready" : "missing"),
    chip(state.protection ? "ok" : "", "Protection", state.protection ? "on" : "off"),
  ].join("");

  // stat line
  $("#statline").innerHTML = [
    stat("Devices", state.device_count),
    stat("Cutting now", state.active_cuts, state.active_cuts > 0),
    stat("Gateway MAC", state.gateway_mac || "—"),
    stat("Last scan", state.last_scan ? state.last_scan.split(" ")[1] : "—"),
  ].join("");

  const grid = $("#grid");
  const seen = new Set();
  const fresh = [];
  for (const d of state.devices) {
    seen.add(d.ip);
    let el = cards.get(d.ip);
    if (!el) { el = document.createElement("div"); el.className = "card"; cards.set(d.ip, el); grid.appendChild(el); fresh.push(el); }
    updateCard(el, d);
  }
  // remove gone
  for (const [ip, el] of cards) if (!seen.has(ip)) { el.remove(); cards.delete(ip); }

  $("#empty").hidden = state.device_count > 0 || state.scanning;
  grid.hidden = state.device_count === 0;

  if (fresh.length && animate && !reduce)
    animate(fresh, { opacity: [0, 1], y: [14, 0], scale: [0.98, 1] },
      { delay: stagger(0.045), duration: 0.42, ease: [0.17, 0.55, 0.55, 1] });
  else fresh.forEach((e) => (e.style.opacity = 1));

  renderRules(state.rules || []);
  updateScopeOptions(state.devices || []);
  const doh = $("#dohCheck"); if (doh && document.activeElement !== doh) doh.checked = !!state.block_doh;
  const hc = $("#httpsCheck");
  if (hc) {
    if (document.activeElement !== hc) hc.checked = !!state.https_intercept;
    hc.disabled = !state.mitm_ok;
    const link = $("#caLink");
    if (state.https_intercept && state.ca_url) { link.hidden = false; link.href = state.ca_url; }
    else link.hidden = true;
    if (!state.mitm_ok) $("#httpsHelp").textContent = "cryptography lib missing — pip install cryptography";
  }

  if (lastAdmin === false && state.admin) toast("Running as Administrator — cutting is live.", "good");
  lastAdmin = state.admin;
}

function renderRules(rules) {
  const box = $("#rulesList");
  if (!box) return;
  const toText = (r) => r.kind === "redirect" ? r.url : r.kind === "serve" ? "your page" : r.ip;
  box.innerHTML = rules.length ? rules.map((r) => `
    <div class="rule">
      <span class="scope">${esc(r.scope === "all" || !r.scope ? "ALL" : r.scope)}</span>
      <span class="from">${esc(r.from)}</span><span class="ar">→</span>
      <span class="to">${esc(toText(r))}</span>
      <span class="kind ${r.kind}">${r.kind}</span>
      <span class="rm" data-rm="${esc(r.from)}">✕</span>
    </div>`).join("") : `<div class="dim" style="font-size:12.5px">no redirects yet.</div>`;
  box.querySelectorAll("[data-rm]").forEach((b) => b.onclick = () => NC.removeRule(b.dataset.rm));
}

function updateScopeOptions(devices) {
  const sel = $("#ruleScope");
  if (!sel || document.activeElement === sel) return;
  const cur = sel.value;
  const opts = ['<option value="all">All devices</option>'].concat(
    devices.filter((d) => !d.is_me && !d.is_gateway).map((d) =>
      `<option value="${esc(d.ip)}">${esc((d.name || d.vendor || d.ip))} — ${esc(d.ip)}</option>`));
  sel.innerHTML = opts.join("");
  if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;
}

const chip = (cls, k, v) => `<span class="chip ${cls}"><span class="led"></span>${k} <b>${esc(v)}</b></span>`;
const stat = (k, v, alert) => `<div class="stat ${alert ? "alert" : ""}"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`;

function updateCard(el, d) {
  const cut = d.cut;
  const wasCut = el.classList.contains("cut") || el.classList.contains("throttle");
  el.classList.toggle("me", d.is_me);
  el.classList.toggle("gw", d.is_gateway);
  el.classList.toggle("cut", !!cut && cut.mode === "full");
  el.classList.toggle("throttle", !!cut && (cut.mode === "throttle" || cut.mode === "shape"));
  el.classList.toggle("monitor", !!cut && cut.mode === "monitor");
  el.classList.toggle("online", d.online);

  const role = d.is_me ? `<span class="badge role">this PC</span>` :
    d.is_gateway ? `<span class="badge role">router</span>` : "";
  const name = d.name || d.vendor || "unknown device";

  let status = "";
  if (cut && cut.mode === "shape") {
    const d = cut.down_mbps || 0, u = cut.up_mbps || 0;
    if (cut.holding)
      status = `<div class="cutstatus live shaped">
        <span class="label">Speed-limited</span>
        <span class="rate">↓ <b>${(cut.down_rate || 0).toFixed(1)}</b> / ${d ? d : "∞"}</span>
        <span class="rate">↑ <b>${(cut.up_rate || 0).toFixed(1)}</b> / ${u ? u : "∞"}</span>
        <span class="dim" style="margin-left:auto">Mbps</span></div>`;
    else
      status = `<div class="cutstatus wait shaped">
        <span class="label">⚠ not intercepting</span>
        <span class="dim">traffic is bypassing us — the router talks straight to the device</span></div>`;
  } else if (cut && cut.mode === "monitor") {
    status = `<div class="cutstatus live monitor"><span class="label">👁 Watching traffic</span>
      ${stackChip(cut.stack)}<span class="dim" style="margin-left:auto">device stays online</span></div>`;
  } else if (cut) {
    const live = cut.intercepting;
    const cls = live ? "live" : "wait";
    const label = cut.mode === "throttle"
      ? `Weak-WiFi · ${pct(cut.throttle)} throttle`
      : `Cut · level ${cut.level}`;
    const verdict = cut.mode === "throttle"
      ? `degrading` : (live ? `no internet` : `no traffic yet`);
    const pips = cut.mode === "full"
      ? `<span class="lvlpips">${[1, 2, 3].map((n) => `<i class="${n <= cut.level ? "on" : ""}"></i>`).join("")}</span>` : "";
    status = `<div class="cutstatus ${cls}"><span class="label">${esc(label)}</span> ${pips}
      ${stackChip(cut.stack)}<span class="dim">${esc(verdict)}</span>
      <span class="counter" data-count>${cut.intercepted}</span></div>`;
  }

  const acts = buildActions(d);
  el.innerHTML = `
    <div class="card-top">
      <span class="dot"></span>
      <div class="idwrap"><div class="name">${esc(name)}</div><div class="ip mono">${esc(d.ip)}</div></div>
      <div class="kind-ico">${kindIcon(d.kind, d.is_gateway, d.is_me)}</div>
    </div>
    <div class="meta"><span>${esc(d.kind || "—")} ${role}</span><span class="mac">${esc(d.mac || "")}</span></div>
    ${status}
    <div class="actions">${acts}</div>
    ${trafficBlock(d)}`;

  wireActions(el, d);
  animateCounter(el, d);
  if (!wasCut && cut && animate && !reduce) animate(el, { scale: [1, 1.025, 1] }, { duration: 0.4, ease: "easeOut" });
}

const pct = (f) => Math.round((f || 0) * 100) + "%";
const stackChip = (s) => `<span class="stackchip" data-a="stack" title="pipe blocked — click to change">${s === "both" ? "v4+v6" : s}</span>`;

function buildActions(d) {
  if (d.is_me || d.is_gateway) return `<span class="dim" style="font-size:12px">protected — never cut</span>`;
  if (!d.cut)
    return `<button class="btn danger sm" data-a="cut">Cut</button>
            <button class="btn warn sm" data-a="weak">Weak-WiFi ▾</button>
            <button class="btn sm ghost" data-a="shape">Limit ▾</button>
            <button class="btn sm ghost" data-a="watch">👁 Watch ▾</button>`;
  if (d.cut.mode === "monitor")
    return `<button class="btn primary sm" data-a="resume">Stop watching</button>`;
  if (d.cut.mode === "shape")
    return `<button class="btn primary sm" data-a="resume">Resume</button>
            <button class="btn sm ghost" data-a="shape">Edit limits ▾</button>`;
  const extra = d.cut.mode === "full"
    ? `<button class="btn sm ghost" data-a="level">Level ▾</button>`
    : `<button class="btn sm ghost" data-a="weak">Strength ▾</button>`;
  return `<button class="btn primary sm" data-a="resume">Resume</button>
          <button class="btn sm ghost" data-a="verify">Verify</button>${extra}`;
}

const trafExpanded = new Set();   // ips whose traffic list is expanded (persists across polls)

function trafficBlock(d) {
  if (!d.cut || !("log" in d.cut)) return "";
  const open = trafExpanded.has(d.ip);
  const total = d.cut.log_total || 0;
  const uniq = (d.cut.log || []).length;
  let list = "";
  if (open) {
    if (!d.cut.log.length) list = `<div class="traffic-empty">no named requests seen yet…</div>`;
    else list = `<div class="traffic">` + d.cut.log.map((r) =>
      `<div class="treq"><span class="tkind ${r.kind}">${r.kind.toUpperCase()}</span>` +
      `<span class="tname" title="${esc(r.name)}">${esc(r.name)}</span>` +
      `<span class="tcount">×${r.count}</span></div>`).join("") + `</div>`;
  }
  return `<div class="traffic-head ${open ? "open" : ""}" data-a="traffic">
      📡 <b>Traffic</b> · ${uniq} hosts, ${total} reqs
      ${open ? `<span class="btn sm ghost" data-a="clrtraffic" style="padding:2px 7px">clear</span>` : ""}
      <span class="caret">▸</span></div>${list}`;
}

function wireActions(el, d) {
  el.querySelectorAll("[data-a]").forEach((b) => {
    b.onclick = (e) => {
      const a = b.dataset.a;
      if (a === "cut") NC.cut(d.ip);
      else if (a === "resume") NC.resume(d.ip);
      else if (a === "verify") NC.verify(d.ip);
      else if (a === "weak") popover(b, "WiFi strength", [
        { label: "Light — a little lag", cls: "ghost", onPick: () => NC.weak(d.ip, "light") },
        { label: "Medium — choppy", cls: "warn", onPick: () => NC.weak(d.ip, "medium") },
        { label: "Heavy — barely alive", cls: "danger", onPick: () => NC.weak(d.ip, "heavy") },
      ]);
      else if (a === "level") popover(b, "Attack level", [
        { label: "1 · gentle", cls: "ghost", onPick: () => NC.level(d.ip, 1) },
        { label: "2 · firm", cls: "warn", onPick: () => NC.level(d.ip, 2) },
        { label: "3 · hard", cls: "danger", onPick: () => NC.level(d.ip, 3) },
      ]);
      else if (a === "shape") speedDialog(b, d);
      else if (a === "watch") popover(b, "Watch traffic", [
        { label: "Keep online (watch only)", cls: "ghost", onPick: () => NC.monitor(d.ip) },
        { label: "Block + watch (cut)", cls: "danger", onPick: () => NC.cut(d.ip) },
      ]);
      else if (a === "traffic") { trafExpanded.has(d.ip) ? trafExpanded.delete(d.ip) : trafExpanded.add(d.ip); updateCard(el, d); }
      else if (a === "clrtraffic") { e.stopPropagation(); NC.clearTraffic(d.ip); }
      else if (a === "stack") popover(b, "Block which pipe", [
        { label: "IPv4 only", cls: "ghost", onPick: () => NC.setStack(d.ip, "ipv4") },
        { label: "IPv6 only", cls: "ghost", onPick: () => NC.setStack(d.ip, "ipv6") },
        { label: "Both (v4 + v6)", cls: "warn", onPick: () => NC.setStack(d.ip, "both") },
      ]);
    };
  });
}

function speedDialog(anchor, d) {
  const cur = d.cut && d.cut.mode === "shape" ? d.cut : { down_mbps: 5, up_mbps: 1 };
  const pop = $("#popover");
  const presets = [[5, 1], [10, 2], [2, 0.5], [1, 0.5]];
  pop.innerHTML = `
    <div class="pop-title">Speed limit · Mbps (0 = unlimited)</div>
    <div class="speedrow"><label>↓ Download</label><input id="spd" type="number" min="0" step="0.5" value="${cur.down_mbps || 0}"></div>
    <div class="speedrow"><label>↑ Upload</label><input id="spu" type="number" min="0" step="0.5" value="${cur.up_mbps || 0}"></div>
    <div class="speedpresets">${presets.map(([a, b]) => `<button class="btn sm ghost" data-p="${a}:${b}">${a}/${b}</button>`).join("")}</div>
    <div class="pop-note">Best for low limits (≤ ~30 Mbps). On a gigabit link a high limit won't hold — use the router's QoS for that.</div>
    <button class="btn warn sm" id="spapply" style="width:100%;justify-content:center;margin-top:4px">Apply limit</button>`;
  pop.hidden = false;
  const r = anchor.getBoundingClientRect();
  pop.style.left = Math.min(r.left, innerWidth - 190) + "px";
  pop.style.top = (r.bottom + 6) + "px";
  if (animate && !reduce) animate(pop, { opacity: [0, 1], y: [-6, 0], scale: [0.96, 1] }, { duration: 0.18, ease: "easeOut" });
  const dIn = $("#spd", pop), uIn = $("#spu", pop);
  pop.querySelectorAll("[data-p]").forEach((btn) => btn.onclick = () => {
    const [a, b] = btn.dataset.p.split(":"); dIn.value = a; uIn.value = b;
  });
  $("#spapply", pop).onclick = () => { closePop(); NC.shape(d.ip, dIn.value, uIn.value); };
  setTimeout(() => document.addEventListener("pointerdown", function away(e) {
    if (!pop.contains(e.target)) closePop(); else document.addEventListener("pointerdown", away, { once: true });
  }, { once: true }), 0);
}

function animateCounter(el, d) {
  const node = el.querySelector("[data-count]");
  if (!node || !d.cut) return;
  const to = d.cut.intercepted;
  const from = +node.dataset.prev || 0;
  node.dataset.prev = to;
  if (from === to || !animate || reduce) { node.textContent = to; return; }
  animate(from, to, { duration: 0.5, ease: "easeOut", onUpdate: (v) => (node.textContent = Math.round(v)) });
}

/* ---------- loop ---------- */
async function refresh() {
  try { render(await api("/api/state")); } catch (e) { /* server starting */ }
}
$("#scanBtn").onclick = () => NC.scan();
$("#resumeAllBtn").onclick = () => NC.resume("all");
$("#protectBtn").onclick = () => api("/api/state").then((s) => NC.protect(!s.protection));
$("#stackSeg").querySelectorAll("button").forEach((b) => b.onclick = () => {
  NC.stack = b.dataset.s;
  $("#stackSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
});
$("#rulesBtn").onclick = () => { const p = $("#rulesPanel"); p.hidden = !p.hidden; };
$("#ruleAdd").onclick = () => {
  const f = $("#ruleFrom").value.trim(), t = $("#ruleTo").value.trim(), sc = $("#ruleScope").value || "all";
  const html = $("#ruleHtml").value.trim();
  if (f && (t || html)) { NC.addRule(f, t, sc, html); $("#ruleFrom").value = ""; $("#ruleTo").value = ""; $("#ruleHtml").value = ""; }
};
$("#dohCheck").onchange = (e) => NC.blockDoh(e.target.checked);
$("#httpsCheck").onchange = (e) => NC.https(e.target.checked);
$("#ruleTo").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#ruleAdd").click(); });

refresh();
setInterval(refresh, 1500);
