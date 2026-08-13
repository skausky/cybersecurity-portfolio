// ── State ────────────────────────────────────────────────────────
const state = {
  token: new URLSearchParams(location.search).get("token") || "",
  networks: [],
  selected: new Map(),   // bssid → target obj
  devices: [],
  presenceStates: [],
  rogues: [],
  ws: null,
  drawerBssid: null,
  scanBusy: false,
  watchActive: false,
};

// ── Config & API ─────────────────────────────────────────────────
async function loadConfig() {
  const r = await fetch("/config.json");
  const cfg = await r.json();
  if (!state.token) state.token = cfg.token;
}

function headers() {
  return { "Content-Type": "application/json", Authorization: `Bearer ${state.token}` };
}

async function api(path, opts = {}) {
  const url = path.includes("?") ? `${path}&token=${state.token}` : `${path}?token=${state.token}`;
  const res = await fetch(url, { ...opts, headers: { ...headers(), ...(opts.headers || {}) } });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function authedHref(path) {
  return path.includes("?") ? `${path}&token=${state.token}` : `${path}?token=${state.token}`;
}

// ── Live feed ────────────────────────────────────────────────────
function log(msg, kind = "info") {
  const el = document.createElement("div");
  el.className = `log ${kind}`;
  el.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  const feed = document.getElementById("liveFeed");
  feed.prepend(el);
  while (feed.children.length > 150) feed.lastChild.remove();
}

// ── Tab switching ────────────────────────────────────────────────
function tab(name) {
  document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
  const btn = document.querySelector(`[data-tab="${name}"]`);
  const panel = document.getElementById(`panel-${name}`);
  if (btn) btn.classList.add("active");
  if (panel) panel.classList.add("active");
  if (name === "devices") loadDevices();
  if (name === "presence") loadPresence();
  if (name === "intel") { loadRogues(); loadSessions(); loadStats(); }
}

// ── Sidebar ──────────────────────────────────────────────────────
function encClass(enc) {
  const e = (enc || "").toUpperCase();
  if (e.includes("WPA3")) return "enc-wpa3";
  if (e.includes("WPA2")) return "enc-wpa2";
  if (e.includes("WEP"))  return "enc-wep";
  if (e === "OPN" || e === "OPEN" || e === "") return "enc-open";
  if (e.includes("WPA"))  return "enc-wpa2";
  return "enc-unknown";
}

function encLabel(enc) {
  const e = (enc || "").toUpperCase();
  if (e.includes("WPA3")) return "WPA3";
  if (e.includes("WPA2")) return "WPA2";
  if (e.includes("WPA"))  return "WPA";
  if (e.includes("WEP"))  return "WEP";
  if (e === "OPN" || e === "OPEN" || e === "") return "OPEN";
  return enc || "?";
}

function powerWidth(p) {
  const n = parseInt(p, 10);
  if (Number.isNaN(n)) return 6;
  return Math.min(100, Math.max(6, 100 + n));
}

function relTime(ts) {
  if (!ts) return "never";
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

function renderSidebar() {
  const q = (document.getElementById("globalSearch").value || "").toLowerCase();
  const list = document.getElementById("apList");
  list.innerHTML = "";

  const nets = q
    ? state.networks.filter(n =>
        (n.ssid || "").toLowerCase().includes(q) ||
        (n.bssid || "").toLowerCase().includes(q)
      )
    : state.networks;

  if (!nets.length) {
    list.innerHTML = `<div style="padding:1rem;color:var(--muted);font-size:.8rem">No networks — run a scan</div>`;
    return;
  }

  nets.forEach(n => {
    const selected = state.selected.has(n.bssid);
    const isCurrent = state.drawerBssid === n.bssid;
    const ec = encClass(n.encryption);
    const el = encLabel(n.encryption);
    const pw = powerWidth(n.power);

    const div = document.createElement("div");
    div.className = `ap-row${isCurrent ? " active" : ""}`;
    div.innerHTML = `
      <div class="ap-row-top">
        <span class="ap-ssid">${esc(n.ssid || "<hidden>")}</span>
        <span class="enc ${ec}">${el}</span>
      </div>
      <div class="ap-row-meta">
        <span>${esc(n.bssid)}</span>
        <span>ch ${n.channel || "?"}</span>
        <span>${n.power || "?"}dBm</span>
        ${selected ? '<span style="color:var(--accent)">✓ target</span>' : ""}
      </div>
      <div class="ap-signal" style="width:${pw}%"></div>`;
    div.onclick = () => openDrawer(n);
    list.appendChild(div);
  });
}

function esc(s) {
  return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ── AP Drawer ────────────────────────────────────────────────────
function openDrawer(ap) {
  state.drawerBssid = ap.bssid;
  document.getElementById("drawerSsid").textContent = ap.ssid || "<hidden>";
  document.getElementById("drawerBssid").textContent = ap.bssid;
  document.getElementById("drawerMeta").innerHTML = `
    <div class="drawer-meta-item"><span class="drawer-meta-label">Channel</span>${esc(ap.channel)}</div>
    <div class="drawer-meta-item"><span class="drawer-meta-label">Encryption</span>${esc(ap.encryption)}</div>
    <div class="drawer-meta-item"><span class="drawer-meta-label">Cipher</span>${esc(ap.cipher)}</div>
    <div class="drawer-meta-item"><span class="drawer-meta-label">Auth</span>${esc(ap.auth)}</div>
    <div class="drawer-meta-item"><span class="drawer-meta-label">Power</span>${esc(ap.power)} dBm</div>
    <div class="drawer-meta-item"><span class="drawer-meta-label">Vendor</span>${esc(ap.vendor_oui)}</div>`;

  document.getElementById("drawerAddTarget").textContent =
    state.selected.has(ap.bssid) ? "Remove Target" : "Add to Targets";
  document.getElementById("drawerAddTarget").onclick = () => {
    toggleTarget(ap);
    document.getElementById("drawerAddTarget").textContent =
      state.selected.has(ap.bssid) ? "Remove Target" : "Add to Targets";
  };
  document.getElementById("drawerScanClients").onclick = () => scanClients(ap.bssid);

  document.getElementById("apDrawer").classList.add("open");
  document.getElementById("drawerOverlay").classList.add("open");
  renderSidebar();

  // Load clients from cache
  const cached = state.networks.find(n => n.bssid === ap.bssid);
  renderDrawerClients([]);
  loadDrawerSparkline(ap.bssid);
}

function closeDrawer() {
  state.drawerBssid = null;
  document.getElementById("apDrawer").classList.remove("open");
  document.getElementById("drawerOverlay").classList.remove("open");
  renderSidebar();
}

function renderDrawerClients(clients) {
  const el = document.getElementById("drawerClients");
  if (!clients.length) {
    el.innerHTML = `<div style="color:var(--muted);font-size:.8rem;padding:.5rem 0">No clients cached — click Scan Clients</div>`;
    return;
  }
  el.innerHTML = clients.map(c => {
    const traits = parsedTraits(c.traits_json);
    return `<div class="drawer-client-row">
      <span class="drawer-client-icon">${traits.device_icon || "❓"}</span>
      <div class="drawer-client-info">
        <div>${esc(traits.device_label || "Unknown")}</div>
        <div class="drawer-client-mac">${esc(c.mac || c.station_mac)}</div>
      </div>
      <div style="font-size:.75rem;color:var(--muted)">${c.power || "?"}dBm</div>
    </div>`;
  }).join("");
}

async function loadDrawerSparkline(bssid) {
  try {
    const data = await api(`/api/history/aps/${encodeURIComponent(bssid)}/power?hours=24`);
    drawSparkline(data.points || []);
  } catch (_) { /* ignore */ }
}

function drawSparkline(points) {
  const line = document.getElementById("sparklineLine");
  if (!points.length) { line.setAttribute("points", ""); return; }
  const W = 300, H = 60, PAD = 4;
  const powers = points.map(p => parseInt(p.power, 10) || -100);
  const times  = points.map(p => p.ts);
  const minP = Math.min(...powers), maxP = Math.max(...powers);
  const minT = Math.min(...times),  maxT = Math.max(...times);
  const rangeP = maxP - minP || 1, rangeT = maxT - minT || 1;
  const pts = points.map((p, i) => {
    const x = PAD + ((times[i] - minT) / rangeT) * (W - PAD * 2);
    const y = (H - PAD) - ((powers[i] - minP) / rangeP) * (H - PAD * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  line.setAttribute("points", pts.join(" "));
}

// ── Scan UX ──────────────────────────────────────────────────────
function setScanBusy(busy, duration = 20) {
  state.scanBusy = busy;
  const btn = document.getElementById("btnScan");
  const cancel = document.getElementById("btnCancelScan");
  const wrap = document.getElementById("scanProgressWrap");
  const fill = document.getElementById("scanProgressFill");
  const label = document.getElementById("scanProgressLabel");
  const pill = document.getElementById("scanPill");

  if (busy) {
    btn.style.display = "none";
    cancel.style.display = "";
    wrap.style.display = "";
    fill.style.width = "0%";
    label.textContent = `0 / ${duration}s`;
    pill.textContent = "scanning";
    pill.className = "status-pill scanning";
  } else {
    btn.style.display = "";
    cancel.style.display = "none";
    wrap.style.display = "none";
    fill.style.width = "0%";
    pill.textContent = "idle";
    pill.className = "status-pill idle";
  }
}

function updateScanProgress(elapsed, total) {
  const pct = Math.min(100, Math.round(elapsed / total * 100));
  document.getElementById("scanProgressFill").style.width = `${pct}%`;
  document.getElementById("scanProgressLabel").textContent = `${elapsed} / ${total}s`;
}

// ── Interface ────────────────────────────────────────────────────
async function refreshInterfaces() {
  const data = await api("/api/interfaces");
  const sel = document.getElementById("ifaceSelect");
  const prev = sel.value;
  sel.innerHTML = "";
  (data.interfaces || []).forEach(i => {
    const o = document.createElement("option");
    o.value = i; o.textContent = i;
    if (i === prev) o.selected = true;
    sel.appendChild(o);
  });
}

function showIfaceCapabilities(caps) {
  const warnEl = document.getElementById("ifaceWarn");
  if (!caps) {
    warnEl.style.display = "none";
    return;
  }
  const parts = [];
  if (caps.driver) parts.push(`Driver: ${caps.driver}`);
  if (caps.has_5ghz) parts.push("5 GHz: yes"); else parts.push("5 GHz: no");
  if (caps.current_channel) parts.push(`Tuned: ch ${caps.current_channel}`);
  document.getElementById("ifaceStatus").textContent =
    `Monitor: ${caps.interface || ""} · ${parts.join(" · ")}`;

  if (caps.warnings && caps.warnings.length) {
    warnEl.style.display = "block";
    warnEl.innerHTML = caps.warnings.map(w => `<div>${esc(w)}</div>`).join("");
    caps.warnings.forEach(w => log(w, "warn"));
  } else {
    warnEl.style.display = "none";
    warnEl.innerHTML = "";
  }
}

async function enableIface() {
  const iface = document.getElementById("ifaceSelect").value;
  const r = await api("/api/interface", { method: "POST", body: JSON.stringify({ interface: iface }) });
  document.getElementById("ifaceChip").textContent = r.monitor;
  document.getElementById("ifaceChip").className = "chip active-chip";
  showIfaceCapabilities(r.capabilities);
  log(`Monitor mode on ${r.monitor}`, "ok");
}

// ── Scanning ─────────────────────────────────────────────────────
function getSelectedBand() {
  const active = document.querySelector(".band-chip.active");
  return active ? active.dataset.band : "abg";
}

async function scanNetworks() {
  if (state.scanBusy) return;
  const band = getSelectedBand();
  setScanBusy(true, 20);
  log(`Scan started (band: ${band})…`, "info");
  try {
    const r = await api("/api/scan", { method: "POST", body: JSON.stringify({ band, duration: band === "a" ? 30 : 45 }) });
    state.networks = r.networks || [];
    log(`Scan complete — ${r.count} network(s) found`, r.count ? "ok" : "warn");
    renderSidebar();
  } catch (err) {
    log(`Scan error: ${err.message}`, "fail");
  } finally {
    setScanBusy(false);
  }
}

async function cancelScan() {
  await api("/api/scan/cancel", { method: "POST", body: "{}" }).catch(() => {});
  setScanBusy(false);
  log("Scan cancelled", "warn");
}

async function scanClients(bssid) {
  log(`Scanning clients for ${bssid}…`, "info");
  try {
    const r = await api(`/api/scan/clients/${encodeURIComponent(bssid)}`, { method: "POST", body: "{}" });
    log(`${r.count} client(s) on ${bssid}`, r.count ? "ok" : "warn");
    if (state.drawerBssid === bssid) renderDrawerClients(r.clients || []);
  } catch (err) {
    log(`Client scan error: ${err.message}`, "fail");
  }
}

// ── Targets ──────────────────────────────────────────────────────
function toggleTarget(ap) {
  if (state.selected.has(ap.bssid)) {
    state.selected.delete(ap.bssid);
  } else {
    state.selected.set(ap.bssid, {
      bssid: ap.bssid,
      ssid: ap.ssid,
      channel: parseInt(ap.channel, 10) || 1,
      mode: "all_clients",
      client_macs: [],
    });
  }
  renderTargetChips();
  renderSidebar();
  persistTargets();
}

function persistTargets() {
  api("/api/targets", {
    method: "PUT",
    body: JSON.stringify({ targets: [...state.selected.keys()] }),
  }).catch(() => {});
}

function renderTargetChips() {
  const chips = document.getElementById("targetChips");
  const hint = document.getElementById("noTargetsHint");
  const count = document.getElementById("targetCount");
  count.textContent = state.selected.size;

  if (!state.selected.size) {
    chips.innerHTML = "";
    hint.style.display = "";
    return;
  }
  hint.style.display = "none";
  chips.innerHTML = [...state.selected.values()].map(t => `
    <span class="target-chip">
      ${esc(t.ssid || t.bssid)}
      <button class="target-chip-x" data-bssid="${esc(t.bssid)}">✕</button>
    </span>`).join("");
  chips.querySelectorAll(".target-chip-x").forEach(btn => {
    btn.onclick = (e) => {
      e.stopPropagation();
      state.selected.delete(btn.dataset.bssid);
      renderTargetChips();
      renderSidebar();
      persistTargets();
    };
  });
}

// ── Deauth ───────────────────────────────────────────────────────
async function startDeauth() {
  if (!state.selected.size) return alert("Select at least one target from the sidebar.");
  const packets = parseInt(document.getElementById("pktCount").value, 10) || 3;
  const loop = document.getElementById("loopDeauth").checked;
  const targets = [...state.selected.values()];
  await api("/api/deauth/start", {
    method: "POST",
    body: JSON.stringify({ targets, packets, loop, duration_seconds: 0 }),
  });
  log(`Deauth started — ${targets.length} target(s), ${packets} pkts${loop ? ", looping" : ""}`, "warn");
  document.getElementById("deauthPill").style.display = "";
  tab("live");
}

async function stopDeauth() {
  await api("/api/deauth/stop", { method: "POST", body: "{}" });
  log("Stop signal sent", "info");
}

// ── Devices panel ─────────────────────────────────────────────────
function parsedTraits(json) {
  try { return JSON.parse(json || "{}"); } catch (_) { return {}; }
}

function deviceMatchesFilter(d, q, typeFilter, watchedOnly) {
  if (watchedOnly && !d.watch) return false;
  if (typeFilter) {
    const traits = parsedTraits(d.traits_json);
    if ((traits.device_type || "") !== typeFilter) return false;
  }
  if (!q) return true;
  const haystack = [d.mac, d.vendor_oui, d.label, d.ap_ssid].join(" ").toLowerCase();
  return haystack.includes(q);
}

async function loadDevices() {
  try {
    const data = await api("/api/devices");
    state.devices = data.devices || [];
    renderDevices();
  } catch (err) {
    log(`Devices load error: ${err.message}`, "fail");
  }
}

function renderDevices() {
  const q = (document.getElementById("deviceFilter").value || "").toLowerCase();
  const typeFilter = document.getElementById("deviceTypeFilter").value;
  const watchedOnly = document.getElementById("watchedOnly").checked;
  const grid = document.getElementById("deviceGrid");
  const filtered = state.devices.filter(d => deviceMatchesFilter(d, q, typeFilter, watchedOnly));

  if (!filtered.length) {
    grid.innerHTML = `<div style="color:var(--muted);font-size:.85rem;padding:.5rem">No devices yet — scan some clients first.</div>`;
    return;
  }

  grid.innerHTML = filtered.map(d => {
    const traits = parsedTraits(d.traits_json);
    const icon = traits.device_icon || "❓";
    const dtype = traits.device_label || "Unknown";
    const label = d.label || d.vendor_oui || d.mac;
    const ap = d.ap_ssid ? `on ${esc(d.ap_ssid)}` : (d.ap_bssid ? `on ${esc(d.ap_bssid)}` : "");
    const rand = d.is_randomized ? '<span class="device-badge rand-badge">randomized</span>' : "";
    const watchBadge = d.watch ? '<span class="device-badge watch-badge">watched</span>' : "";
    return `<div class="device-card${d.watch ? " watched" : ""}${d.label ? " labeled" : ""}"
      data-mac="${esc(d.mac)}">
      <button class="device-watch-btn ${d.watch ? "active" : ""}"
        data-mac="${esc(d.mac)}" data-watch="${d.watch ? 1 : 0}"
        title="${d.watch ? "Stop watching" : "Watch this device"}">${d.watch ? "👁 Watching" : "👁 Watch"}</button>
      <span class="device-icon">${icon}</span>
      <div class="device-label-text" title="${esc(d.label || d.vendor_oui || d.mac)}">${esc(label)}</div>
      <div class="device-vendor">${esc(d.vendor_oui || "")}</div>
      <div class="device-mac">${esc(d.mac)}</div>
      ${ap ? `<div class="device-ap">${ap}</div>` : ""}
      <div class="device-last">last seen ${relTime(d.last_seen)}</div>
      <div class="device-badges">${rand}${watchBadge}
        <span class="device-badge">${esc(dtype)}</span>
      </div>
    </div>`;
  }).join("");

  // Click to open label editor
  grid.querySelectorAll(".device-card").forEach(card => {
    card.addEventListener("click", e => {
      if (e.target.classList.contains("device-watch-btn")) return;
      showLabelModal(card.dataset.mac);
    });
  });
  grid.querySelectorAll(".device-watch-btn").forEach(btn => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const mac = btn.dataset.mac;
      const isWatched = btn.dataset.watch === "1";
      const device = state.devices.find(d => d.mac === mac);
      const label = device?.label || mac;
      await api(`/api/devices/${encodeURIComponent(mac)}/label`, {
        method: "PUT",
        body: JSON.stringify({ label, watch: !isWatched }),
      });
      log(`${!isWatched ? "Watching" : "Stopped watching"} ${label}`, "info");
      await loadDevices();
    };
  });
}

function showLabelModal(mac) {
  const device = state.devices.find(d => d.mac === mac);
  if (!device) return;
  const existing = device.label || "";
  const existingNotes = device.notes || "";
  const existingColor = device.color || "#5b9dff";

  const modal = document.createElement("div");
  modal.className = "device-label-edit open";
  modal.innerHTML = `
    <div class="card-label">LABEL DEVICE</div>
    <div class="device-mac" style="margin-bottom:.4rem">${esc(mac)}</div>
    <input class="lbl-input" placeholder="Device name (e.g. Dad's iPhone)" value="${esc(existing)}" style="min-height:36px;border-radius:8px;background:var(--surface2);border:1px solid rgba(255,255,255,.1);color:var(--text);padding:0 .75rem;font-size:.88rem;width:100%" />
    <input class="notes-input" placeholder="Notes (optional)" value="${esc(existingNotes)}" style="min-height:36px;border-radius:8px;background:var(--surface2);border:1px solid rgba(255,255,255,.1);color:var(--text);padding:0 .75rem;font-size:.88rem;width:100%" />
    <div style="display:flex;gap:.4rem;margin-top:.3rem">
      <button class="btn accent btn-sm lbl-save" style="flex:1">Save</button>
      ${existing ? '<button class="btn btn-sm lbl-del" style="color:var(--bad)">Remove</button>' : ""}
      <button class="btn btn-sm lbl-cancel">Cancel</button>
    </div>`;

  const card = document.querySelector(`[data-mac="${CSS.escape(mac)}"]`);
  if (!card) return;
  card.appendChild(modal);

  modal.querySelector(".lbl-cancel").onclick = () => modal.remove();
  modal.querySelector(".lbl-save").onclick = async () => {
    const label = modal.querySelector(".lbl-input").value.trim();
    if (!label) return;
    await api(`/api/devices/${encodeURIComponent(mac)}/label`, {
      method: "PUT",
      body: JSON.stringify({ label, notes: modal.querySelector(".notes-input").value.trim(), color: existingColor, watch: device.watch || false }),
    });
    log(`Labeled ${mac} as "${label}"`, "ok");
    modal.remove();
    await loadDevices();
  };
  const delBtn = modal.querySelector(".lbl-del");
  if (delBtn) delBtn.onclick = async () => {
    await api(`/api/devices/${encodeURIComponent(mac)}/label`, { method: "DELETE" });
    log(`Removed label for ${mac}`, "warn");
    modal.remove();
    await loadDevices();
  };
}

// ── Presence panel ─────────────────────────────────────────────────
async function loadPresence() {
  try {
    const data = await api("/api/presence/state");
    state.presenceStates = data.states || [];
    renderPresence();
    renderTimelines();
  } catch (err) {
    log(`Presence load error: ${err.message}`, "fail");
  }
}

function renderPresence() {
  const grid = document.getElementById("homeGrid");
  if (!state.presenceStates.length) {
    grid.innerHTML = "";
    return;
  }
  grid.innerHTML = state.presenceStates.map(s => {
    const isHome = s.status === "home";
    return `<div class="home-tile${isHome ? " status-home" : " status-away"}">
      <div class="home-tile-status">${isHome ? "🟢" : "⚫"}</div>
      <div class="home-tile-label">${esc(s.label || s.mac)}</div>
      <div class="home-tile-mac">${esc(s.mac)}</div>
      ${s.ap_ssid ? `<div class="home-tile-ap">${esc(s.ap_ssid)}</div>` : ""}
      <div class="home-tile-last">${isHome ? "home now" : "away"} · ${relTime(s.updated_at)}</div>
    </div>`;
  }).join("");
}

async function renderTimelines() {
  const grid = document.getElementById("timelineGrid");
  const hint = document.getElementById("noWatchedHint");
  const watched = state.presenceStates;
  if (!watched.length) { grid.innerHTML = ""; hint.style.display = ""; return; }
  hint.style.display = "none";
  grid.innerHTML = "";
  const now = Date.now() / 1000;
  const start = now - 86400;

  for (const s of watched) {
    try {
      const data = await api(`/api/presence/timeline/${encodeURIComponent(s.mac)}?hours=24`);
      const segs = buildTimelineSegments(data.timeline || [], start, now);
      const row = document.createElement("div");
      row.className = "timeline-row";
      row.innerHTML = `
        <span class="timeline-label">${esc(s.label || s.mac)}</span>
        <div class="timeline-bar">${segs.map(seg =>
          `<div class="timeline-seg ${seg.status}" style="width:${seg.pct.toFixed(2)}%" title="${seg.status} for ${Math.round(seg.dur / 60)}m"></div>`
        ).join("")}</div>
        <span class="timeline-time">${relTime(s.last_seen_home)}</span>`;
      grid.appendChild(row);
    } catch (_) {}
  }
}

function buildTimelineSegments(events, start, end) {
  if (!events.length) return [{ status: "unknown", pct: 100, dur: end - start }];
  const total = end - start;
  const segs = [];
  let cursor = start;

  for (const ev of events) {
    if (ev.ts > cursor) {
      const dur = Math.min(ev.ts, end) - cursor;
      segs.push({ status: "away", pct: (dur / total) * 100, dur });
    }
    cursor = ev.ts;
  }
  // last segment to now
  if (cursor < end) {
    const last = events[events.length - 1];
    const dur = end - cursor;
    segs.push({ status: last?.status || "away", pct: (dur / total) * 100, dur });
  }
  return segs.filter(s => s.pct > 0);
}

async function startPresenceWatch() {
  const interval = parseInt(document.getElementById("watchInterval").value, 10) || 120;
  await api("/api/presence/watch/start", {
    method: "POST",
    body: JSON.stringify({ interval, bssids: [] }),
  });
  state.watchActive = true;
  document.getElementById("btnStartWatch").style.display = "none";
  document.getElementById("btnStopWatch").style.display = "";
  document.getElementById("watchPill").style.display = "";
  log(`Presence watch started (every ${interval}s)`, "ok");
}

async function stopPresenceWatch() {
  await api("/api/presence/watch/stop", { method: "POST", body: "{}" });
  state.watchActive = false;
  document.getElementById("btnStartWatch").style.display = "";
  document.getElementById("btnStopWatch").style.display = "none";
  document.getElementById("watchPill").style.display = "none";
  log("Presence watch stopped", "info");
}

// ── Stats panel ────────────────────────────────────────────────────
async function loadStats() {
  let s;
  try { s = await api("/api/stats"); } catch { return; }

  const total = s.deauth_total ?? 0;
  const success = total ? Math.round((s.deauth_success ?? 0) / total * 100) : 0;

  document.getElementById("kpiTotalVal").textContent = total || "–";
  document.getElementById("kpiSuccessVal").textContent = total ? `${success}%` : "–";
  document.getElementById("kpiEvictedVal").textContent =
    (s.avg_clients_evicted != null) ? (s.avg_clients_evicted).toFixed(1) : "–";
  document.getElementById("kpiLabeledVal").textContent = s.labeled_devices ?? "–";
  document.getElementById("kpiWatchedVal").textContent = s.watched_devices ?? "–";

  // Confidence breakdown bars
  const conf = {
    high: s.confidence_high ?? 0,
    med:  s.confidence_medium ?? 0,
    low:  s.confidence_low ?? 0,
    inc:  s.confidence_inconclusive ?? 0,
  };
  const confTotal = conf.high + conf.med + conf.low + conf.inc || 1;
  const pct = v => `${Math.round(v / confTotal * 100)}%`;
  document.getElementById("confHigh").style.width = pct(conf.high);
  document.getElementById("confMed").style.width  = pct(conf.med);
  document.getElementById("confLow").style.width  = pct(conf.low);
  document.getElementById("confInc").style.width  = pct(conf.inc);
  document.getElementById("confHighN").textContent = conf.high;
  document.getElementById("confMedN").textContent  = conf.med;
  document.getElementById("confLowN").textContent  = conf.low;
  document.getElementById("confIncN").textContent  = conf.inc;

  // By mode
  const modeBody = document.getElementById("modeBody");
  modeBody.innerHTML = "";
  (s.by_mode || []).forEach(m => {
    const sp = m.cnt ? Math.round((m.wins || 0) / m.cnt * 100) : 0;
    const cls = sp >= 60 ? "good" : sp >= 30 ? "warn" : "bad";
    modeBody.insertAdjacentHTML("beforeend",
      `<tr><td>${m.mode}</td><td>${m.cnt}</td><td class="${cls}">${sp}%</td></tr>`);
  });
  if (!s.by_mode?.length) modeBody.insertAdjacentHTML("beforeend", `<tr><td colspan="3" style="color:var(--muted)">No data yet</td></tr>`);

  // Top targets
  const ttBody = document.getElementById("topTargetsBody");
  ttBody.innerHTML = "";
  (s.top_targets || []).forEach(t => {
    const sp = t.cnt ? Math.round((t.wins || 0) / t.cnt * 100) : 0;
    const cls = sp >= 60 ? "good" : sp >= 30 ? "warn" : "bad";
    const bssid = t.target_bssid || "";
    // Try to find SSID from state.networks
    const net = state.networks.find(n => n.bssid === bssid);
    const display = (net?.ssid && net.ssid !== "<hidden>") ? net.ssid : `<span class="mono">${bssid.slice(0,11)}</span>`;
    ttBody.insertAdjacentHTML("beforeend",
      `<tr><td>${display}</td><td>${t.cnt}</td><td class="${cls}">${sp}%</td></tr>`);
  });
  if (!s.top_targets?.length) ttBody.insertAdjacentHTML("beforeend", `<tr><td colspan="3" style="color:var(--muted)">No targets yet</td></tr>`);

  // Recent events
  const evList = document.getElementById("recentEvents");
  evList.innerHTML = "";
  (s.recent_events || []).forEach(ev => {
    const dt = ev.ts ? new Date(ev.ts * 1000).toLocaleString([], {month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}) : "";
    let detail = {};
    try { detail = JSON.parse(ev.detail_json || "{}"); } catch {}
    const conf = detail.confidence || (ev.success ? "medium" : "low");
    const msg = detail.message || `${ev.clients_before ?? "?"} → ${ev.clients_after ?? "?"} clients`;
    evList.insertAdjacentHTML("beforeend",
      `<div class="recent-event-row">
        <span class="re-conf ${conf}">${conf.toUpperCase()}</span>
        <span class="re-msg">${msg}</span>
        <span style="color:var(--muted);font-size:.65rem">${(ev.target_bssid||"").slice(0,11)}</span>
        <span class="re-ts">${dt}</span>
      </div>`);
  });
  if (!s.recent_events?.length) evList.insertAdjacentHTML("beforeend",
    `<div style="color:var(--muted);font-size:.75rem;padding:.5rem">No deauth events recorded yet.</div>`);
}

// ── Intel panel ────────────────────────────────────────────────────
function renderChannelHeatmap() {
  const el = document.getElementById("channelHeatmap");
  const channels = {};
  state.networks.forEach(n => {
    const ch = parseInt(n.channel, 10);
    if (!ch) return;
    if (!channels[ch]) channels[ch] = { count: 0, maxPow: -100 };
    channels[ch].count++;
    const p = parseInt(n.power || "-100", 10);
    if (p > channels[ch].maxPow) channels[ch].maxPow = p;
  });

  const ch24 = Array.from({length: 14}, (_, i) => i + 1);
  const ch5  = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165];
  const maxCount = Math.max(1, ...Object.values(channels).map(c => c.count));

  function renderGroup(label, chs) {
    const cells = chs.map(ch => {
      const info = channels[ch];
      const h = info ? Math.max(6, Math.round((info.count / maxCount) * 40)) : 0;
      const color = info ? (info.count >= 3 ? "var(--bad)" : info.count >= 2 ? "var(--warn)" : "var(--accent)") : "var(--surface3)";
      const tooltip = info ? `${info.count} AP${info.count > 1 ? "s" : ""}, ${info.maxPow}dBm` : "empty";
      return `<div class="ch-cell" title="${tooltip}">
        <div class="ch-cell-bar" style="height:${h}px;background:${color}"></div>
        <div class="ch-cell-num">${ch}</div>
        <div class="ch-tooltip">${tooltip}</div>
      </div>`;
    }).join("");
    return `<div><div class="ch-group-label">${label}</div><div class="ch-grid">${cells}</div></div>`;
  }

  el.innerHTML = renderGroup("2.4 GHz", ch24) + renderGroup("5 GHz", ch5);
}

async function loadProbeCloud() {
  try {
    const data = await api("/api/intel/probes");
    const cloud = document.getElementById("probeCloud");
    const ssids = data.top_ssids || [];
    if (!ssids.length) { cloud.innerHTML = `<span style="color:var(--muted);font-size:.8rem">No probe data yet</span>`; return; }
    const max = Math.max(1, ...ssids.map(s => s.count));
    cloud.innerHTML = ssids.map(s => {
      const size = 0.7 + (s.count / max) * 0.9;
      return `<span class="probe-tag" style="font-size:${size.toFixed(2)}rem" title="${s.count} probes, ${s.unique_clients} client(s)">${esc(s.ssid)}</span>`;
    }).join("");
  } catch (err) {
    log(`Probes load error: ${err.message}`, "fail");
  }
}

async function loadSessions() {
  try {
    const data = await api("/api/history/sessions");
    const list = document.getElementById("sessionList");
    const sessions = data.sessions || [];
    if (!sessions.length) { list.innerHTML = `<div style="color:var(--muted);font-size:.8rem">No scan history yet</div>`; return; }
    list.innerHTML = sessions.map(s => `
      <div class="session-row">
        <div class="session-row-left">
          <div>${s.band || "?"} band · ${s.iface || "?"}</div>
          <div class="session-row-time">${new Date(s.started_at * 1000).toLocaleString()}</div>
        </div>
        <div style="color:var(--muted);font-size:.8rem">${s.ap_count || 0} APs</div>
      </div>`).join("");
  } catch (err) {
    log(`Sessions load error: ${err.message}`, "fail");
  }
}

async function loadRogues() {
  try {
    const data = await api("/api/intel/rogues");
    state.rogues = data.rogues || [];
    renderRogues();
  } catch (_) {}
}

function renderRogues() {
  const section = document.getElementById("rogueSection");
  const list = document.getElementById("rogueList");
  const badge = document.getElementById("rogueBadge");
  const intelTab = document.querySelector('[data-tab="intel"]');

  if (!state.rogues.length) {
    section.style.display = "none";
    badge.style.display = "none";
    if (intelTab) intelTab.classList.remove("has-alert");
    return;
  }

  section.style.display = "";
  badge.style.display = "";
  badge.textContent = `⚠ ${state.rogues.length} rogue${state.rogues.length > 1 ? "s" : ""}`;
  if (intelTab) intelTab.classList.add("has-alert");

  list.innerHTML = state.rogues.map(r => `
    <div class="rogue-alert" data-id="${r.id}">
      <div>
        <div class="rogue-ssid">${esc(r.ssid)} <span class="rogue-sev-${r.severity}">[${r.severity}]</span></div>
        <div class="rogue-detail">Suspect: ${esc(r.suspect_bssid)} · Trusted: ${esc(r.trusted_bssid)}</div>
        <div class="rogue-detail">${(JSON.parse(r.reasons || "[]")).join(" | ")}</div>
      </div>
      <button class="btn btn-sm" data-dismiss="${r.id}">Dismiss</button>
    </div>`).join("");

  list.querySelectorAll("[data-dismiss]").forEach(btn => {
    btn.onclick = async () => {
      await api(`/api/intel/rogues/${btn.dataset.dismiss}/dismiss`, { method: "POST", body: "{}" });
      state.rogues = state.rogues.filter(r => r.id != btn.dataset.dismiss);
      renderRogues();
    };
  });
}

function exportData(what) {
  const url = authedHref(`/api/export/csv?what=${what}`);
  const a = document.createElement("a");
  a.href = url;
  a.download = `camjam_${what}_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function exportJson() {
  const url = authedHref("/api/export/json");
  const a = document.createElement("a");
  a.href = url;
  a.download = `camjam_export_${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

// ── WebSocket ──────────────────────────────────────────────────────
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  state.ws = new WebSocket(`${proto}://${location.host}/ws?token=${state.token}`);

  state.ws.onopen = () => {
    const badge = document.getElementById("connBadge");
    badge.className = "badge on"; badge.textContent = "live";
  };
  state.ws.onclose = () => {
    const badge = document.getElementById("connBadge");
    badge.className = "badge off"; badge.textContent = "offline";
    setTimeout(connectWs, 2000);
  };
  state.ws.onmessage = ev => {
    try { handleEvent(JSON.parse(ev.data)); } catch (_) {}
  };
}

function handleEvent(msg) {
  const e = msg.event;

  if (e === "radio:warning" && msg.capabilities) {
    showIfaceCapabilities(msg.capabilities);
  }
  if (e === "scan:start") {
    setScanBusy(true, msg.duration || 20);
    log(`Scan started (${msg.band || "?"})…`, "info");
  }
  if (e === "scan:progress") {
    updateScanProgress(msg.elapsed, msg.total);
  }
  if (e === "scan:done") {
    setScanBusy(false);
    state.networks = msg.networks || state.networks;
    log(`Scan done — ${msg.count} network(s)`, msg.count ? "ok" : "warn");
    renderSidebar();
    renderChannelHeatmap();
  }
  if (e === "scan:rogues") {
    if (msg.count > 0) {
      log(`⚠ ${msg.count} rogue AP alert(s) detected`, "warn");
      loadRogues();
    }
  }
  if (e === "clients:done") {
    log(`Clients: ${msg.count} on ${msg.bssid}`, msg.count ? "ok" : "warn");
    if (state.drawerBssid === msg.bssid) renderDrawerClients(msg.clients || []);
  }
  if (e === "deauth:result") {
    const kind = msg.success ? "ok" : "fail";
    log(`${msg.bssid}: ${msg.clients_before}→${msg.clients_after} [${msg.confidence}] ${msg.message}`, kind);
  }
  if (e === "deauth:stopped") {
    document.getElementById("deauthPill").style.display = "none";
    log("Deauth stopped", "info");
  }
  if (e === "deauth:start") {
    document.getElementById("deauthPill").style.display = "";
  }
  if (e && e.startsWith("deauth:") && !["deauth:result","deauth:stopped","deauth:start"].includes(e)) {
    log(`${e} ${msg.bssid || ""}`.trim(), "warn");
  }
  if (e === "presence:change") {
    const label = msg.label || msg.mac;
    const isHome = msg.status === "home";
    log(`${label} is now ${isHome ? "HOME 🟢" : "AWAY ⚫"}`, isHome ? "ok" : "warn");
    // Update presence tile if panel is open
    loadPresence();
    // Browser notification
    if (Notification.permission === "granted") {
      new Notification("CamJam", {
        body: `${label} is ${isHome ? "home" : "away"}`,
        tag: `presence-${msg.mac}`,
      });
    }
    // Update sidebar presence dot
    updatePresenceDots();
  }
  if (e === "presence:watching") {
    state.watchActive = msg.active;
    document.getElementById("watchPill").style.display = msg.active ? "" : "none";
    document.getElementById("btnStartWatch").style.display = msg.active ? "none" : "";
    document.getElementById("btnStopWatch").style.display = msg.active ? "" : "none";
  }
}

function updatePresenceDots() {
  // Placeholder — presence dots in sidebar AP rows would need client→AP mapping
  // Presence state is shown on the Presence tab instead
}

// ── Mobile sidebar toggle ─────────────────────────────────────────
function toggleSidebar() {
  document.getElementById("sidebar").classList.toggle("open");
}

// ── Init ──────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(btn => {
  btn.onclick = () => tab(btn.dataset.tab);
});

document.getElementById("globalSearch").oninput = renderSidebar;

document.getElementById("btnHamburger").onclick = toggleSidebar;
document.getElementById("btnSidebarClose").onclick = toggleSidebar;

document.getElementById("btnRefreshIface").onclick = () => refreshInterfaces().catch(e => log(e.message, "fail"));
document.getElementById("btnIface").onclick = () => enableIface().catch(e => log(e.message, "fail"));
document.getElementById("btnScan").onclick = () => scanNetworks();
document.getElementById("btnCancelScan").onclick = () => cancelScan();

document.querySelectorAll(".band-chip").forEach(chip => {
  chip.onclick = () => {
    document.querySelectorAll(".band-chip").forEach(c => c.classList.remove("active"));
    chip.classList.add("active");
  };
});

document.getElementById("btnDeauth").onclick = () => startDeauth().catch(e => log(e.message, "fail"));
document.getElementById("btnStop").onclick = () => stopDeauth().catch(e => log(e.message, "fail"));

document.getElementById("btnRefreshDevices").onclick = loadDevices;
document.getElementById("deviceFilter").oninput = renderDevices;
document.getElementById("deviceTypeFilter").onchange = renderDevices;
document.getElementById("watchedOnly").onchange = renderDevices;

document.getElementById("btnStartWatch").onclick = () => startPresenceWatch().catch(e => log(e.message, "fail"));
document.getElementById("btnStopWatch").onclick = () => stopPresenceWatch().catch(e => log(e.message, "fail"));

document.getElementById("btnRefreshProbes").onclick = loadProbeCloud;
document.getElementById("btnRefreshSessions").onclick = loadSessions;
document.getElementById("btnRefreshStats").onclick = loadStats;
document.getElementById("btnClearLive").onclick = () => { document.getElementById("liveFeed").innerHTML = ""; };

document.getElementById("exportAps").onclick = () => exportData("aps");
document.getElementById("exportClients").onclick = () => exportData("clients");
document.getElementById("exportEvents").onclick = () => exportData("events");
document.getElementById("exportJson").onclick = exportJson;

document.getElementById("btnCloseDrawer").onclick = closeDrawer;
document.getElementById("drawerOverlay").onclick = closeDrawer;

document.getElementById("rogueBadge").onclick = () => { tab("intel"); loadRogues(); };

// Request notification permission early (non-blocking)
if ("Notification" in window && Notification.permission === "default") {
  Notification.requestPermission().catch(() => {});
}

async function restoreState() {
  try {
    const apsRes = await api("/api/aps");
    state.networks = apsRes.networks || [];
  } catch {}
  try {
    const targetsRes = await api("/api/targets");
    (targetsRes.targets || []).forEach(bssid => {
      const net = state.networks.find(n => n.bssid === bssid);
      state.selected.set(bssid, {
        bssid,
        ssid: net ? net.ssid : "",
        channel: net ? (parseInt(net.channel, 10) || 1) : 1,
        mode: "all_clients",
        client_macs: [],
      });
    });
  } catch {}
  renderSidebar();
  renderTargetChips();
  loadDevices().catch(() => {});
  loadRogues().catch(() => {});
  loadPresence().catch(() => {});
}

(async () => {
  await loadConfig();
  if (!state.token) {
    alert("Missing session token. Restart camjam and open the printed URL.");
    return;
  }
  connectWs();
  await refreshInterfaces().catch(e => log(e.message, "fail"));
  await restoreState();
})();
