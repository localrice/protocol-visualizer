const state = { events: [], current: -1, timer: null };
const streamState = { poll: null, pollStop: null, lastEvent: 0, hls: null };
const $ = (selector) => document.querySelector(selector);

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const dark = theme === "dark";
  const label = dark ? "Switch to light mode" : "Switch to dark mode";
  $("#theme-toggle").setAttribute("aria-label", label);
  $("#theme-toggle").setAttribute("title", label);
}

applyTheme(localStorage.getItem("protocol-dashboard-theme") || "dark");
$("#theme-toggle").addEventListener("click", () => {
  const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("protocol-dashboard-theme", nextTheme);
  applyTheme(nextTheme);
});

function setStatus(message, active = false) {
  $("#status").textContent = message;
  $(".status-dot").classList.toggle("is-active", active);
}
function showError(message = "") { const box = $("#error"); box.textContent = message; box.hidden = !message; }
function messageLabel(item) {
  const labels = {
    query: "DNS Query",
    response: "Response",
    request: "Request",
    command: "Command",
    data: "Message Data",
    connect: "Connection",
    handshake: "TLS Handshake",
    note: "Encrypted Data",
    syn: "SYN",
    "syn-ack": "SYN-ACK",
    ack: "ACK",
    psh: "PSH, ACK",
    "fin-ack": "FIN, ACK",
    datagram: "UDP",
  };
  return labels[item.type] || item.type.toUpperCase();
}

function displayMessage(item) {
  if (item.protocol === "TCP") {
    return item.direction === "client-to-server" ? "Client → Server" : "Server → Client";
  }
  if (item.protocol === "UDP") {
    return item.message || (item.direction === "client-to-server" ? "Client → Server" : "Server → Client");
  }
  if (item.protocol === "DNS" && item.type === "query") return `A ${item.fields?.Name || "hostname"}`;
  if (item.protocol === "DNS" && item.type === "response") return "NOERROR";
  return item.message;
}

function visibleFields(item) {
  const allowed = {
    DNS: item.type === "query" ? ["Name", "Type"] : ["Answer", "Resolver", "Status"],
    HTTP: item.type === "request" ? ["Host"] : ["Content-Type", "Size", "Location"],
    HTTPS: item.type === "request" ? ["Host"] : ["Content-Type", "Size", "Location"],
    SMTP: item.type === "response" ? ["Capabilities"] : [],
    MANIFEST: ["Representation", "Resource"],
    SEGMENT: ["Representation", "Resource"],
    TCP: ["Seq", "Ack", "Src", "Dst", "Window", "Length"],
    UDP: ["Src", "Dst", "Length"],
    TLS: [],
    HLS: item.type === "response" ? ["Content-Type", "Size"] : ["Resource"],
  };

  const alias = {
    "Sequence Number": "Seq",
    "Acknowledgment Number": "Ack",
    "Source Port": "Src",
    "Destination Port": "Dst",
    "Window Size": "Window",
    "Payload Length": "Length",
    "Content-Length": "Size",
  };

  const keys = allowed[item.protocol] || [];
  const raw = Object.entries(item.fields || {}).map(([k, v]) => [alias[k] || k, v]);

  return raw.filter(([k]) => keys.includes(k)).map(([key, value]) => {
    if (key === "Answer") return [key, String(value).split(",")[0]];
    if (key === "Length" && typeof value === "string") return [key, value.replace(" bytes", "")];
    return [key, String(value)];
  });
}

function visibleFieldRows(item) {
  const fields = visibleFields(item);
  if (!fields.length) return [];

  if (item.protocol === "TCP") {
    const map = new Map(fields);
    const rows = [];
    const r1 = [];
    if (map.has("Seq")) r1.push(["Seq", map.get("Seq")]);
    if (map.has("Ack")) r1.push(["Ack", map.get("Ack")]);
    if (r1.length) rows.push(r1);

    const r2 = [];
    if (map.has("Src")) r2.push(["Src", map.get("Src")]);
    if (map.has("Dst")) r2.push(["Dst", map.get("Dst")]);
    if (r2.length) rows.push(r2);

    const r3 = [];
    if (map.has("Window")) r3.push(["Window", map.get("Window")]);
    if (map.has("Length")) r3.push(["Length", map.get("Length")]);
    if (r3.length) rows.push(r3);

    const handled = new Set(["Seq", "Ack", "Src", "Dst", "Window", "Length"]);
    const remaining = fields.filter(([k]) => !handled.has(k));
    if (remaining.length) rows.push(remaining);
    return rows;
  }

  if (item.protocol === "UDP") {
    const map = new Map(fields);
    const rows = [];
    const r1 = [];
    if (map.has("Src")) r1.push(["Src", map.get("Src")]);
    if (map.has("Dst")) r1.push(["Dst", map.get("Dst")]);
    if (r1.length) rows.push(r1);

    const r2 = [];
    if (map.has("Length")) r2.push(["Length", map.get("Length")]);
    if (r2.length) rows.push(r2);

    const handled = new Set(["Src", "Dst", "Length"]);
    const remaining = fields.filter(([k]) => !handled.has(k));
    if (remaining.length) rows.push(remaining);
    return rows;
  }

  if (fields.length > 1) {
    const map = new Map(fields);
    if (map.has("Content-Type") && map.has("Size")) {
      const rows = [[["Content-Type", map.get("Content-Type")], ["Size", map.get("Size")]]];
      const rest = fields.filter(([k]) => k !== "Content-Type" && k !== "Size");
      if (rest.length) rows.push(rest);
      return rows;
    }
  }

  return fields.map((f) => [f]);
}

function smtpInteractionGroups(items) {
  const groups = [];
  let current = null;
  items.forEach(({ item, index }) => {
    if (item.direction === "server-to-client" && !groups.length && !current) {
      groups.push({ key: "SMTP / SERVER GREETING", layer: "application", protocol: "SMTP", items: [{ item, index }] });
      return;
    }
    if (item.direction === "client-to-server" && !(item.type === "data" && current?.key === "SMTP / DATA")) {
      const command = item.type === "data" ? "MESSAGE DATA" : item.message.split(" ", 1)[0].toUpperCase();
      const title = command === "EHLO" && groups.some((group) => group.key === "SMTP / EHLO") ? "EHLO (AFTER TLS)" : command;
      current = { key: `SMTP / ${title}`, layer: "application", protocol: "SMTP", items: [] };
      groups.push(current);
    }
    if (current) current.items.push({ item, index });
  });
  return groups;
}

function groupKeyFor(item) {
  if (item.protocol === "TCP") {
    if (item.type === "syn" || item.type === "syn-ack" || (item.type === "ack" && item.fields?.State === "ESTABLISHED")) {
      return "TCP / THREE-WAY HANDSHAKE";
    }
    if (item.type === "fin-ack" || (item.type === "ack" && (item.fields?.State?.includes("CLOSE") || item.fields?.State?.includes("CLOSED")))) {
      return "TCP / CONNECTION TEARDOWN";
    }
    return "TCP / DATA TRANSFER";
  }
  if (item.protocol === "UDP") {
    return "UDP / DATAGRAM TRANSPORT";
  }
  if (item.protocol === "DNS") {
    return "DNS / RESOLUTION";
  }
  if (item.protocol === "TLS") {
    return "TLS / SECURITY HANDSHAKE";
  }
  return item.protocol;
}

function renderExchange() {
  const view = $("#exchange-view"); view.replaceChildren();
  if (!state.events.length) { view.innerHTML = '<p class="empty-state">Run an activity to populate the exchange.</p>'; return; }
  const groups = [];
  state.events.forEach((item, index) => {
    const key = groupKeyFor(item);
    const layer = item.layer || (item.protocol === "TCP" || item.protocol === "UDP" ? "transport" : "application");
    let group = groups[groups.length - 1];
    if (!group || group.key !== key) {
      group = { key, layer, protocol: item.protocol, items: [] };
      groups.push(group);
    }
    group.items.push({ item, index });
  });

  const partitionedGroups = groups.flatMap((group) => {
    if (group.protocol === "SMTP") return smtpInteractionGroups(group.items);
    return [group];
  });

  partitionedGroups.forEach((group) => {
    const section = document.createElement("section");
    section.className = `exchange-group${group.key.startsWith("SMTP /") || group.key.startsWith("TCP /") || group.key.startsWith("UDP /") ? " smtp-interaction" : ""}`;
    const resolver = group.protocol === "DNS" ? group.items[0]?.item.fields?.Resolver : "";
    const context = resolver ? `<p class="exchange-context">Client → ${escapeHtml(resolver)}</p>` : "";
    const layerTag = group.layer === "transport" ? "Transport Layer (L4)" : "Application Layer (L7)";
    section.innerHTML = `<span class="eyebrow">${escapeHtml(layerTag)}</span><h3 class="exchange-group-title">${escapeHtml(group.key)}</h3>${context}`;
    const list = document.createElement("div");
    list.className = "exchange-events";
    group.items.forEach(({ item, index }) => {
      const message = document.createElement("article");
      message.className = `exchange-message ${index === state.current ? "is-current" : index < state.current ? "is-complete" : ""}`;
      const fieldRows = visibleFieldRows(item);
      const fieldsHtml = fieldRows.map((row) =>
        `<div class="field-row">${row.map(([key, value]) => `<span class="field"><b>${escapeHtml(key)}:</b> ${escapeHtml(String(value))}</span>`).join("")}</div>`
      ).join("");
      message.innerHTML = `<div class="message-side"><span class="message-kind">${escapeHtml(messageLabel(item))}</span><strong>${escapeHtml(displayMessage(item))}</strong>${fieldsHtml ? `<div class="message-fields">${fieldsHtml}</div>` : ""}</div>`;
      list.append(message);
    });
    section.append(list);
    view.append(section);
  });
  const current = view.querySelector(".is-current"); if (current) current.scrollIntoView({ block: "nearest", behavior: "smooth" });
}
function showEvent(index) { if (!state.events.length) return; state.current = Math.max(0, Math.min(index, state.events.length - 1)); renderExchange(); scheduleNext(); }
function escapeHtml(value) { const div = document.createElement("div"); div.textContent = value; return div.innerHTML; }
function scheduleNext() { clearTimeout(state.timer); if (state.current >= state.events.length - 1) return; state.timer = setTimeout(() => showEvent(state.current + 1), state.events[state.current]?.delay || 800); }
function loadEvents(data) { clearTimeout(state.timer); state.events = data.events || []; state.current = -1; showEvent(0); }
async function postJson(url, payload) { const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); const data = await response.json(); if (!response.ok || !data.success) throw new Error(data.error || "Request failed"); return data; }
function appendStreamEvents(events) { if (!events.length) return; const previousLength = state.events.length; state.events.push(...events); streamState.lastEvent = events[events.length - 1].sequence; if (state.current < 0) showEvent(0); else if (state.current === previousLength - 1) showEvent(previousLength); else renderExchange(); }
async function pollStreamEvents() { try { const response = await fetch(`/api/stream/events?since=${streamState.lastEvent}`); const data = await response.json(); appendStreamEvents(data.events || []); } catch (_error) { /* Playback can continue if event polling briefly fails. */ } }
function stopStreamPolling() { clearInterval(streamState.poll); clearTimeout(streamState.pollStop); streamState.poll = null; streamState.pollStop = null; }
function beginStreamPolling() { stopStreamPolling(); streamState.poll = setInterval(pollStreamEvents, 400); streamState.pollStop = setTimeout(stopStreamPolling, 20000); pollStreamEvents(); }
function playHls(url) {
  const video = $("#stream-player"); video.hidden = false;
  if (streamState.hls) streamState.hls.destroy();
  if (window.Hls && window.Hls.isSupported()) {
    streamState.hls = new window.Hls();
    streamState.hls.loadSource(url);
    streamState.hls.attachMedia(video);
    streamState.hls.on(window.Hls.Events.MANIFEST_PARSED, () => video.play().catch(() => {}));
  } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
    video.src = url;
    video.play().catch(() => {});
  } else {
    throw new Error("This browser does not support HLS playback");
  }
}

$(".activity-tabs").addEventListener("click", (event) => { const tab = event.target.closest(".tab"); if (!tab) return; document.querySelectorAll(".tab").forEach((button) => { const active = button === tab; button.classList.toggle("is-active", active); button.setAttribute("aria-selected", active); }); document.querySelectorAll(".activity-view").forEach((view) => view.classList.toggle("is-hidden", view.dataset.view !== tab.dataset.activity)); showError(); setStatus("Ready for an activity."); });

$("#browse-form").addEventListener("submit", async (event) => { event.preventDefault(); showError(); setStatus("Resolving hostname and requesting URL...", true); try { const data = await postJson("/api/browse", { url: $("#url").value }); loadEvents(data); setStatus("Browse exchange complete."); } catch (error) { setStatus("Browse failed."); showError(error.message); } });
$("#mail-form").addEventListener("submit", async (event) => { event.preventDefault(); showError(); setStatus("Simulating SMTP exchange...", true); try { const data = await postJson("/api/mail", { to: $("#to").value, subject: $("#subject").value, body: $("#body").value }); loadEvents(data); setStatus("SMTP exchange complete."); } catch (error) { setStatus("Simulation failed."); showError(error.message); } });
$("#stream-play").addEventListener("click", async () => { showError(); setStatus("Preparing HLS stream...", true); try { const data = await postJson("/api/stream", { quality: "auto" }); clearTimeout(state.timer); state.events = []; state.current = -1; streamState.lastEvent = 0; playHls(data.stream_url); beginStreamPolling(); setStatus("Streaming from the Flask server."); } catch (error) { setStatus("Streaming failed."); showError(error.message); } });
$("#stream-pause").addEventListener("click", () => { $("#stream-player").pause(); stopStreamPolling(); setStatus("Streaming paused."); });
$("#stream-player").addEventListener("ended", () => { stopStreamPolling(); setStatus("Streaming complete."); });
