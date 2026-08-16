"use strict";

const state = { token: sessionStorage.getItem("sentinelgate-token") || "", mode: "dry-run" };
const $ = (selector) => document.querySelector(selector);

function escapeHtml(value) {
  return String(value ?? "—").replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[character]);
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(`/api${path}`, { ...options, headers });
  if (response.status === 401) {
    throw new Error("Authentication required. Select Access token and enter the configured token.");
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = (await response.json()).detail || message; } catch (_) { /* no JSON body */ }
    throw new Error(message);
  }
  return response.status === 204 ? null : response.json();
}

function toast(message, isError = false) {
  const element = $("#toast");
  element.textContent = message;
  element.className = `toast show${isError ? " error" : ""}`;
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => { element.className = "toast"; }, 4200);
}

function timeLabel(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString([], {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}

function renderStatus(status, stats) {
  state.mode = status.mode;
  $("#system-state").textContent = "Control plane online";
  $("#state-dot").className = "online";
  $("#mode-short").textContent = status.mode === "dry-run" ? "SAFE" : "LIVE";
  $("#mode-name").textContent = status.mode === "dry-run" ? "Dry-run simulation" : "Active enforcement";
  $("#mode-copy").textContent = status.mode === "dry-run"
    ? "Rules are rendered but the host is unchanged"
    : "Validated rules are enforced by nftables";
  $("#seed-button").hidden = status.mode !== "dry-run";
  $("#metric-blocked").textContent = stats.blocked_events.toLocaleString();
  $("#metric-rules").textContent = status.rules_enabled.toLocaleString();
  $("#metric-high").textContent = stats.high_severity_events.toLocaleString();
  $("#metric-bans").textContent = status.active_bans.toLocaleString();
  $("#snapshot-id").textContent = status.active_snapshot ? `#${status.active_snapshot}` : "None";
  $("#policy-list").innerHTML = Object.entries(status.policies).map(([chain, verdict]) => `
    <div class="policy-row"><span>${escapeHtml(chain)} chain</span><b class="verdict ${escapeHtml(verdict)}">${escapeHtml(verdict)}</b></div>
  `).join("");
}

function renderSources(sources) {
  const container = $("#source-bars");
  if (!sources.length) {
    container.innerHTML = '<p class="empty">No source telemetry recorded.</p>';
    return;
  }
  const max = Math.max(...sources.map((item) => item.count));
  container.innerHTML = sources.map((item) => `
    <div class="source-item">
      <span>${escapeHtml(item.source_ip)}</span>
      <progress class="source-progress" max="${escapeHtml(max)}" value="${escapeHtml(item.count)}">${escapeHtml(item.count)}</progress>
      <b>${escapeHtml(item.count)}</b>
    </div>
  `).join("");
}

function renderEvents(events) {
  const body = $("#events-body");
  if (!events.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No firewall decisions recorded.</td></tr>';
    return;
  }
  body.innerHTML = events.slice(0, 12).map((event) => {
    const destination = event.destination_ip
      ? `${escapeHtml(event.destination_ip)}${event.destination_port ? `:${escapeHtml(event.destination_port)}` : ""}`
      : "—";
    return `<tr>
      <td>${escapeHtml(timeLabel(event.occurred_at))}</td>
      <td><span class="severity ${escapeHtml(event.severity)}">${escapeHtml(event.severity)}</span></td>
      <td>${escapeHtml(event.source_ip)}</td>
      <td>${destination}</td>
      <td>${escapeHtml((event.protocol || "—").toUpperCase())}</td>
      <td><span class="decision">${escapeHtml(event.action)}</span></td>
    </tr>`;
  }).join("");
}

function renderRules(rules) {
  const container = $("#rules-list");
  $("#rule-count").textContent = `${rules.length} RULE${rules.length === 1 ? "" : "S"}`;
  if (!rules.length) {
    container.innerHTML = '<p class="empty">No custom rules yet.</p>';
    return;
  }
  container.innerHTML = rules.map((rule) => {
    const source = rule.source || "any source";
    const target = rule.destination_port ? `port ${rule.destination_port}` : (rule.destination || "any destination");
    return `<div class="rule-item${rule.enabled ? "" : " disabled"}">
      <div><h3>${escapeHtml(rule.name)}</h3><p>${escapeHtml(rule.direction)} · ${escapeHtml(rule.protocol)} · ${escapeHtml(source)} → ${escapeHtml(target)} · P${escapeHtml(rule.priority)}</p></div>
      <span class="rule-action ${escapeHtml(rule.action)}">${escapeHtml(rule.action)}</span>
      <button class="delete-rule" type="button" data-rule-id="${escapeHtml(rule.id)}" aria-label="Delete ${escapeHtml(rule.name)}">×</button>
    </div>`;
  }).join("");
}

async function loadAll() {
  try {
    const [status, stats, rules, events] = await Promise.all([
      api("/status"), api("/stats"), api("/rules"), api("/events?limit=40")
    ]);
    renderStatus(status, stats);
    renderSources(stats.top_sources || []);
    renderEvents(events);
    renderRules(rules);
    $("#last-updated").textContent = `Last sync ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    $("#system-state").textContent = "Control plane unavailable";
    $("#state-dot").className = "offline";
    toast(error.message, true);
  }
}

$("#refresh-button").addEventListener("click", loadAll);

$("#token-button").addEventListener("click", () => {
  const token = window.prompt("Enter the SentinelGate bearer token. Leave empty to clear it.", "");
  if (token === null) return;
  state.token = token.trim();
  if (state.token) sessionStorage.setItem("sentinelgate-token", state.token);
  else sessionStorage.removeItem("sentinelgate-token");
  loadAll();
});

$("#seed-button").addEventListener("click", async () => {
  try {
    const result = await api("/demo/seed", { method: "POST", body: "{}" });
    toast(`Demo ready: ${result.rules_added} rules and ${result.events_added} events added.`);
    loadAll();
  } catch (error) { toast(error.message, true); }
});

$("#apply-button").addEventListener("click", async () => {
  let confirmation = "";
  if (state.mode === "apply") {
    confirmation = window.prompt("This changes the host firewall. Type APPLY to continue.", "") || "";
    if (confirmation !== "APPLY") return;
  }
  try {
    const result = await api("/apply", {
      method: "POST",
      body: JSON.stringify({ confirmation, reason: "Dashboard deployment" })
    });
    toast(result.message);
    loadAll();
  } catch (error) { toast(error.message, true); }
});

$("#rule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    name: form.get("name"), direction: form.get("direction"), action: form.get("action"),
    protocol: form.get("protocol"), source: form.get("source") || null,
    destination_port: form.get("destination_port") || null,
    priority: Number(form.get("priority")), log: form.get("log") === "on"
  };
  try {
    await api("/rules", { method: "POST", body: JSON.stringify(payload) });
    event.currentTarget.reset();
    event.currentTarget.elements.priority.value = 500;
    event.currentTarget.elements.log.checked = true;
    toast("Policy rule added. Deploy the ruleset when ready.");
    loadAll();
  } catch (error) { toast(error.message, true); }
});

$("#rules-list").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-rule-id]");
  if (!button || !window.confirm("Delete this policy rule?")) return;
  try {
    await api(`/rules/${encodeURIComponent(button.dataset.ruleId)}`, { method: "DELETE" });
    toast("Policy rule deleted.");
    loadAll();
  } catch (error) { toast(error.message, true); }
});

loadAll();
window.setInterval(loadAll, 15000);
