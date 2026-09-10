const defaultApiBase = window.location.port === "8787" ? `${window.location.origin}/api/v1` : "http://127.0.0.1:8787/api/v1";
const API_BASE = (window.COCKPIT_BACKEND_URL || localStorage.getItem("cockpitBackendUrl") || defaultApiBase).replace(/\/$/, "");
const state = { wifi: [], devices: [], forwards: [], backups: [], peers: [], vpnInterfaces: [], vpnInterfaceError: null, wanInterfaces: [], wanInterfaceError: null, pppoe: [], firewall: { forward: [], input: [], nat: [] }, services: [], guest: null, firmware: null, status: null, capabilities: null, network: null, dhcpRanges: [], leases: [], session: null, securityCheck: null, onboardingPage: "status" };

const $ = (selector) => document.querySelector(selector);
let proModulePromise = null;

// Pro ist absichtlich kein Teil der Basis-Auslieferung. Erst ein Pro-Backend darf das
// optionale Modul anfordern; ein öffentlicher Basis-Checkout enthält diese Datei nicht.
async function ensureProModule() {
  if (state.capabilities?.tier !== "pro") return null;
  if (window.CockpitPro) return window.CockpitPro;
  if (!proModulePromise) {
    proModulePromise = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "pro.js";
      script.onload = () => window.CockpitPro ? resolve(window.CockpitPro) : reject(new Error("Pro-Modul wurde nicht initialisiert."));
      script.onerror = () => reject(new Error("Pro-Modul ist auf diesem Rechner nicht installiert."));
      document.head.append(script);
    }).catch((error) => {
      proModulePromise = null;
      showToast(error.message);
      return null;
    });
  }
  const pro = await proModulePromise;
  if (pro && !pro.initialized) await pro.init();
  return pro;
}
function applyTierUi() {
  if (state.capabilities?.tier === "pro") return;
  // Basis darf weder eine scheinbar verfügbare Pro-Aktion zeigen noch beim Laden
  // versehentlich eine Pro-Route berühren. Die endgültige öffentliche Ausgabe
  // enthält diese DOM-Blöcke nicht; diese Schutzschicht hält auch einen lokalen
  // Basis-Checkout mit noch altem HTML ehrlich.
  document.querySelectorAll("#guest, #pppoe, #firewall, #services, #vpn").forEach((element) => element.remove());
  $("#firmware-current")?.closest(".maintenance-card")?.remove();
  $("#router-password-form")?.closest(".maintenance-card")?.remove();
  document.querySelectorAll('[data-onboarding-page="guest"], [data-onboarding-page="maintenance"]').forEach((button) => button.remove());
}
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
const toastQueue = [];
let toastVisible = false;
let wifiUndoTimer = null;
function showToast(message) {
  toastQueue.push(String(message || "Etwas ist schiefgelaufen."));
  if (toastVisible) return;
  const next = () => {
    const text = toastQueue.shift();
    if (!text) { toastVisible = false; return; }
    toastVisible = true;
    const toast = $("#toast"); toast.textContent = text; toast.classList.add("show");
    window.setTimeout(() => { toast.classList.remove("show"); window.setTimeout(next, 220); }, 3600);
  };
  next();
}
function clearWifiUndoNotice() {
  if (wifiUndoTimer) window.clearTimeout(wifiUndoTimer);
  wifiUndoTimer = null;
  $("#wifi-undo-notice")?.remove();
}
function showWifiUndoNotice(interfaceName) {
  clearWifiUndoNotice();
  const notice = document.createElement("aside");
  notice.id = "wifi-undo-notice";
  notice.className = "wifi-undo-notice";
  notice.setAttribute("role", "status");
  notice.innerHTML = '<div><strong>WLAN-Passwort geändert</strong><p>Du kannst diese letzte Änderung noch fünf Minuten rückgängig machen.</p></div><button class="secondary-button" type="button" data-action="undo-wifi-password">Rückgängig</button>';
  notice.querySelector("[data-action=undo-wifi-password]").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    button.textContent = "Wird rückgängig gemacht …";
    try {
      await request(`/wifi/${encodeURIComponent(interfaceName)}/password/undo`, { method: "POST" });
      clearWifiUndoNotice();
      showToast("Das vorherige WLAN-Passwort wurde wiederhergestellt.");
    } catch (error) {
      clearWifiUndoNotice();
      showError(error);
    }
  });
  document.body.append(notice);
  wifiUndoTimer = window.setTimeout(clearWifiUndoNotice, 5 * 60 * 1000);
}
function explainActionError(error) {
  const messages = {
    bad_request: "Die Eingabe ist unvollständig oder ungültig. Bitte prüfe die markierten Werte.",
    router_unreachable: "Der Router ist nicht erreichbar. Prüfe Kabel, Adresse und Verbindung.",
    router_timeout: "Der Router antwortet zu langsam. Bitte aktualisiere erst, bevor du die Aktion wiederholst.",
    router_state_unclear: "Der Routerzustand ist nach der Aktion unklar. Bitte aktualisiere, bevor du etwas wiederholst.",
    conflict: "Diese Änderung passt nicht mehr zum aktuellen Routerzustand. Bitte aktualisiere die Seite.",
    already_exists: "Diese Einstellung gibt es bereits. Bitte aktualisiere die Ansicht und prüfe die vorhandenen Einträge.",
    not_found: "Der Eintrag wurde nicht gefunden. Er wurde möglicherweise bereits geändert oder entfernt.",
    not_connected: "Die Verbindung zum Router ist abgelaufen. Bitte erneut verbinden.",
    backup_storage_unsafe: "Der lokale Backup-Ordner ist nicht sicher eingerichtet. Es wurde kein Backup verwendet.",
    undo_unavailable: "Der Rückgängig-Zeitraum ist abgelaufen oder bereits verbraucht.",
    undo_failed: "Das vorherige WLAN-Passwort konnte nicht wiederhergestellt werden.",
  };
  return messages[error?.code] || error?.message || "Die Aktion konnte nicht ausgeführt werden.";
}
function showError(error) { showToast(explainActionError(error)); }
function confirmAction(message, title = "Änderung bestätigen", confirmLabel = "Jetzt ausführen") {
  return new Promise((resolve) => {
    const dialog = document.createElement("dialog");
    dialog.className = "confirm-dialog";
    dialog.innerHTML = '<div class="confirm-dialog-icon" aria-hidden="true">!</div><div><p class="eyebrow">Bitte prüfen</p><h2></h2><p class="confirm-dialog-message"></p></div><div class="confirm-dialog-actions"><button type="button" class="secondary-button" data-confirm-cancel>Abbrechen</button><button type="button" class="primary-button confirm-danger-button" data-confirm-ok></button></div>';
    dialog.querySelector("h2").textContent = title;
    dialog.querySelector(".confirm-dialog-message").textContent = message;
    dialog.querySelector("[data-confirm-ok]").textContent = confirmLabel;
    const finish = (confirmed) => { if (dialog.open) dialog.close(); dialog.remove(); resolve(confirmed); };
    dialog.querySelector("[data-confirm-cancel]").onclick = () => finish(false);
    dialog.querySelector("[data-confirm-ok]").onclick = () => finish(true);
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); finish(false); });
    document.body.append(dialog); dialog.showModal(); dialog.querySelector("[data-confirm-cancel]").focus();
  });
}
function setConnection(connected) { $("#connection-label").innerHTML = connected ? "Backend verbunden<small>Live vom Router</small>" : "Backend nicht erreichbar<small>Verbindung oder Dienst prüfen</small>"; $("#connection-dot").style.background = connected ? "#39bc7c" : "#d88927"; $(".connection-pill").innerHTML = `<span class="live-dot"></span> ${connected ? "Router verbunden" : "Backend prüfen"}`; }
function isDarkTheme() { const explicit = document.documentElement.getAttribute("data-theme"); if (explicit) return explicit === "dark"; return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false; }
function updateThemeLabel() { const label = $("#theme-toggle-label"); if (label) label.textContent = isDarkTheme() ? "Hell" : "Dunkel"; }
function toggleTheme() { const next = isDarkTheme() ? "light" : "dark"; document.documentElement.setAttribute("data-theme", next); try { localStorage.setItem("cockpit-theme", next); } catch (error) { /* localStorage blockiert -- Wahl gilt nur für diese Sitzung */ } updateThemeLabel(); }
function showWelcome() { $("#connect-screen").classList.add("hidden"); $(".app-shell").classList.add("hidden"); $("#welcome-screen").classList.remove("hidden"); $("[data-onboarding-page]")?.focus(); }
function showConnect(message = "") { clearWifiUndoNotice(); window.CockpitPro?.cleanup?.(); loadStates.clear(); state.session = null; localStorage.removeItem("cockpitSession"); $("#welcome-screen").classList.add("hidden"); $(".app-shell").classList.add("hidden"); $("#connect-screen").classList.remove("hidden"); $("#connect-error").textContent = message; $("#connect-password").value = ""; $("#connect-host").focus(); }
function showDashboard() { $("#welcome-screen").classList.add("hidden"); $("#connect-screen").classList.add("hidden"); $(".app-shell").classList.remove("hidden"); }
function applyOnboardingPage() { showPage(state.onboardingPage || "status"); if (state.onboardingPage === "guest") window.setTimeout(() => $("#guest")?.scrollIntoView({ behavior: "smooth", block: "start" }), 80); }
function explainConnectError(error) { if (error.code === "auth_failed") return "Benutzername oder Passwort falsch."; if (error.code === "router_unreachable") return "Gerät unter dieser Adresse nicht erreichbar."; if (error.code === "router_timeout") return "Das Gerät antwortet nicht rechtzeitig."; return explainActionError(error); }

async function connectToRouter(event) {
  event.preventDefault();
  const submit = $("#connect-submit");
  const payload = {
    host: $("#connect-host").value.trim(),
    user: $("#connect-user").value.trim(),
    password: $("#connect-password").value,
    ssh_port: Number($("#connect-port").value || 22),
  };
  $("#connect-error").textContent = "";
  submit.disabled = true;
  submit.textContent = "Verbinde …";
  try {
    await attemptConnect(payload);
  } catch (error) {
    $("#connect-error").textContent = explainConnectError(error);
  } finally {
    submit.disabled = false;
    submit.textContent = "Verbinden";
  }
}

async function attemptConnect(payload) {
  // Audit A18: Erstkontakt zu einem Router zeigt jetzt den SSH-Fingerprint zur Bestätigung,
  // statt ihn wie bisher (StrictHostKeyChecking=accept-new) still zu übernehmen. Nur bei
  // "host_key_unknown" wird automatisch mit derselben Anfrage plus Bestätigung wiederholt --
  // bei "host_key_changed" gibt es bewusst keinen Klick-weg, das bleibt eine harte Ablehnung.
  try {
    const data = await request("/connect", { method: "POST", body: jsonBody(payload) }, false);
    return finishConnect(data, payload.host);
  } catch (error) {
    if (error.code !== "host_key_unknown") throw error;
    const confirmed = await confirmAction(
      `Dieser Router wurde noch nie bestätigt.\n\nSSH-Fingerprint (${error.keyType}):\n${error.fingerprint}\n\n` +
      "Nur fortfahren, wenn dieser Fingerprint mit dem am Router selbst angezeigten übereinstimmt " +
      "(z. B. in WinBox oder WebFig). Jetzt vertrauen und verbinden?",
      "Router-Fingerprint prüfen", "Vertrauen & verbinden"
    );
    if (!confirmed) throw error;
    const data = await request(
      "/connect",
      { method: "POST", body: jsonBody({ ...payload, confirm_fingerprint: error.fingerprint }) },
      false,
    );
    return finishConnect(data, payload.host);
  }
}

function finishConnect(data, host) {
  state.session = data.session;
  localStorage.setItem("cockpitSession", data.session);
  localStorage.setItem("cockpitLastHost", host);
  // Das Backend benötigt das Passwort nur innerhalb der Sitzung. Im Browserfeld
  // darf es nach erfolgreicher Anmeldung nicht unnötig sichtbar/auslesbar bleiben.
  $("#connect-password").value = "";
  showDashboard();
  return loadAll().finally(applyOnboardingPage);
}

async function init() {
  updateThemeLabel();
  $("#connect-host").value = localStorage.getItem("cockpitLastHost") || "";
  if (!localStorage.getItem("cockpitOnboardingSeen")) return showWelcome();
  return resumeSession();
}
async function resumeSession() {
  const savedSession = localStorage.getItem("cockpitSession");
  if (!savedSession) return showConnect();
  state.session = savedSession;
  try {
    const data = await request("/session");
    state.status = { router_identity: data.router_identity, routeros_version: data.routeros_version };
    showDashboard();
    await loadAll();
    applyOnboardingPage();
  } catch (error) {
    showConnect("Die vorige Verbindung ist nicht mehr aktiv. Bitte erneut verbinden.");
  }
}
async function finishOnboarding(pageName) {
  state.onboardingPage = pageName;
  localStorage.setItem("cockpitOnboardingSeen", "1");
  await resumeSession();
}

async function request(path, options = {}, withSession = true) {
  const session = state.session;
  const headers = { ...(withSession && state.session ? { "X-Cockpit-Session": state.session } : {}), ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) };
  let response;
  try { response = await fetch(`${API_BASE}${path}`, { signal: AbortSignal.timeout(60000), ...options, headers }); } catch (error) { throw new Error(error.name === "TimeoutError" ? "Zeitüberschreitung beim Backend. Ergebnis unbekannt; vor Wiederholung aktualisieren." : `Backend nicht erreichbar unter ${API_BASE}`); }
  if (withSession && session !== state.session) throw new Error("Antwort einer beendeten Sitzung verworfen.");
  if (response.ok) return response.status === 204 ? null : response.json();
  let detail = null;
  try { detail = await response.json(); } catch (error) { /* Antwort ohne JSON */ }
  const failure = new Error(detail?.message || `Backend-Fehler (${response.status})`);
  failure.code = detail?.error;
  failure.fingerprint = detail?.fingerprint;
  failure.keyType = detail?.key_type;
  failure.message = explainActionError(failure);
  if (failure.code === "not_connected") showConnect("Die Verbindung ist abgelaufen. Bitte erneut verbinden.");
  throw failure;
}
const loadStates = new Map();
function renderLoadStates() {
  const entries = [...loadStates];
  const failed = entries.filter(([, value]) => value.status === "error");
  const pending = entries.some(([, value]) => value.status === "pending");
  setConnection(!failed.length && !pending);
  if (failed.length || pending) {
    $("#connection-label").textContent = failed.length ? "Daten teilweise nicht aktuell" : "Daten werden geladen …";
    $(".connection-pill").textContent = failed.length ? "Aktualisierung fehlgeschlagen" : "Wird aktualisiert …";
  }
  let notice = $("#load-notice");
  if (!notice) { notice = document.createElement("div"); notice.id = "load-notice"; notice.className = "info-banner warning-banner"; notice.setAttribute("role", "status"); $(".topbar").after(notice); }
  notice.classList.toggle("hidden", !failed.length);
  notice.textContent = failed.map(([path, value]) => `${path}: ${value.message} Vorhandene Daten können veraltet sein.`).join(" ");
}
async function load(path, assign, render) {
  const session = state.session;
  const ticket = { status: "pending" };
  loadStates.set(path, ticket);
  renderLoadStates();
  try {
    const data = await request(path);
    if (state.session !== session || loadStates.get(path) !== ticket) throw new Error("Aktualisierung durch neuere Sitzung oder Abfrage ersetzt.");
    assign(data); render(); ticket.status = "ok";
    return data;
  } catch (error) {
    if (state.session === session && loadStates.get(path) === ticket) {
      ticket.status = "error"; ticket.message = explainActionError(error);
      showError(error);
    }
    throw error;
  } finally {
    if (state.session === session && loadStates.get(path) === ticket) renderLoadStates();
  }
}
function jsonBody(value) { return JSON.stringify(value); }

function todayImportant() {
  const checks = state.securityCheck?.checks || [];
  const warning = checks.find((check) => check.status === "warn");
  if (warning) return { tone: "warning", eyebrow: "Heute wichtig", title: warning.label, detail: warning.plain || warning.detail, button: "Jetzt prüfen" };
  const unknown = checks.find((check) => check.status === "unknown");
  if (unknown) return { tone: "neutral", eyebrow: "Heute wichtig", title: "Sicherheits-Check vervollständigen", detail: unknown.plain || `${unknown.label}: ${unknown.detail}`, button: "Details ansehen" };
  if (state.status?.internet && state.status.internet !== "up") return { tone: "warning", eyebrow: "Heute wichtig", title: "Internetverbindung prüfen", detail: "Der Router meldet derzeit keine aktive Verbindung zum Internet.", button: "Status ansehen" };
  if (!state.securityCheck) return { tone: "neutral", eyebrow: "Heute wichtig", title: "Heimnetz wird geprüft", detail: "Sobald die Routerdaten vorliegen, zeigen wir dir genau eine sinnvolle nächste Aktion.", button: "Sicherheits-Check öffnen" };
  return { tone: "good", eyebrow: "Heute wichtig", title: "Dein Heimnetz ist gut aufgestellt", detail: "Die geprüften Punkte sind in Ordnung. Du musst gerade nichts ändern.", button: "Sicherheits-Check ansehen" };
}
function renderTodayImportant() {
  const status = $("#status");
  if (!status) return;
  let card = $("#today-important");
  if (!card) {
    card = document.createElement("article");
    card.id = "today-important";
    card.className = "today-important";
    status.querySelector(".status-grid")?.before(card);
  }
  const item = todayImportant();
  card.className = `today-important ${item.tone}`;
  card.innerHTML = `<div class="today-important-mark" aria-hidden="true">${item.tone === "good" ? "✓" : "!"}</div><div class="today-important-copy"><p class="eyebrow">${escapeHtml(item.eyebrow)}</p><h3>${escapeHtml(item.title)}</h3><p>${escapeHtml(item.detail)}</p></div><button class="secondary-button" type="button" data-action="show-page-security">${escapeHtml(item.button)} →</button>`;
}

function renderStatus() {
  const data = state.status;
  if (!data) return;
  const online = data.internet === "up";
  $("#status-heading").textContent = online ? "Alles im grünen Bereich" : "Internet prüfen";
  $("#internet-status").textContent = online ? "Verbunden" : "Nicht verbunden";
  $("#internet-status").style.color = online ? "#228e5c" : "#b66f1b";
  $("#internet-message").textContent = online ? "Deine Verbindung läuft stabil." : "Der Router meldet keine aktive Verbindung.";
  $("#internet-badge").textContent = online ? "Online" : "Offline";
  $("#internet-badge").className = `status-badge ${online ? "success" : "warning"}`;
  $("#connected-devices").textContent = data.connected_devices ?? "–";
  $("#router-identity").textContent = data.router_identity || "–";
  $("#router-identity-input").value = data.router_identity || "";
  $("#router-version").textContent = `RouterOS ${data.routeros_version || "–"}`;
  $("#router-uptime").textContent = `Uptime ${data.uptime || "–"}`;
  $("#wan-ip").textContent = data.wan_ip || "–";
  $("#wan-interface-picker")?.classList.add("hidden");
  $("#last-updated").textContent = `Zuletzt geprüft: ${new Date().toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" })}`;
  renderTodayImportant();
}
function renderCapabilities() {
  const status = $("#status");
  if (!status || !state.capabilities) return;
  let banner = $("#capability-banner");
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "capability-banner";
    banner.className = "info-banner capability-banner";
    status.append(banner);
  }
  const notices = [];
  const wifi = state.capabilities.wifi;
  const wireguard = state.capabilities.wireguard;
  const routing = state.capabilities.routing;
  if (wifi && !wifi.supported) notices.push("Dieser Router meldet keinen unterstützten WLAN-Treiber.");
  else if (wifi && !wifi.configured) notices.push("Es ist aktuell kein WLAN-Interface eingerichtet.");
  if (wireguard && !wireguard.supported) notices.push("WireGuard ist auf diesem Router oder für diesen Benutzer nicht verfügbar.");
  else if (wireguard && !wireguard.configured) notices.push("Es ist aktuell kein WireGuard-Interface eingerichtet.");
  if (routing && !routing.supported) notices.push("Die Routing-Tabelle ist für diesen Benutzer nicht verfügbar.");
  else if (routing && !routing.configured) notices.push("Der Router meldet aktuell keine Route.");
  banner.classList.toggle("hidden", notices.length === 0);
  banner.innerHTML = notices.length
    ? `<span class="info-icon">i</span><p><strong>Fähigkeiten dieses Routers</strong> ${escapeHtml(notices.join(" "))}</p>`
    : "";
}
function renderWanInterfacePicker() {
  const picker = $("#wan-interface-picker");
  if (!picker) return;
  picker.classList.toggle("hidden", state.wanInterfaceError?.code !== "wan_interface_ambiguous");
  if (state.wanInterfaceError?.code === "wan_interface_ambiguous") {
    $("#wan-interface-select").innerHTML = `<option value="">Bitte auswählen …</option>${state.wanInterfaces.map((item) => `<option value="${escapeHtml(item.interface)}">${escapeHtml(item.interface)} · ${escapeHtml(item.source)}</option>`).join("")}`;
  }
}
async function loadStatus() {
  try {
    await load("/status", (data) => { state.status = data; state.wanInterfaceError = null; }, renderStatus);
  } catch (error) {
    if (error.code !== "wan_interface_ambiguous" || state.session === null) throw error;
    state.wanInterfaceError = error;
    state.wanInterfaces = await request("/network/wan-interfaces");
    renderWanInterfacePicker();
    throw error;
  }
}
function renderLeases() {
  let card = $("#dashboard-leases");
  if (!card) {
    card = document.createElement("article");
    card.id = "dashboard-leases";
    card.className = "feature-card dashboard-leases";
    $("#status").append(card);
  }
  card.innerHTML = `<div class="section-heading"><div><p class="eyebrow">Netzwerk</p><h3>DHCP-Leases</h3></div><span class="muted">${state.leases.length} Einträge</span></div>${state.leases.length ? `<div class="lease-list">${state.leases.map((lease) => `<div class="mini-item"><span><strong>${escapeHtml(lease.hostname || "Unbekanntes Gerät")}</strong><br><span class="mono">${escapeHtml(lease.ip || "–")}</span> · ${escapeHtml(lease.network || "–")}</span><span class="status-badge ${lease.active ? "success" : "neutral"}">${lease.active ? "Aktiv" : "Inaktiv"}</span></div>`).join("")}</div>` : `<p class="muted">Keine DHCP-Leases vorhanden.</p>`}`;
}
function renderNetwork() {
  if (!state.network) return;
  $("#network-address-list").innerHTML = state.network.addresses.length ? state.network.addresses.map((item) => `<form class="network-ip-form" data-interface="${escapeHtml(item.interface)}"><label><span>${escapeHtml(item.interface)}</span><input name="address" value="${escapeHtml(item.address || "")}" required></label><button class="secondary-button" type="submit">IP speichern</button></form>`).join("") : `<p class="muted">Keine IP-Adressen gefunden.</p>`;
  $("#dns-servers").value = state.network.dns_servers.join(", ");
  $("#dhcp-client-list").innerHTML = state.network.dhcp_clients.length ? state.network.dhcp_clients.map((client) => `<div class="mini-item"><span><strong>${escapeHtml(client.interface)}</strong><br>${escapeHtml(client.address || "Keine Adresse")} · ${escapeHtml(client.status || "unbekannt")}</span><button type="button" data-dhcp-client="${escapeHtml(client.interface)}">Entfernen</button></div>`).join("") : `<p class="muted">Keine DHCP-Clients eingerichtet.</p>`;
  $("#dhcp-client-interface").innerHTML = state.network.addresses.map((item) => `<option value="${escapeHtml(item.interface)}">${escapeHtml(item.interface)}</option>`).join("");
}
function renderDhcpRanges() {
  $("#dhcp-range-list").innerHTML = state.dhcpRanges.length ? state.dhcpRanges.map((range) => `<div class="mini-item"><span><strong>${escapeHtml(range.interface)}</strong><br>${escapeHtml(range.network || "–")} · ${escapeHtml(range.range_start || "–")}–${escapeHtml(range.range_end || "–")}</span><button type="button" data-dhcp-range="${escapeHtml(range.id)}">Entfernen</button></div>`).join("") : `<p class="muted">Keine DHCP-Bereiche eingerichtet.</p>`;
}
function renderWifi() { $("#wifi-list").innerHTML = state.wifi.length ? state.wifi.map((network) => `<article class="feature-card wifi-card"><div class="network-head"><div><h3>${escapeHtml(network.ssid || network.interface)}</h3><p class="muted">${escapeHtml(network.interface)}</p></div><span class="status-badge ${network.disabled === true ? "neutral" : "success"}">${network.disabled === true ? "Deaktiviert" : "Aktiv"}</span></div><div class="wifi-details"><span>◉ ${escapeHtml(network.band || "Band unbekannt")}</span><span>◌ ${network.hidden ? "Verborgen" : "Sichtbar"}</span></div><form class="wifi-ssid-form" data-interface="${escapeHtml(network.interface)}"><label>Netzwerkname (SSID)<input aria-label="Neue SSID für ${escapeHtml(network.ssid || network.interface)}" maxlength="32" value="${escapeHtml(network.ssid || "")}" required></label><button class="secondary-button" type="submit">SSID speichern</button></form><form class="wifi-form" data-interface="${escapeHtml(network.interface)}"><input aria-label="Neues Passwort für ${escapeHtml(network.ssid || network.interface)}" minlength="8" placeholder="Neues Passwort (mind. 8 Zeichen)" required><button class="secondary-button" type="submit">Passwort ändern</button></form></article>`).join("") : `<div class="feature-card"><p class="muted">Das Backend meldet keine WLAN-Interfaces.</p></div>`; }
function deviceIcon(device) {
  const text = `${device.vendor_guess || ""} ${device.hostname || ""}`.toLowerCase();
  if (text.includes("druck") || text.includes("printer")) return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 8V4.5h10V8M6.5 18.5h11v-5h-11zM5 8h14a2 2 0 0 1 2 2v5.5h-3.5M6.5 15.5H3V10a2 2 0 0 1 2-2Z"/></svg>';
  if (text.includes("shelly") || text.includes("espressif")) return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3v6M16 3v6M6 9h12v2a6 6 0 0 1-6 6h0a6 6 0 0 1-6-6V9ZM12 17v4"/></svg>';
  return '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="5" width="16" height="12" rx="2"/><path d="M9 21h6M12 17v4"/></svg>';
}
function renderDevices() {
  $(".count-pill").textContent = state.devices.length;
  let grid = $("#device-grid");
  if (!grid) {
    grid = document.createElement("div"); grid.id = "device-grid"; grid.className = "device-grid";
    const table = $("#device-list")?.closest(".table-card");
    table?.after(grid); table?.classList.add("hidden");
  }
  grid.innerHTML = state.devices.length ? state.devices.map((device) => `<article class="device-card ${device.active ? "is-active" : "is-inactive"}"><div class="device-card-head"><span class="device-icon device-card-icon">${deviceIcon(device)}</span><div><h3>${escapeHtml(device.hostname || "Unbekanntes Gerät")}</h3><p>${escapeHtml(device.vendor_guess || "Hersteller unbekannt")}</p></div><span class="status-badge ${device.active ? "success" : "neutral"}">${device.active ? "● Verbunden" : "○ Inaktiv"}</span></div><div class="device-card-meta"><span class="mono">${escapeHtml(device.ip || "Keine IP")}</span><span>${escapeHtml(device.network || "Netzwerk unbekannt")}</span><span>${escapeHtml(device.mac)}</span></div><form class="device-room-form" data-device="${escapeHtml(device.mac)}"><label>Raum<input data-room-input maxlength="40" value="${escapeHtml(device.room || "")}" placeholder="Kein Raum zugewiesen"></label><button class="secondary-button" type="button" data-action="save-room" data-device="${escapeHtml(device.mac)}">Raum speichern</button></form><div class="device-card-actions"><button class="text-button" type="button" data-device="${escapeHtml(device.mac)}">Details verwalten →</button><button class="text-button" type="button" data-action="open-webui" data-device="${escapeHtml(device.mac)}">Weboberfläche →</button></div></article>`).join("") : `<article class="feature-card"><p class="muted">Keine DHCP-Geräte gefunden.</p></article>`;
}

function renderTopology() {
  let topology = $("#network-topology");
  if (!topology) {
    const guest = $("#guest");
    if (!guest) return;
    guest.insertAdjacentHTML("beforebegin", '<section class="section compact-section topology-section"><div class="section-heading"><div><p class="eyebrow">Übersicht</p><h2>Deine Netzwerk-Topologie</h2></div><span class="muted">Live aus dem Router</span></div><article class="feature-card topology-card"><p class="explanation">Diese Übersicht zeigt die Geräte und Netzwerke, die Cockpit gerade vom Router lesen kann. Sie ersetzt keinen vollständigen Netzplan.</p><div id="network-topology" class="topology" aria-live="polite"></div></article></section>');
    topology = $("#network-topology");
  }
  const addresses = state.network?.addresses || [];
  const networks = [...new Set(addresses.map((item) => item.interface).filter(Boolean))];
  const router = escapeHtml(state.status?.router_identity || "Router");
  const internet = state.status?.internet === "up" ? "Internet erreichbar" : "Internetstatus unbekannt";
  const nodes = networks.length ? networks.map((name) => `<div class="topology-node network-node"><strong>${escapeHtml(name)}</strong><small>${state.devices.filter((device) => device.network === name).length} Gerät(e)</small></div>`).join("") : `<div class="topology-node network-node"><strong>Lokales Netzwerk</strong><small>${state.devices.length} Gerät(e)</small></div>`;
  topology.innerHTML = `<div class="topology-node internet-node"><strong>${internet}</strong></div><span class="topology-line"></span><div class="topology-node router-node"><strong>${router}</strong><small>${addresses.length || "Keine"} IP-Adresse(n)</small></div><span class="topology-line"></span><div class="topology-branches">${nodes}</div>`;
}
function renderForwards() { $("#forward-list").innerHTML = state.forwards.length ? state.forwards.map((forward) => `<div class="mini-item"><span><strong>${escapeHtml(forward.name)}</strong><br>${String(forward.protocol).toUpperCase()} ${escapeHtml(forward.external_port)} → ${escapeHtml(forward.internal_ip)}:${escapeHtml(forward.internal_port)}</span><button type="button" data-forward="${escapeHtml(forward.id)}">Entfernen</button></div>`).join("") : `<p class="muted">Keine Cockpit-Portfreigaben vorhanden.</p>`; }
const SECURITY_STATUS_ICON = {
  good: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6"><path d="M4 12l5 5L20 6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 4.5 21 19H3z"/><path d="M12 10v4.2M12 17h.01" stroke-linecap="round"/></svg>',
  unknown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="8.5"/><path d="M12 16h.01M9.5 9.3a2.5 2.5 0 1 1 3.9 2.1c-.7.5-1.4 1-1.4 2.1" stroke-linecap="round"/></svg>',
};
function renderSecurityCheck() {
  const data = state.securityCheck;
  const gaugeArc = $("#score-gauge-arc");
  const gaugeNum = $("#score-number");
  const detail = $("#score-detail");
  const list = $("#security-check-list");
  if (!data) return;
  if (data.score === null) {
    gaugeNum.textContent = "–";
    gaugeArc.style.stroke = "var(--muted)";
    gaugeArc.setAttribute("stroke-dashoffset", "163.4");
    detail.textContent = "Noch keine geprüfbaren Punkte für diesen Router.";
  } else {
    gaugeNum.textContent = String(data.score);
    gaugeArc.style.stroke = data.score >= 80 ? "var(--green)" : data.score >= 50 ? "var(--warn)" : "var(--danger)";
    gaugeArc.setAttribute("stroke-dashoffset", String(163.4 - (163.4 * data.score) / 100));
    const good = data.checks.filter((check) => check.status === "good").length;
    const rated = data.checks.filter((check) => check.status !== "unknown").length;
    detail.textContent = `${good} von ${rated} Prüfungen bestanden`;
  }
  list.innerHTML = data.checks.map((check) => {
    const plain = check.plain || check.detail || "Dieser Punkt konnte nicht erläutert werden.";
    const technical = check.detail || "Keine technischen Details verfügbar.";
    return `<div class="check-row check-${escapeHtml(check.status)}"><span class="check-icon ${check.status}">${SECURITY_STATUS_ICON[check.status]}</span><div class="check-body"><strong>${escapeHtml(check.label)}</strong><span class="check-plain">${escapeHtml(plain)}</span><details class="check-technical"><summary>Technische Details</summary><p>${escapeHtml(technical)}</p></details></div></div>`;
  }).join("");
  renderTodayImportant();
}
function renderBackups() { $("#backup-list").innerHTML = state.backups.length ? state.backups.map((backup) => `<div class="mini-item"><span><strong>${escapeHtml(new Date(backup.created_at).toLocaleString("de-DE"))}</strong><br>${escapeHtml(backup.size_kb)} KB · ${escapeHtml(backup.id)}</span><span><button type="button" data-backup="${escapeHtml(backup.id)}">Download</button> <button type="button" class="device-action" data-backup-restore="${escapeHtml(backup.id)}">Wiederherstellen</button></span></div>`).join("") : `<p class="muted">Noch keine Backups vorhanden.</p>`; }
async function loadAll() {
  await load("/capabilities", (data) => { state.capabilities = data; renderCapabilities(); }, renderCapabilities).catch(() => {});
  await ensureProModule();
  applyTierUi();
  const proLoads = window.CockpitPro?.loadAll ? window.CockpitPro.loadAll() : [];
  await Promise.allSettled([
    loadStatus(),
    load("/wifi", (data) => { state.wifi = data; renderWifi(); window.CockpitPro?.onWifiLoaded?.(); }, () => {}),
    load("/devices", (data) => { state.devices = data; renderDevices(); }, renderDevices),
    load("/network", (data) => { state.network = data; }, renderNetwork),
    load("/network/dhcp-ranges", (data) => { state.dhcpRanges = data; }, renderDhcpRanges),
    load("/network/dhcp-leases", (data) => { state.leases = data; }, renderLeases),
    load("/port-forwards", (data) => { state.forwards = data; }, renderForwards),
    load("/backup", (data) => { state.backups = data; }, renderBackups),
    load("/security-check", (data) => { state.securityCheck = data; }, renderSecurityCheck),
    ...proLoads,
  ]);
}
function openDevicePanel(mac) { const device = state.devices.find((item) => item.mac === mac); if (!device) return; $("#device-panel").classList.remove("hidden"); $("#device-panel").innerHTML = `<div><p class="eyebrow">Gerät verwalten</p><h3>${escapeHtml(device.hostname || "Unbekanntes Gerät")}</h3><p class="muted">${escapeHtml(device.vendor_guess || "Hersteller unbekannt")} · ${escapeHtml(device.mac)}</p><div class="suggestion">Erkennung wird geprüft …</div></div><div class="panel-actions"><label>Feste IP<input id="reservation-ip" value="${escapeHtml(device.ip || "")}"></label><button class="primary-button" type="button" data-action="save-reservation" data-device="${escapeHtml(device.mac)}">IP speichern</button><button class="secondary-button" type="button" data-action="open-webui" data-device="${escapeHtml(device.mac)}">Weboberfläche öffnen</button><button class="device-action" type="button" data-action="disconnect-device" data-device="${escapeHtml(device.mac)}">WLAN kurz trennen</button></div>`; $("#device-panel").scrollIntoView({ behavior: "smooth", block: "nearest" }); load(`/devices/${encodeURIComponent(mac)}/webui-suggestion`, (suggestion) => { const text = suggestion.suggested ? `Weboberfläche erkannt: ${escapeHtml(suggestion.vendor)} · Port ${suggestion.default_port}` : "Keine Weboberfläche automatisch erkannt."; $("#device-panel .suggestion").innerHTML = text; }, () => {}).catch(() => {}); }

document.addEventListener("submit", async (event) => { if (event.target.matches("#connect-form")) return connectToRouter(event); if (event.target.matches(".wifi-ssid-form")) { event.preventDefault(); const input = event.target.querySelector("input"); try { const data = await request(`/wifi/${encodeURIComponent(event.target.dataset.interface)}/ssid`, { method: "PUT", body: jsonBody({ ssid: input.value }) }); const network = state.wifi.find((item) => item.interface === event.target.dataset.interface); if (network) network.ssid = data.ssid; renderWifi(); showToast("WLAN-Name wurde geändert."); } catch (error) { showToast(error.message); } return; } if (!event.target.matches(".wifi-form")) return; event.preventDefault(); const input = event.target.querySelector("input"); try { const result = await request(`/wifi/${encodeURIComponent(event.target.dataset.interface)}/password`, { method: "PUT", body: jsonBody({ new_password: input.value }) }); input.value = ""; if (result.undo_available === true) return showWifiUndoNotice(event.target.dataset.interface); showToast("WLAN-Passwort wurde geändert."); } catch (error) { showToast(error.message); } });
document.addEventListener("submit", async (event) => { if (!event.target.matches("#router-identity-form")) return; event.preventDefault(); const input = $("#router-identity-input"); try { const data = await request("/router-identity", { method: "PUT", body: jsonBody({ name: input.value.trim() }) }); state.status.router_identity = data.router_identity; renderStatus(); $("#router-identity-form").classList.add("hidden"); showToast("Routername wurde gespeichert."); } catch (error) { showToast(error.message); } });
document.addEventListener("submit", async (event) => {
  if (event.target.matches(".network-ip-form")) {
    event.preventDefault();
    if (!await confirmAction("Die Verbindung zum Router kann sofort abbrechen. Fahre nur fort, wenn du die neue Adresse sicher kennst.", "IP-Adresse ändern")) return;
    const interfaceName = event.target.dataset.interface;
    const address = event.target.elements.address.value.trim();
    try { await request(`/network/ip-address/${encodeURIComponent(interfaceName)}`, { method: "PUT", body: jsonBody({ address }) }); showToast("IP-Adresse wurde gespeichert."); await load("/network", (data) => { state.network = data; }, renderNetwork); } catch (error) { showToast(error.message); }
    return;
  }
  if (event.target.matches("#dns-form")) {
    event.preventDefault();
    const servers = $("#dns-servers").value.split(",").map((server) => server.trim()).filter(Boolean);
    try { await request("/network/dns", { method: "PUT", body: jsonBody({ servers }) }); showToast("DNS-Server wurden gespeichert."); await load("/network", (data) => { state.network = data; }, renderNetwork); } catch (error) { showToast(error.message); }
    return;
  }
  if (event.target.matches("#dhcp-client-form")) {
    event.preventDefault();
    try { await request("/network/dhcp-client", { method: "POST", body: jsonBody({ interface: $("#dhcp-client-interface").value }) }); showToast("DHCP-Client wurde eingerichtet."); await load("/network", (data) => { state.network = data; }, renderNetwork); } catch (error) { showToast(error.message); }
    return;
  }
  if (!event.target.matches("#dhcp-range-form")) return;
  event.preventDefault();
  const form = event.target;
  const payload = { interface: $("#dhcp-range-interface").value.trim(), network: $("#dhcp-range-network").value.trim(), range_start: $("#dhcp-range-start").value.trim(), range_end: $("#dhcp-range-end").value.trim(), gateway: $("#dhcp-range-gateway").value.trim() || undefined, dns_servers: $("#dhcp-range-dns").value.split(",").map((server) => server.trim()).filter(Boolean) };
  try { await request("/network/dhcp-ranges", { method: "POST", body: jsonBody(payload) }); form.reset(); await load("/network/dhcp-ranges", (data) => { state.dhcpRanges = data; }, renderDhcpRanges); showToast("DHCP-Bereich wurde angelegt."); } catch (error) { showToast(error.message); }
});
document.addEventListener("click", async (event) => {
  const action = event.target.closest("[data-action]")?.dataset.action;
  try {
    if (action === "toggle-theme") { toggleTheme(); return; }
    if (action === "show-page-security") { showPage("security"); return; }
    if (action === "disconnect") { try { await request("/disconnect", { method: "POST" }); } finally { showConnect(); } return; }
    if (action === "refresh") return loadAll();
    if (action === "show-identity-form") { $("#router-identity-form").classList.toggle("hidden"); if (!$("#router-identity-form").classList.contains("hidden")) $("#router-identity-input").focus(); return; }
    if (action === "copy-ip") { await navigator.clipboard?.writeText($("#wan-ip").textContent); return showToast("WAN-Adresse in die Zwischenablage kopiert."); }
    if (action === "select-wan-interface") { const interfaceName = $("#wan-interface-select").value; if (!interfaceName) return showToast("Bitte zuerst ein WAN-Interface auswählen."); await request("/network/wan-interface", { method: "PUT", body: jsonBody({ interface: interfaceName }) }); state.wanInterfaceError = null; await loadStatus(); return showToast("WAN-Interface wurde ausgewählt."); }
    if (action === "show-forward-form") return $("#forward-form").classList.toggle("hidden");
    if (action === "add-forward") { const payload = { name: $("#forward-name").value.trim(), protocol: $("#forward-protocol").value, external_port: Number($("#forward-port").value), internal_ip: $("#forward-ip").value.trim(), internal_port: Number($("#forward-internal-port").value) }; await request("/port-forwards", { method: "POST", body: jsonBody(payload) }); $("#forward-form").classList.add("hidden"); await load("/port-forwards", (data) => { state.forwards = data; }, renderForwards); return showToast("Portfreigabe mit NAT- und Firewall-Regel angelegt."); }
    if (action === "create-backup") { await request("/backup", { method: "POST" }); await load("/backup", (data) => { state.backups = data; }, renderBackups); return showToast("Backup wurde erstellt."); }
    const deviceButton = event.target.closest("[data-device]");
    if (deviceButton && !action) return openDevicePanel(deviceButton.dataset.device);
    if (action === "save-room") { const mac = event.target.dataset.device; const card = event.target.closest(".device-card"); const room = card?.querySelector("[data-room-input]")?.value ?? ""; const result = await request(`/devices/${encodeURIComponent(mac)}/room`, { method: "PUT", body: jsonBody({ room: room === "" ? null : room }) }); const device = state.devices.find((item) => item.mac === mac); if (device) device.room = result.room; renderDevices(); return showToast(result.room ? `Raum „${result.room}“ gespeichert.` : "Raum-Zuordnung entfernt."); }
    if (action === "save-reservation") { const mac = event.target.dataset.device; const device = state.devices.find((item) => item.mac === mac); await request(`/devices/${encodeURIComponent(mac)}/reservation`, { method: "PUT", body: jsonBody({ ip: $("#reservation-ip").value, has_webui: Boolean(device?.webui_port), webui_port: device?.webui_port || 80, webui_scheme: device?.webui_scheme || "http" }) }); return showToast("Feste IP wurde gespeichert."); }
    if (action === "open-webui") { const mac = event.target.dataset.device; const device = state.devices.find((item) => item.mac === mac); const suggestion = await request(`/devices/${encodeURIComponent(mac)}/webui-suggestion`); if (!suggestion.suggested || !device?.ip) return showToast("Für dieses Gerät ist keine Weboberfläche bekannt."); window.open(`${suggestion.default_scheme}://${device.ip}:${suggestion.default_port}`, "_blank", "noopener"); return; }
    if (action === "disconnect-device") { const mac = event.target.dataset.device; if (!await confirmAction("Das WLAN-Gerät kann sich sofort wieder verbinden. Kabelgeräte werden nicht getrennt. Falls dies dein eigenes Gerät ist, kann auch die Cockpit-Verbindung abbrechen.", "WLAN-Gerät kurz trennen")) return; await request(`/devices/${encodeURIComponent(mac)}/connection`, { method: "DELETE" }); await load("/devices", (data) => { state.devices = data; }, renderDevices); return showToast("WLAN-Trennung angefordert. Das Gerät kann sich sofort wieder verbinden."); }
    const forwardButton = event.target.closest("[data-forward]"); if (forwardButton) { await request(`/port-forwards/${encodeURIComponent(forwardButton.dataset.forward)}`, { method: "DELETE" }); await load("/port-forwards", (data) => { state.forwards = data; }, renderForwards); return showToast("Portfreigabe wurde entfernt."); }
    const backupButton = event.target.closest("[data-backup]"); if (backupButton) { const response = await fetch(`${API_BASE}/backup/${encodeURIComponent(backupButton.dataset.backup)}/download`, { headers: { "X-Cockpit-Session": state.session } }); if (!response.ok) { const detail = await response.json().catch(() => null); throw new Error(detail?.message || `Backend-Fehler (${response.status})`); } const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = `${backupButton.dataset.backup}.backup`; link.click(); URL.revokeObjectURL(url); return; }
    const restoreButton = event.target.closest("[data-backup-restore]");
    if (restoreButton) {
      const backupId = restoreButton.dataset.backupRestore;
      // Audit A13-Rest: Wiederherstellung ersetzt die GESAMTE Konfiguration und startet den
      // Router sofort neu -- zweifache Bestätigung, kein einfacher Klick-weg.
      if (!await confirmAction(`Backup „${backupId}“ überschreibt die komplette Konfiguration dieses Routers und startet ihn sofort neu.`, "Backup wiederherstellen", "Weiter")) return;
      if (!await confirmAction("Diese Aktion kann nicht rückgängig gemacht werden.", "Wirklich wiederherstellen?", "Endgültig wiederherstellen")) return;
      await request(`/backup/${encodeURIComponent(backupId)}/restore`, { method: "POST", body: jsonBody({ confirm: true }) });
      return showToast("Wiederherstellung gestartet. Der Router wird kurz nicht erreichbar sein.");
    }
  } catch (error) { showToast(error.message); }
});
document.addEventListener("click", async (event) => {
  const client = event.target.closest("[data-dhcp-client]");
  const range = event.target.closest("[data-dhcp-range]");
  try {
    if (client) { await request(`/network/dhcp-client/${encodeURIComponent(client.dataset.dhcpClient)}`, { method: "DELETE" }); await load("/network", (data) => { state.network = data; }, renderNetwork); return showToast("DHCP-Client wurde entfernt."); }
    if (range) { if (!await confirmAction("Pool und DHCP-Server dieses Bereichs werden entfernt. Geräte erhalten dort keine neuen Adressen mehr.", "DHCP-Bereich entfernen", "Bereich entfernen")) return; await request(`/network/dhcp-ranges/${encodeURIComponent(range.dataset.dhcpRange)}`, { method: "DELETE" }); await load("/network/dhcp-ranges", (data) => { state.dhcpRanges = data; }, renderDhcpRanges); return showToast("DHCP-Bereich wurde entfernt."); }
  } catch (error) { showToast(error.message); }
});

function showPage(pageName) {
  document.querySelectorAll("[data-page-view]").forEach((page) => page.classList.toggle("hidden", page.dataset.pageView !== pageName));
  document.querySelectorAll(".nav-link[data-page]").forEach((link) => link.classList.toggle("active", link.dataset.page === pageName));
  document.querySelector(".main-content")?.scrollTo({ top: 0, behavior: "smooth" });
  window.scrollTo({ top: 0, behavior: "smooth" });
}
function setupPages() {
  const main = $(".main-content");
  const firstSection = main.querySelector("section[id]");
  const groups = {
    status: ["status"],
    wifi: ["wifi", "guest"],
    network: ["devices", "network", "dhcp-ranges", "pppoe"],
    security: ["security-check", "forwards", "firewall", "services"],
    maintenance: ["maintenance"],
    help: ["faq", "wiki"],
  };
  const sections = new Map([...main.querySelectorAll("section[id]")].map((section) => [section.id, section]));
  const wrappers = new Map();
  const pages = Object.keys(groups).map((pageName) => {
    const page = document.createElement("div");
    page.className = "page-view hidden";
    page.dataset.pageView = pageName;
    main.insertBefore(page, firstSection);
    wrappers.set(pageName, page);
    return page;
  });
  Object.entries(groups).forEach(([pageName, ids]) => ids.forEach((id) => { const section = sections.get(id); if (section) wrappers.get(pageName).append(section); }));
  const contentGrid = main.querySelector(".content-grid");
  contentGrid?.remove();
  showPage("status");
}
document.addEventListener("click", (event) => {
  const goal = event.target.closest("[data-onboarding-page]");
  if (goal) { finishOnboarding(goal.dataset.onboardingPage); return; }
  if (event.target.closest('[data-action="skip-onboarding"]')) { finishOnboarding("status"); return; }
});
document.addEventListener("click", (event) => {
  const link = event.target.closest(".nav-link[data-page]");
  if (!link) return;
  event.preventDefault();
  showPage(link.dataset.page);
  history.replaceState(null, "", `#page-${link.dataset.page}`);
});
setupPages();
window.CockpitCore = { state, load, request, jsonBody, showToast, showError, explainActionError, confirmAction, escapeHtml, $, setConnection, renderSecurityCheck };
init();
