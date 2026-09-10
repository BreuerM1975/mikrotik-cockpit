// Sprachschicht fuer Cockpit.
//
// Die Oberflaeche ist in Deutsch geschrieben -- index.html, app.js und pro.js enthalten den
// deutschen Text direkt. Diese Datei uebersetzt das, was tatsaechlich im DOM landet, statt jede
// einzelne Codestelle anzufassen. Damit wird auch Text aus HTML-Vorlagen erfasst, die erst zur
// Laufzeit erzeugt werden, und der deutsche Ausgangszustand bleibt unveraendert.
//
// Zwei Nachschlagewege: DICT fuer exakte Treffer, PATTERNS fuer Saetze mit eingesetzten Werten.
// Deutsch ist die Ausgangssprache und braucht kein Woerterbuch.

(function () {
  "use strict";

  const SUPPORTED = ["de", "en"];
  const STORAGE_KEY = "cockpit-language";

  function detectLanguage() {
    let saved = null;
    try { saved = localStorage.getItem(STORAGE_KEY); } catch (e) { /* privates Fenster */ }
    if (SUPPORTED.includes(saved)) return saved;
    const nav = (navigator.language || "en").toLowerCase();
    return nav.startsWith("de") ? "de" : "en";
  }

  const lang = detectLanguage();
  const DICT = window.COCKPIT_DICT_EN || {};
  const PATTERNS = window.COCKPIT_PATTERNS_EN || [];
  const SUBSTITUTIONS = window.COCKPIT_SUBSTITUTIONS_EN || [];

  // Attribute, die sichtbaren Text tragen.
  const TEXT_ATTRS = ["placeholder", "title", "aria-label"];

  function translate(value) {
    if (lang === "de") return value;
    const raw = String(value);
    const trimmed = raw.trim();
    if (!trimmed) return value;
    const hit = DICT[trimmed];
    if (hit !== undefined) {
      // Fuehrende/abschliessende Leerzeichen des Originals erhalten, sonst bricht das Layout
      // an Stellen wie "<span>Icon</span> Startseite".
      const lead = raw.slice(0, raw.indexOf(trimmed[0]));
      const tail = raw.slice(raw.lastIndexOf(trimmed[trimmed.length - 1]) + 1);
      return lead + hit + tail;
    }
    for (const [pattern, replacement] of PATTERNS) {
      if (pattern.test(trimmed)) {
        pattern.lastIndex = 0;
        return raw.replace(pattern, replacement);
      }
      pattern.lastIndex = 0;
    }
    // Dritte Stufe fuer zusammengesetzte Zeichenketten: die Firewall-Zusammenfassung etwa entsteht
    // aus Bausteinen mit " · " dazwischen und landet als ein einziger Textknoten. Hier wird jeder
    // Baustein einzeln ersetzt, statt den ganzen Satz treffen zu muessen.
    let substituted = raw;
    for (const [needle, replacement] of SUBSTITUTIONS) {
      if (substituted.includes(needle)) substituted = substituted.split(needle).join(replacement);
    }
    return substituted;
  }

  function translateNode(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      const next = translate(node.nodeValue);
      if (next !== node.nodeValue) node.nodeValue = next;
      return;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return;
    if (node.tagName === "SCRIPT" || node.tagName === "STYLE" || node.tagName === "SVG") return;

    for (const attr of TEXT_ATTRS) {
      const value = node.getAttribute && node.getAttribute(attr);
      if (value) {
        const next = translate(value);
        if (next !== value) node.setAttribute(attr, next);
      }
    }
    // Optionen und Knoepfe tragen ihren Text als Kindknoten, der Walker unten holt sie ab.
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, {
      acceptNode(textNode) {
        const parent = textNode.parentNode;
        if (!parent) return NodeFilter.FILTER_REJECT;
        const tag = parent.tagName;
        if (tag === "SCRIPT" || tag === "STYLE") return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    let current;
    while ((current = walker.nextNode())) {
      const next = translate(current.nodeValue);
      if (next !== current.nodeValue) current.nodeValue = next;
    }
    if (node.querySelectorAll) {
      for (const attr of TEXT_ATTRS) {
        node.querySelectorAll("[" + attr + "]").forEach((el) => {
          const value = el.getAttribute(attr);
          const next = translate(value);
          if (next !== value) el.setAttribute(attr, next);
        });
      }
    }
  }

  function translateDocument() {
    if (lang === "de") return;
    translateNode(document.body);
    document.documentElement.setAttribute("lang", lang);
    const description = document.querySelector('meta[name="description"]');
    if (description) description.setAttribute("content", translate(description.getAttribute("content")));
  }

  // Alles, was app.js/pro.js nachtraeglich rendert, laeuft hier durch.
  function observe() {
    if (lang === "de") return;
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "characterData") {
          const next = translate(mutation.target.nodeValue);
          if (next !== mutation.target.nodeValue) mutation.target.nodeValue = next;
        }
        mutation.addedNodes.forEach(translateNode);
      }
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
      attributeFilter: TEXT_ATTRS,
    });
  }

  function setLanguage(next) {
    if (!SUPPORTED.includes(next) || next === lang) return;
    try { localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* privates Fenster */ }
    // Neu laden ist hier der verlaessliche Weg: die Sitzung liegt im Backend und ueberlebt das,
    // eine Rueckuebersetzung des bereits ersetzten DOM waere fehleranfaellig.
    location.reload();
  }

  function mountSwitch() {
    const actions = document.querySelector(".topbar-actions");
    if (!actions || document.getElementById("language-toggle")) return;
    const button = document.createElement("button");
    button.type = "button";
    button.id = "language-toggle";
    button.className = "theme-toggle language-toggle";
    button.setAttribute("aria-label", lang === "de" ? "Switch to English" : "Auf Deutsch umschalten");
    button.title = button.getAttribute("aria-label");
    button.textContent = lang === "de" ? "EN" : "DE";
    button.addEventListener("click", () => setLanguage(lang === "de" ? "en" : "de"));
    const themeToggle = actions.querySelector(".theme-toggle");
    actions.insertBefore(button, themeToggle || actions.firstChild);
  }

  function start() {
    translateDocument();
    observe();
    mountSwitch();
  }

  window.cockpitI18n = { language: lang, t: translate, setLanguage };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
