"""Einstiegspunkt von mikrotik-cockpit.

Seit der Basis/Pro-Code-Trennung (
2026-09-10) ist dies eine reine Zusammensetzungsdatei: erzeugt die Flask-App, registriert
die geteilten Fehlerbehandler/Session-Pruefung/CORS-Header, registriert `routes_basis`
(oeffentlich, AGPL, immer vorhanden) und versucht `routes_pro` (privates Repo, "Cockpit
Pro") per try/except zu laden. Im oeffentlichen Repo fehlt `routes_pro.py` schlicht -- die
App bleibt dann ein vollstaendiges, eigenstaendiges Basis-Produkt, `/api/v1/capabilities`
meldet `"tier": "basis"` statt `"tier": "pro"`.

Feature-Code (egal ob Basis oder Pro) gehoert NICHT hierher, siehe core.py/routes_basis.py/
routes_pro.py.
"""

import os
import time

from flask import Flask, jsonify, request, send_from_directory

import core
from routeros import (
    RouterAuthFailed,
    RouterCommandFailed,
    RouterTimeout,
    RouterUnreachable,
)
import routes_basis

try:
    import routes_pro
except ImportError:
    routes_pro = None

app = Flask(__name__)
cfg = core.cfg
# Kennung dieses Prozesses (Startzeit). Das Frontend merkt sich den ersten Wert und laedt die
# Seite neu, sobald er sich aendert -- so arbeitet nach einem Update (start-cockpit.sh startet
# den Dienst neu) nie eine alte Oberflaeche gegen ein neues Backend weiter.
BUILD_ID = f"{int(time.time())}-{os.getpid()}"
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend"))


@app.errorhandler(RouterUnreachable)
def handle_unreachable(exc):
    return jsonify({"error": "router_unreachable", "message": str(exc)}), 502


@app.errorhandler(RouterTimeout)
def handle_timeout(exc):
    return jsonify({"error": "router_timeout", "message": "Router antwortet nicht"}), 504


@app.errorhandler(RouterAuthFailed)
def handle_auth_failed(exc):
    return jsonify({"error": "auth_failed", "message": "Benutzername oder Passwort falsch"}), 401


@app.errorhandler(RouterCommandFailed)
def handle_command_failed(exc):
    # Audit A14: RouterOS meldet manche Fehler (ungueltiger Wert, fehlende Rechte,
    # Syntaxfehler) trotz Exitcode 0 nur im Ausgabetext -- run_command() erkennt bekannte
    # Fehlermuster und wirft das hier als eigenen Fehler statt es als Erfolg durchzureichen.
    text = str(exc)
    lowered = text.lower()
    # Audit 18.09., Befund 3: "not enough permissions (9) (/user/set *0)" liest sich wie ein Absturz;
    # tatsaechlich fehlt dem Sitzungsbenutzer nur die Policy (Benutzer verwalten darf nur full).
    if "not enough permissions" in lowered:
        return jsonify({
            "error": "router_permission_denied",
            "message": "Der angemeldete Router-Benutzer hat dafür keine Rechte. Für diese Aktion braucht "
                       "es einen Benutzer der Gruppe full.",
        }), 403
    # Kundeneigene Passwortrichtlinie (/user settings minimum-categories, minimum-password-length),
    # live am hAP 18.09.: "failure: password is too weak - it must contain characters from at least
    # 4 categories (...)". Ist eine Eingabeablehnung, kein Routerfehler.
    if "password is too weak" in lowered or "password is too short" in lowered:
        return jsonify({
            "error": "password_policy",
            "message": "Der Router lehnt das Passwort wegen seiner eigenen Passwortrichtlinie ab "
                       "(zu kurz oder zu wenige Zeichenarten aus Ziffern, Klein- und Großbuchstaben, Symbolen).",
        }), 400
    return jsonify({
        "error": "router_command_failed",
        "message": f"Der Router hat den Befehl abgelehnt: {text}",
    }), 502


@app.before_request
def require_session():
    # Die Oberfläche (statische Dateien) darf immer laden -- sonst käme man nicht mal bis
    # zum Verbinden-Bildschirm. Nur /api/*-Aufrufe brauchen eine aktive Sitzung, ausser den
    # beiden Endpunkten, die die Sitzung selbst verwalten.
    if not request.path.startswith("/api/") or request.method == "OPTIONS":
        return None
    if request.path in core.EXEMPT_API_PATHS:
        # Audit Runde 4, 09.09.: /connect braucht (anders als jeder andere Endpunkt) keine
        # Sitzung und damit auch keinen "X-Cockpit-Session"-Header -- genau der Header, dessen
        # Pflicht ueberall sonst schon als CSRF-Schutz wirkt (ein Custom-Header zwingt Browser zu
        # einem CORS-Preflight, den die feste Access-Control-Allow-Origin-Pruefung abfaengt).
        # Live nachgewiesen: eine fremde Webseite kann per fetch(url, {method:"POST",
        # headers:{"Content-Type":"text/plain"}, body: ...}) -- eine CORS-"simple request" ohne
        # Preflight -- trotzdem POST /connect gegen den lokal laufenden Cockpit-Prozess ausloesen.
        # Der Prozess baut dann blind eine SSH-Verbindung zu einem vom Angreifer gewaehlten Host
        # mit dessen Zugangsdaten auf, nur weil der Nutzer eine fremde Seite offen hat (blindes
        # SSRF/CSRF, Antwort selbst bleibt fuer den Angreifer wegen CORS unlesbar). Ohne
        # "application/json" als Content-Type ist die Anfrage kein CORS-Safelist-Fall mehr --
        # der Browser muss dann zwingend preflighten, und die bestehende Origin-Pruefung greift.
        if request.path == "/api/v1/connect" and request.method == "POST":
            content_type = (request.content_type or "").split(";")[0].strip().lower()
            if content_type != "application/json":
                return jsonify({
                    "error": "bad_request",
                    "message": "Content-Type muss application/json sein",
                }), 400
        return None
    session_id = request.headers.get("X-Cockpit-Session")
    now = time.monotonic()
    expired = False
    with core._sessions_lock:
        conn = core.SESSIONS.get(session_id) if session_id else None
        if conn is not None:
            last_activity = conn.setdefault("last_activity", now)
            if now - last_activity > core.SESSION_IDLE_TIMEOUT_SECONDS:
                core.SESSIONS.pop(session_id, None)
                expired = True
                conn = None
            else:
                conn["last_activity"] = now
    if conn is None:
        return jsonify({
            "error": "session_expired" if expired else "not_connected",
            "message": "Die Sitzung ist wegen Inaktivität abgelaufen. Bitte erneut verbinden."
            if expired else "Keine aktive Verbindung. Bitte zuerst verbinden.",
        }), 401


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = core.cfg.allowed_origin
    # "X-Cockpit-Token" ist ein Relikt aus der Zeit vor dem Verbinden-Modell (siehe
    # dem Verbinden-Modell) -- Audit A18, 09.09.: nur noch "X-Cockpit-Session"
    # ist gueltig, der alte Header-Name gehoert hier nicht mehr rein.
    response.headers["Access-Control-Allow-Headers"] = "X-Cockpit-Session, Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Expose-Headers"] = "X-Cockpit-Build"
    response.headers["X-Cockpit-Build"] = BUILD_ID
    return response


@app.get("/")
def frontend_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def frontend_asset(filename: str):
    return send_from_directory(FRONTEND_DIR, filename)


app.register_blueprint(routes_basis.bp)

if routes_pro is not None:
    app.register_blueprint(routes_pro.bp)
    app.config["COCKPIT_TIER"] = "pro"
else:
    app.config["COCKPIT_TIER"] = "basis"


if __name__ == "__main__":
    # Nur lokal erreichbar -- das Verbinden-Modell (siehe dem Verbinden-Modell)
    # braucht keinen Zugriff aus dem Heimnetz mehr, Cockpit läuft wie WinBox auf dem Rechner
    # des Kunden selbst.
    app.run(host="127.0.0.1", port=cfg.backend_port, debug=False, use_reloader=False)
