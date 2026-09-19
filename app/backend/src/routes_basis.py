"""Basis-Routen von mikrotik-cockpit (oeffentlich, AGPL, kostenlos).

Aufteilung nach der Basis/Pro-Klassifikation ("Modell:
GitHub-Sponsors + Pro-Features":

| Endpunkt-Gruppe | Einordnung | Begruendung |
|---|---|---|
| /connect, /disconnect, /session, /capabilities | Basis (Infrastruktur) | Kein Feature, ohne das laeuft gar nichts |
| /status, /security-check | Basis | Kernversprechen, im SHOW.md als Alleinstellungsmerkmal genannt |
| /network/wan-interfaces, /network/ip-address, /network/dns, /network/dhcp-client, /network/dhcp-ranges | Basis | Grundlegendes Onboarding (Setup-Assistent aus Phase B), kein Nischen-Feature |
| /network/dhcp-leases | Basis | Explizit in der Strategie genannt |
| /router-identity | Basis | Explizit genannt ("Routername aendern") |
| /router-password (+undo), /reboot | Pro | Explizit genannt ("Passwort aendern + Neustart") |
| /wifi* (Liste, SSID, Passwort +undo) | Basis | Explizit genannt |
| /pppoe | Pro | Explizit genannt |
| /devices* (Liste, Trennen, Raum, Reservierung, Web-UI-Vorschlag) | Basis | Teil des Status-Dashboards |
| /guest-network | Pro | Explizit genannt |
| /port-forwards | Basis | Explizit genannt |
| /firmware (+update) | Pro | Nicht explizit genannt, aber riskant wie Neustart (echter Reboot) |
| /backup (erstellen, Download, restore) | Basis | Erstellen/Download explizit genannt; Restore gehoert strukturell dazu |
| /vpn/* (Interfaces, Peers) | Pro | Explizit genannt |
| /network (GET, Uebersicht) | Basis | Lesend, Teil des Dashboards |
| /firewall/* (forward/input/nat) | Pro | Explizit genannt |
| /services | Pro | Explizit genannt ("IP-Services-Verwaltung") |

Grenzfaelle (siehe den Projektnotizen, Ergebnis des RouterOS-Reviews vom 10.09.2026):
Die Gastnetz-Isolationspruefung fuer `/security-check` (Basis) und `_fw_ordered_ids()` fuer
`/port-forwards` (Basis) haengen an Helfern, die inhaltlich zu den Pro-Themen Gastnetz/
Firewall gehoeren -- diese Helfer liegen deshalb in `core.py`, nicht hier.
"""

import ipaddress
import json
import os
import re
import secrets
import tempfile
import time
import uuid
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request, send_file

import core
from routeros import (
    HostKeyChanged,
    HostKeyUnknown,
    RouterCommandFailed,
    RouterTimeout,
    RouterUnreachable,
    download_file,
    ensure_host_key_trusted,
    parse_colon,
    parse_terse,
    run_command,
    trust_host_key,
    upload_file,
)

bp = Blueprint("basis", __name__)

# Ergebnis des Produkt-Reviews (10.09.2026): gezieltes Undo pro Aktionstyp statt
# eines kompletten Backup-Restores mit Router-Neustart. Das Zeitfenster ist bewusst kurz --
# "Ruecklaengig" ist ein kurzer Reflex direkt nach der Aenderung, kein dauerhaftes Feature.
try:
    WIFI_PASSWORD_UNDO_WINDOW_SECONDS = int(os.environ.get("COCKPIT_WIFI_UNDO_WINDOW", "300"))
except ValueError:
    WIFI_PASSWORD_UNDO_WINDOW_SECONDS = 300


@bp.post("/api/v1/connect")
def connect():
    body = request.get_json(force=True, silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({"error": "bad_request", "message": "Der Request-Body muss ein JSON-Objekt sein"}), 400
    host = body.get("host")
    user = body.get("user", "admin")
    password = body.get("password")
    if not isinstance(host, str) or not isinstance(user, str) or not isinstance(password, str):
        return jsonify({
            "error": "bad_request",
            "message": "'host', 'user' und 'password' müssen Text sein",
        }), 400
    host = host.strip()
    user = user.strip() or "admin"
    # Bewusst NICHT .strip(): ein Passwort mit fuehrenden/abschliessenden Leerzeichen ist
    # gueltig und muss unveraendert an RouterOS gehen -- ein Nutzer, der so ein Passwort
    # gesetzt hat, wuerde sonst mit korrektem Passwort ausgesperrt.
    try:
        ssh_port_value = body.get("ssh_port")
        if isinstance(ssh_port_value, bool):
            raise ValueError
        ssh_port = 22 if ssh_port_value in (None, "") else int(ssh_port_value)
    except (TypeError, ValueError):
        return jsonify({"error": "bad_request", "message": "'ssh_port' muss eine Zahl sein"}), 400
    if not 1 <= ssh_port <= 65535:
        return jsonify({"error": "bad_request", "message": "'ssh_port' muss zwischen 1 und 65535 liegen"}), 400
    if not host or not password:
        return jsonify({"error": "bad_request", "message": "'host' und 'password' sind Pflicht"}), 400
    confirm_fingerprint = body.get("confirm_fingerprint")
    if confirm_fingerprint is not None and not isinstance(confirm_fingerprint, str):
        return jsonify({"error": "bad_request", "message": "'confirm_fingerprint' muss Text sein"}), 400

    # Audit A18: vor dem ersten Login pruefen, ob der SSH-Host-Key dieses Routers schon
    # bestaetigt wurde. Ohne diese Pruefung wuerde der anschliessende ssh-Aufruf einen
    # unbekannten Schluessel bisher klaglos selbst akzeptieren (frueher "accept-new") --
    # das ist genau der stille Vertrauensschritt, den ein Kunde sehen und bestaetigen muss.
    try:
        ensure_host_key_trusted(host, ssh_port, core.cfg.known_hosts_path)
    except HostKeyUnknown as exc:
        if confirm_fingerprint != exc.fingerprint:
            return jsonify({
                "error": "host_key_unknown",
                "message": (
                    f"Dieser Router wurde noch nie bestätigt. SSH-Fingerprint ({exc.key_type}): "
                    f"{exc.fingerprint}. Bitte mit dem am Router selbst angezeigten Fingerprint "
                    "vergleichen und erneut senden, um ihm zu vertrauen."
                ),
                "fingerprint": exc.fingerprint,
                "key_type": exc.key_type,
            }), 428
        trust_host_key(core.cfg.known_hosts_path, exc.known_hosts_line)
    except HostKeyChanged as exc:
        return jsonify({
            "error": "host_key_changed",
            "message": (
                f"Achtung: Der SSH-Schlüssel dieses Routers hat sich geändert (jetzt "
                f"{exc.fingerprint}, {exc.key_type}). Das kann ein neu aufgesetztes Gerät sein "
                "oder ein Man-in-the-Middle-Angriff. Verbindung aus Sicherheitsgründen "
                "abgelehnt -- den alten Eintrag nur nach eigener Prüfung manuell entfernen."
            ),
        }), 409

    # Bewusst direkt run_command() statt core.router(): es gibt noch keine Sitzung, deren
    # Zugangsdaten core.router() lesen koennte -- die werden hier gerade erst geprueft.
    identity = parse_colon(run_command(
        host, user, password, ssh_port, "/system identity print",
        known_hosts_path=core.cfg.known_hosts_path,
    ))
    resource = parse_colon(run_command(
        host, user, password, ssh_port, "/system resource print",
        known_hosts_path=core.cfg.known_hosts_path,
    ))

    session_id = secrets.token_urlsafe(24)
    with core._sessions_lock:
        core.SESSIONS[session_id] = {
            "host": host, "user": user, "password": password, "ssh_port": ssh_port,
            "last_activity": time.monotonic(),
        }
    return jsonify({
        "ok": True,
        "session": session_id,
        "router_identity": identity.get("name"),
        "routeros_version": resource.get("version"),
    })


@bp.post("/api/v1/disconnect")
def disconnect():
    # Idempotent: Trennen ohne (noch) aktive Sitzung ist kein Fehler.
    session_id = request.headers.get("X-Cockpit-Session")
    with core._sessions_lock:
        core.SESSIONS.pop(session_id, None)
    return jsonify({"ok": True})


@bp.get("/api/v1/session")
def session_status():
    # require_session() hat die Sitzung an dieser Stelle schon geprüft -- hier nur
    # zusätzlich einen frischen Identity-Check gegen den Router, damit "gültig laut
    # Backend" auch wirklich "Router antwortet noch" bedeutet.
    identity = parse_colon(core.router("/system identity print"))
    resource = parse_colon(core.router("/system resource print"))
    return jsonify({
        "ok": True,
        "session": request.headers["X-Cockpit-Session"],
        "router_identity": identity.get("name"),
        "routeros_version": resource.get("version"),
    })


def _capability_probe(command: str) -> tuple[bool, list[dict]]:
    """Liest eine RouterOS-Fähigkeit ohne Schreibzugriff.

    Ein leerer Tabellenwert bedeutet: Der Befehl ist vorhanden, aber aktuell ist
    kein entsprechendes Objekt eingerichtet. Ein RouterOS-Fehler bedeutet, dass
    die Fähigkeit auf diesem Gerät oder mit diesem Benutzer nicht verfügbar ist.
    Eine RouterOS-Fehlermeldung ohne SSH-Fehlertext kommt bei nicht vorhandenen
    Menüs als leerer ``RouterUnreachable``-Text zurück. Nur diesen Sonderfall
    behandeln wir als nicht verfügbar; echte Transportfehler bleiben ungefangen.
    """
    try:
        return True, parse_terse(core.router(command))
    except RouterCommandFailed:
        return False, []
    except RouterUnreachable as exc:
        if str(exc).strip():
            raise
        return False, []


@bp.get("/api/v1/capabilities")
def capabilities():
    wireless_supported, wireless_rows = _capability_probe("/interface wireless print terse")
    wifi_supported, wifi_rows = _capability_probe("/interface wifi print terse")
    wlan_supported, wlan_rows = _capability_probe('/interface print terse where type="wlan"')
    wireguard_supported, wireguard_rows = _capability_probe("/interface wireguard print terse")
    routing_supported, route_rows = _capability_probe("/ip route print terse")
    wifi_drivers = []
    if wireless_rows:
        wifi_drivers.append("wireless")
    if wifi_rows:
        wifi_drivers.append("wifi")
    return jsonify({
        # Meldet, ob dieser Backend-Prozess ueberhaupt routes_pro.py geladen hat -- siehe
        # app.py. Im oeffentlichen Repo fehlt die Datei schlicht, "tier" bleibt "basis".
        "tier": current_app.config.get("COCKPIT_TIER", "basis"),
        "wifi": {
            "supported": wlan_supported and bool(wlan_rows),
            "configured": bool(wlan_rows),
            "drivers": wifi_drivers,
        },
        "wireguard": {
            "supported": wireguard_supported,
            "configured": bool(wireguard_rows),
        },
        "routing": {
            "supported": routing_supported,
            "configured": bool(route_rows),
        },
    })


@bp.get("/api/v1/status")
def status():
    # Audit A16, 09.09.: "internet up" hing bisher allein am Link-Status der WAN-Schnittstelle --
    # ein eingestecktes, aber funktionsloses Kabel (ISP-Ausfall, keine Adresse, tote Route) sah
    # fuer den Kunden trotzdem nach "Verbunden" aus. Jetzt braucht "up" alle drei Signale, ohne
    # dass Cockpit selbst Traffic nach aussen schickt (kein Ping): Link, eine echte WAN-Adresse
    # und eine aktive Default-Route. Welches der drei fehlt, geht als "internet_detail" mit --
    # Grundlage fuer eine spaetere gezieltere Fehlermeldung im Frontend.
    identity = parse_colon(core.router("/system identity print"))
    resource = parse_colon(core.router("/system resource print"))
    wan_interface = _wan_interface()
    wan_running = parse_terse(core.router(f'/interface print terse where name="{wan_interface}"'))
    wan_addr = parse_terse(core.router(f'/ip address print terse where interface="{wan_interface}"'))
    default_route = parse_terse(core.router('/ip route print terse where dst-address="0.0.0.0/0" and active=yes'))
    leases = parse_terse(core.router('/ip dhcp-server lease print terse where status="bound"'))

    link_up = bool(wan_running) and wan_running[0]["running"]
    wan_ip = wan_addr[0]["address"].split("/")[0] if wan_addr else None
    has_route = bool(default_route)
    internet_up = link_up and wan_ip is not None and has_route

    if internet_up:
        internet_detail = "ok"
    elif not link_up:
        internet_detail = "no_link"
    elif wan_ip is None:
        internet_detail = "no_address"
    else:
        internet_detail = "no_default_route"

    return jsonify({
        "internet": "up" if internet_up else "down",
        "internet_detail": internet_detail,
        "wan_ip": wan_ip,
        "connected_devices": len(leases),
        "router_identity": identity.get("name"),
        "routeros_version": resource.get("version"),
        "uptime": resource.get("uptime"),
    })


class WanInterfaceUnavailable(Exception):
    def __init__(self, code: str, message: str, status: int):
        self.code = code
        self.message = message
        self.status = status


@bp.errorhandler(WanInterfaceUnavailable)
def handle_wan_interface_unavailable(exc):
    return jsonify({"error": exc.code, "message": exc.message}), exc.status


def _wan_interface() -> str:
    conn = core.current_conn()
    selected = conn.get("wan_interface")
    if selected:
        return selected
    configured = core._routeros_value(core.cfg.wan_interface, "wan_interface")
    configured_rows = parse_terse(core.router(f'/interface print terse where name="{configured}"'))
    if configured_rows:
        conn["wan_interface"] = configured
        return configured

    candidates = []
    for row in parse_terse(core.router('/ip dhcp-client print terse where status="bound"')):
        if row.get("interface"):
            candidates.append(row["interface"])
    for row in parse_terse(core.router('/interface pppoe-client print terse')):
        if row.get("name") and (row.get("running") or row.get("status") == "running"):
            candidates.append(row["name"])
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) == 1:
        conn["wan_interface"] = candidates[0]
        return candidates[0]
    if not candidates:
        raise WanInterfaceUnavailable("device_not_found", "Kein aktives WAN-Interface gefunden.", 404)
    raise WanInterfaceUnavailable(
        "wan_interface_ambiguous",
        "Mehrere aktive WAN-Interfaces gefunden. Bitte eines auswählen.",
        409,
    )


@bp.get("/api/v1/network/wan-interfaces")
def wan_interfaces_list():
    rows = []
    for row in parse_terse(core.router('/ip dhcp-client print terse where status="bound"')):
        if row.get("interface"):
            rows.append({"interface": row["interface"], "source": "DHCP"})
    for row in parse_terse(core.router('/interface pppoe-client print terse')):
        if row.get("name") and (row.get("running") or row.get("status") == "running"):
            rows.append({"interface": row["name"], "source": "PPPoE"})
    selected = core.current_conn().get("wan_interface")
    result = []
    seen = set()
    for row in rows:
        if row["interface"] in seen:
            continue
        seen.add(row["interface"])
        result.append({**row, "selected": row["interface"] == selected})
    return jsonify(result)


@bp.put("/api/v1/network/wan-interface")
def wan_interface_select():
    body = request.get_json(force=True, silent=True) or {}
    try:
        interface = core._routeros_value(body.get("interface", ""), "wan_interface")
    except ValueError:
        return jsonify({"error": "bad_request", "message": "Bitte ein WAN-Interface auswählen."}), 400
    rows = parse_terse(core.router(f'/interface print terse where name="{interface}"'))
    if not rows:
        return jsonify({"error": "device_not_found", "message": "WAN-Interface nicht gefunden."}), 404
    core.current_conn()["wan_interface"] = interface
    return jsonify({"ok": True, "interface": interface})


@bp.put("/api/v1/router-identity")
def router_identity_put():
    # Abschlussrunde, 10.09.2026: dieser Endpunkt validierte bisher nur handgestrickt (kein
    # Backslash/Anfuehrungszeichen/Semikolon/Steuerzeichen), rief aber NIE _routeros_text()/
    # _routeros_escape() auf -- anders als jeder andere schreibende Endpunkt im Projekt
    # (wifi_password, wifi_ssid, router_password_put, vpn_peers_create, ...). Ein Name mit
    # einem "$" war unter der alten Pruefung erlaubt (nur "\";" wurden geblockt) und ging
    # unescaped in den RouterOS-Befehl -- exakt der A02-Fund ("RouterOS interpretiert ein
    # unmaskiertes '$' in Strings als Variablenreferenz und ersetzt es still, kein Fehler"),
    # den A02 fuer die zentralen Helfer geschlossen hatte, aber eben nicht fuer diesen
    # Aufrufer, der die Helfer schlicht nie benutzte. Live gegen den Test-hAP verifiziert
    # (10.09.2026): "$x" als Routername liess vor dem Fix den tatsaechlichen Identity-Namen
    # leer laufen, waehrend die Cockpit-Sitzung weiter "$x" anzeigte.
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    try:
        safe_name = core._routeros_text(name, "name", maximum=64)
    except ValueError:
        return jsonify({
            "error": "invalid_router_identity",
            "message": "Der Routername muss 1 bis 64 Zeichen enthalten und darf keine Steuerzeichen, Anführungszeichen oder Semikolons enthalten",
        }), 400

    core.router(f'/system identity set name="{safe_name}"')
    return jsonify({"ok": True, "router_identity": name})


@bp.get("/api/v1/wifi")
def wifi_list():
    return jsonify(core.list_wireless_networks())


@bp.put("/api/v1/wifi/<interface>/password")
def wifi_password(interface: str):
    body = request.get_json(force=True, silent=True) or {}
    new_password = body.get("new_password", "")
    if len(new_password) < 8:
        return jsonify({"error": "password_too_short", "message": "Mindestens 8 Zeichen"}), 400
    try:
        safe_interface = core._routeros_value(interface, "interface")
        # WPA-Passphrasen sind laut IEEE 802.11 druckbares ASCII (8 bis 63 Zeichen), und RouterOS
        # wuerde einen Umlaut per SSH ohnehin still verwerfen (siehe core._routeros_ascii()).
        safe_password = core._routeros_ascii(new_password, "new_password", maximum=63)
    except ValueError:
        return jsonify({
            "error": "invalid_password",
            "message": "Das Passwort darf nur Buchstaben, Ziffern und Sonderzeichen ohne Umlaute enthalten, "
                       "keine Anführungszeichen (max. 63 Zeichen). RouterOS verwirft Umlaute per SSH stillschweigend.",
        }), 400

    # Audit Runde 4, 09.09.: "safe_interface" ist hier schon ueber core._routeros_value() escaped
    # -- ohne validated=True wuerde core._wireless_driver() das Escaping (Backslash verdoppeln,
    # Dollarzeichen maskieren) ein zweites Mal drauflegen. Fuer normale Interface-Namen ohne
    # "\"/"$" ist das folgenlos, bei einem Namen mit einem dieser Zeichen wuerde die interne
    # Lookup-Abfrage aber nicht mehr zum tatsaechlichen RouterOS-Namen passen und faelschlich
    # "device_not_found" liefern -- derselbe Bug, den B06 fuer den Gastnetz-Pfad schon behoben hat.
    driver = core._wireless_driver(safe_interface, validated=True)
    if driver is None:
        return jsonify({"error": "device_not_found", "message": "Interface unbekannt"}), 404

    conn = core.current_conn()
    undo_store = conn.setdefault("wifi_password_undo", {})

    if driver == "wireless":
        profiles = parse_terse(
            core.router(f'/interface wireless print terse where name="{safe_interface}"')
        )
        profile_name = core._routeros_value(profiles[0].get("security-profile", ""), "security-profile")
        old_secret = _wifi_capture_old_secret_wireless(profile_name)
        core.router(
            f'/interface wireless security-profiles set [find name="{profile_name}"] '
            f'wpa2-pre-shared-key="{safe_password}" wpa-pre-shared-key="{safe_password}"'
        )
    else:
        # Neuerer wifiwave2/wifi-Treiber (hAP ax2, wAP ax) -- Konfiguration liegt inline am
        # Interface, analog zu "configuration.ssid" bei wifi_ssid(). NICHT live gegen echte
        # wifi-Treiber-Hardware verifiziert (im Testlabor nur der klassische wireless-Treiber
        # vorhanden, siehe den Projektnotizen) -- vor Kundeneinsatz auf hAP ax2/wAP ax nachpruefen. Gilt
        # genauso fuer den Undo-Lesezugriff unten (_wifi_capture_old_secret_wifi()).
        old_secret = _wifi_capture_old_secret_wifi(safe_interface)
        core.router(
            f'/interface wifi set [find name="{safe_interface}"] '
            f'security.passphrase="{safe_password}"'
        )

    # Ergebnis des Produkt-Reviews: gezieltes Undo statt Backup-Restore-mit-Reboot.
    # "undo_available" ist ehrlich -- konnte der Altwert nicht gelesen werden (siehe
    # _wifi_capture_old_secret_wireless()/_wifi_capture_old_secret_wifi()), gibt es fuer GENAU
    # diese Aenderung kein Ruecklaengig, statt einen Undo-Button zu zeigen, der dann ins Leere
    # liefe. Nur EIN Undo-Stand je Interface (letzter Altwert gewinnt, keine Mehrfach-Historie)
    # -- ein zweiter Passwortwechsel auf demselben Interface ersetzt einen noch nicht genutzten
    # Undo-Stand, statt ihn danebenzulegen.
    undo_available = old_secret is not None
    if undo_available:
        undo_store[safe_interface] = {
            "old_value": old_secret,
            "expires_at": time.monotonic() + WIFI_PASSWORD_UNDO_WINDOW_SECONDS,
        }
    else:
        undo_store.pop(safe_interface, None)
    return jsonify({"ok": True, "undo_available": undo_available})


def _wifi_capture_old_secret_wireless(profile_name: str) -> dict | None:
    # Grundsatzfrage vor diesem Feature (siehe den Projektnotizen): zeigt RouterOS den gesetzten
    # wpa2-pre-shared-key/wpa-pre-shared-key im Klartext? Live gegen den Test-hAP verifiziert
    # (10.09.2026, RouterOS 7.23.1): NEIN in "print terse"/"print detail"/"export" -- RouterOS
    # blendet beide Felder dort grundsaetzlich aus, auch nicht maskiert, einfach nicht
    # vorhanden. Ein direkter Property-Zugriff per ":put [... get ... <feld>]" liefert
    # den Wert trotzdem im Klartext zurueck (ebenfalls live bestaetigt). Deshalb dieser
    # gezielte Lesezugriff statt parse_terse() auf die Listenausgabe.
    try:
        wpa2 = core.router(
            f':put [/interface wireless security-profiles get '
            f'[find name="{profile_name}"] wpa2-pre-shared-key]'
        ).strip()
        wpa = core.router(
            f':put [/interface wireless security-profiles get '
            f'[find name="{profile_name}"] wpa-pre-shared-key]'
        ).strip()
    except (RouterCommandFailed, RouterUnreachable, RouterTimeout):
        # Bewusst kein Absturz und kein Blockieren des eigentlichen Passwortwechsels: ohne
        # erfolgreich gelesenen Altwert gibt es fuer diese Aenderung schlicht kein Undo --
        # "undo_available: false" in der Antwort, kein falsches Versprechen (Projekt-Leitsatz
        # "kein falsches Gruen" gilt auch fuer Funktionsversprechen).
        return None
    return {"driver": "wireless", "profile_name": profile_name, "wpa2": wpa2, "wpa": wpa}


def _wifi_capture_old_secret_wifi(safe_interface: str) -> dict | None:
    # NICHT live gegen echte wifi-Treiber-Hardware verifiziert (Testlabor hat nur den
    # klassischen wireless-Treiber, siehe den Projektnotizen) -- rein defensiv gebaut: schlaegt das
    # Auslesen aus irgendeinem Grund fehl (z.B. abweichender Property-Name auf einer anderen
    # RouterOS-Version), bleibt "undo_available: false", der eigentliche Passwortwechsel oben
    # laeuft trotzdem unveraendert durch.
    try:
        passphrase = core.router(
            f':put [/interface wifi get [find name="{safe_interface}"] security.passphrase]'
        ).strip()
    except (RouterCommandFailed, RouterUnreachable, RouterTimeout):
        return None
    return {"driver": "wifi", "interface": safe_interface, "passphrase": passphrase}


@bp.post("/api/v1/wifi/<interface>/password/undo")
def wifi_password_undo(interface: str):
    # Gegenstueck zu wifi_password(): wendet ausschliesslich einen Altwert an, den DIESE
    # Sitzung selbst vorher erfolgreich gelesen hat (siehe SESSIONS-Kommentar in core.py) --
    # kein Klartext-Passwort verlaesst diese Funktion in Richtung Antwort, exakt wie beim
    # urspruenglichen PUT auch das neue Passwort nie zurueckgespiegelt wird.
    try:
        safe_interface = core._routeros_value(interface, "interface")
    except ValueError:
        return jsonify({"error": "bad_request", "message": "Ungültiger Interface-Name"}), 400

    conn = core.current_conn()
    undo_store = conn.setdefault("wifi_password_undo", {})
    record = undo_store.get(safe_interface)
    if record is None or time.monotonic() > record["expires_at"]:
        # Bewusst 404, nicht 500: "kein Undo mehr verfuegbar" ist ein erwarteter, sauber
        # unterscheidbarer Zustand (Zeitfenster abgelaufen, schon einmal benutzt, oder nie
        # gelesen werden konnte), kein Serverfehler.
        undo_store.pop(safe_interface, None)
        return jsonify({
            "error": "undo_unavailable",
            "message": "Für dieses WLAN-Passwort steht aktuell kein Rückgängig zur Verfügung.",
        }), 404

    # Sofort verbrauchen, bevor der Routerbefehl laeuft: ein Undo wirkt nur einmal, auch wenn
    # der folgende Routerbefehl fehlschlaegt (siehe dem API-Vertrag) -- sonst waere unklar, ob
    # ein zweiter Versuch denselben, ggf. inzwischen ungueltigen Altwert nochmal versuchen darf.
    del undo_store[safe_interface]

    old = record["old_value"]
    try:
        if old["driver"] == "wireless":
            # Altwert kommt vom Router selbst (siehe _wifi_capture_old_secret_wireless()), nicht
            # vom Nutzer -- trotzdem ungeprueft in einen neuen Befehl einzubauen waere genau die
            # Quotierungs-Falle, die dieses Projekt sonst konsequent vermeidet (z.B. ein frueher,
            # nicht ueber Cockpit gesetzter Schluessel mit eingebettetem Anfuehrungszeichen).
            # core._routeros_value() validiert UND escaped identisch zu jedem Nutzereingabepfad.
            safe_wpa2 = core._routeros_value(old["wpa2"], "wpa2-pre-shared-key", maximum=64)
            safe_wpa = core._routeros_value(old["wpa"], "wpa-pre-shared-key", maximum=64)
            core.router(
                f'/interface wireless security-profiles set '
                f'[find name="{old["profile_name"]}"] '
                f'wpa2-pre-shared-key="{safe_wpa2}" wpa-pre-shared-key="{safe_wpa}"'
            )
        else:
            safe_passphrase = core._routeros_value(old["passphrase"], "passphrase", maximum=64)
            core.router(
                f'/interface wifi set [find name="{old["interface"]}"] '
                f'security.passphrase="{safe_passphrase}"'
            )
    except ValueError:
        # Der urspruengliche Altwert war leer (RouterOS-Feld nie gesetzt) oder enthielt ein
        # Zeichen, das sich nicht sicher wieder einbauen laesst (z.B. ein Anfuehrungszeichen aus
        # einer fruehen, nicht ueber Cockpit gesetzten Konfiguration). RouterOS selbst lehnt einen
        # leeren WPA2-Schluessel ohnehin ab ("needs 8 to 64 characters", live bestaetigt) -- in
        # beiden Faellen ist das kein Serverfehler, sondern ein ehrlich benanntes "geht nicht".
        return jsonify({
            "error": "undo_failed",
            "message": "Der ursprüngliche Wert kann nicht sicher wiederhergestellt werden.",
        }), 409

    return jsonify({"ok": True})


@bp.put("/api/v1/wifi/<interface>/ssid")
def wifi_ssid(interface: str):
    body = request.get_json(force=True, silent=True) or {}
    ssid = body.get("ssid", "")
    try:
        safe_ssid = core._routeros_value(ssid, "ssid", maximum=32)
        # Audit Runde 4, 09.09.: hier stand bisher ein handgestricktes ".replace(\"\\\\\", ...)"
        # statt der projektweit etablierten core._routeros_value() -- das maskierte Backslashes,
        # aber KEIN Dollarzeichen. RouterOS interpretiert ein unmaskiertes "$" in einem String als
        # Variablenreferenz (siehe core._routeros_escape()) -- ein Interface-Name mit "$" hätte hier
        # stillschweigend einen anderen, verstümmelten Wert im Set-Befehl ergeben, statt sauber
        # escaped zu werden. In der Praxis nur erreichbar, wenn tatsächlich ein WLAN-Interface mit
        # "$" im Namen existiert (der vorgeschaltete _wireless_driver()-Fund muss treffen), aber
        # eine Abweichung vom sonst überall genutzten Escaping-Muster ist unabhängig davon ein
        # Fund, kein Grenzfall.
        safe_interface = core._routeros_value(interface, "interface")
        driver = core._wireless_driver(safe_interface, validated=True)
    except ValueError:
        return jsonify({"error": "invalid_ssid", "message": "Die SSID muss 1 bis 32 Zeichen enthalten und darf keine Anführungszeichen oder Zeilenumbrüche enthalten"}), 400
    if not driver:
        return jsonify({"error": "device_not_found", "message": "WLAN-Interface unbekannt"}), 404
    path = "wireless" if driver == "wireless" else "wifi"
    setting = "ssid" if driver == "wireless" else "configuration.ssid"
    core.router(f'/interface {path} set [find name="{safe_interface}"] {setting}="{safe_ssid}"')
    return jsonify({"ok": True, "interface": interface, "ssid": ssid})


@bp.get("/api/v1/devices")
def devices():
    leases = parse_terse(core.router("/ip dhcp-server lease print terse"))
    # Phase B, 10.09.2026: "room" ist reine Cockpit-eigene Zusatzinformation ohne
    # RouterOS-Datenquelle (Topologie-Kacheln, Ergebnis des Produkt-Reviews),
    # siehe _device_rooms_file_for_current_router().
    rooms = _load_device_rooms(_device_rooms_file_for_current_router())
    result = []
    for row in leases:
        mac = row.get("mac-address", "").lower()
        result.append({
            "mac": mac,
            "ip": row.get("address"),
            "hostname": row.get("host-name"),
            "vendor_guess": None,
            "active": row.get("status") == "bound",
            "network": row.get("server"),
            "room": rooms.get(mac),
        })
    return jsonify(result)


@bp.delete("/api/v1/devices/<mac>/connection")
def device_connection_delete(mac: str):
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
        return jsonify({"error": "bad_request", "message": "Ungültige MAC-Adresse."}), 400
    safe_mac = mac.upper()
    registrations = []
    for driver in ("wireless", "wifi"):
        path = f"/interface {driver} registration-table"
        try:
            output = core.router(f'{path} print terse where mac-address="{safe_mac}"')
        except (RouterUnreachable, RouterCommandFailed) as error:
            # Nur ein nachweislich fehlendes RouterOS-Menü überspringen, keine
            # Authentifizierungs-/Transportfehler als leere Registrierung ausgeben.
            if str(error).strip().lower().startswith("bad command name"):
                continue
            raise
        if output.strip().lower().startswith("bad command name"):
            continue
        rows = parse_terse(output)
        if output.strip() and not rows:
            return jsonify({"error": "router_state_unclear", "message": "WLAN-Registrierungen konnten nicht sicher gelesen werden."}), 502
        for row in rows:
            if row.get("mac-address", "").upper() != safe_mac or not row.get("interface"):
                return jsonify({"error": "router_state_unclear", "message": "WLAN-Registrierung konnte nicht eindeutig zugeordnet werden."}), 502
            registrations.append((path, row["interface"]))
    if not registrations:
        return jsonify({"error": "disconnect_unavailable", "message": "Dieses Gerät ist hier nicht direkt als WLAN-Client verbunden. Kabelgeräte und Clients anderer Access Points können so nicht getrennt werden. Es wurde nichts geändert."}), 409
    if len(registrations) != 1:
        return jsonify({"error": "router_state_unclear", "message": "Mehrere WLAN-Registrierungen gefunden. Aus Sicherheitsgründen wurde nichts getrennt."}), 409
    path, interface = registrations[0]
    try:
        safe_interface = core._routeros_text(interface, "interface", maximum=64)
    except ValueError:
        return jsonify({"error": "router_state_unclear", "message": "WLAN-Interface konnte nicht sicher zugeordnet werden."}), 502
    result = core.router(f'{path} remove [find where mac-address="{safe_mac}" and interface="{safe_interface}"]')
    if result.strip():
        return jsonify({"error": "router_state_unclear", "message": "Die WLAN-Trennung konnte nicht bestätigt werden. Bitte den Gerätestatus prüfen."}), 502
    # Keine dauerhafte Sperre: Der Client darf sich sofort wieder anmelden.
    return jsonify({"ok": True, "status": "disconnect_requested", "may_reconnect": True}), 202


@bp.put("/api/v1/devices/<mac>/room")
def device_room_put(mac: str):
    # Gleiche MAC-Validierung wie device_connection_delete()/_MAC_RE (device_reservation()) --
    # bewusst dieselbe Regex, siehe Auftrag Phase B, 10.09.2026.
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
        return jsonify({"error": "bad_request", "message": "Ungültige MAC-Adresse."}), 400
    body = request.get_json(force=True, silent=True) or {}
    try:
        room = _validate_room(body.get("room"))
    except ValueError:
        return jsonify({
            "error": "bad_request",
            "message": f"'room' darf höchstens {_ROOM_MAX_BYTES} Zeichen lang sein, muss ein "
                       "Text sein und darf keine Steuerzeichen enthalten.",
        }), 400
    safe_mac = mac.lower()
    rooms_path = _device_rooms_file_for_current_router()
    rooms = _load_device_rooms(rooms_path)
    if room is None:
        rooms.pop(safe_mac, None)
    else:
        rooms[safe_mac] = room
    _save_device_rooms(rooms_path, rooms)
    return jsonify({"ok": True, "mac": safe_mac, "room": room})


def _pf_comment(pf_id: str, name: str) -> str:
    return f"cockpit-pf:{pf_id}:{name}"


def _parse_pf_comment(comment: str) -> tuple[str | None, str | None]:
    parts = comment.split(":", 2)
    if len(parts) != 3 or parts[0] != "cockpit-pf":
        return None, None
    return parts[1], parts[2]


@bp.get("/api/v1/port-forwards")
def port_forwards_list():
    rows = parse_terse(core.router('/ip firewall nat print terse where comment~"^cockpit-pf:"'))
    result = []
    for row in rows:
        pf_id, name = _parse_pf_comment(row.get("comment", ""))
        if pf_id is None:
            continue
        result.append({
            "id": pf_id,
            "name": name,
            "protocol": row.get("protocol"),
            "external_port": row.get("dst-port"),
            "internal_ip": row.get("to-addresses"),
            "internal_port": row.get("to-ports"),
        })
    return jsonify(result)


def _valid_single_port(value) -> bool:
    # Audit Runde 4, 09.09.: "int(value)" akzeptiert stillschweigend fuehrende/abschliessende
    # Leerzeichen und Unterstriche als Tausendertrenner (z.B. int(" 8080\n") == 8080,
    # int("1_000") == 1000) -- true/false-Rueckgabe blieb dabei korrekt, aber der ROHE String
    # (nicht die geparste Zahl) landet unveraendert und UNQUOTIERT im RouterOS-Befehl
    # (port_forwards_create, device_reservation). Anders als bei Zeichen wie '"'/';' wuerde das
    # keine neue RouterOS-Zeile einschleusen (int() liesse dafuer sonst noetigen Text nicht
    # durch), aber ein still eingebauter Zeilenumbruch/Leerzeichen im Wert kann den sonst
    # einzeiligen Befehl an unerwarteter Stelle aufbrechen. Jetzt strikt auf reine Ziffern
    # beschraenkt, bevor ueberhaupt in int() konvertiert wird.
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 1 <= value <= 65535
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
        return 1 <= int(value) <= 65535
    return False


_PF_ID_RE = re.compile(r"^pf-[0-9a-f]{8}$")


@bp.post("/api/v1/port-forwards")
def port_forwards_create():
    with core._router_create_lock():
        return _port_forwards_create()


def _port_forwards_create():
    body = request.get_json(force=True, silent=True) or {}
    protocol = body.get("protocol")
    external_port = body.get("external_port")
    internal_ip = body.get("internal_ip")
    internal_port = body.get("internal_port")
    try:
        safe_name = core._routeros_text(body.get("name", ""), "name", maximum=64)
    except ValueError:
        return jsonify({"error": "bad_request", "message": "'name' fehlt oder ungueltig"}), 400
    if (
        protocol not in ("tcp", "udp")
        or not _valid_single_port(external_port)
        or not _valid_single_port(internal_port)
        or not core._valid_ipv4(internal_ip)
    ):
        return jsonify({
            "error": "bad_request",
            "message": "'external_port'/'internal_port' muessen 1-65535 sein, 'internal_ip' eine gueltige IPv4-Adresse",
        }), 400

    existing = parse_terse(
        core.router(
            f'/ip firewall nat print terse where chain=dstnat and protocol="{protocol}" '
            f'and dst-port="{external_port}"'
        )
    )
    if existing:
        return jsonify({"error": "port_in_use", "message": "Port bereits belegt"}), 409

    pf_id = "pf-" + uuid.uuid4().hex[:8]
    comment = _pf_comment(pf_id, safe_name)
    safe_wan = core._routeros_value(_wan_interface(), "wan_interface")
    # Audit A06, 09.09.: die NAT-Regel wurde bisher ohne Eingangsinterface angelegt und
    # konnte damit auch internen Verkehr treffen, nicht nur echten Zugriff von aussen ueber
    # den konfigurierten WAN-Anschluss. "in-interface" grenzt beide Regeln jetzt darauf ein.
    core.router(
        f'/ip firewall nat add chain=dstnat action=dst-nat protocol={protocol} '
        f'in-interface="{safe_wan}" dst-port={external_port} to-addresses={internal_ip} '
        f'to-ports={internal_port} comment="{comment}"'
    )
    try:
        # Wie bei den Firewall-Endpunkten (Pro, siehe routes_pro.py): vor die letzte bestehende
        # forward-Regel setzen, nicht ans Ende anhaengen -- sonst wirkt eine bereits
        # greifende "drop all"-Regel vor der neuen Freigabe-Regel und macht sie wirkungslos.
        # core._fw_ordered_ids() liegt in core.py, weil sowohl diese Basis-Route als auch die
        # Pro-Firewall-Erstellung sie brauchen (siehe Moduldocstring/den Projektnotizen).
        filter_path = "/ip firewall filter"
        before_ids = core._fw_ordered_ids(filter_path, "forward")
        place_before = f" place-before={before_ids[-1]}" if before_ids else ""
        core.router(
            f'{filter_path} add chain=forward action=accept protocol={protocol} '
            f'in-interface="{safe_wan}" dst-address={internal_ip} dst-port={internal_port} '
            f'comment="{comment}"{place_before}'
        )
    except Exception:
        # Rueckbau: schlaegt die Filter-Regel fehl, bleibt keine verwaiste, wirkungslose
        # NAT-Regel zurueck (Audit A06: "es gibt keinen Rueckbau/Abgleich").
        core.router(f'/ip firewall nat remove [find where comment="{comment}"]')
        raise
    return jsonify({
        "id": pf_id, "name": safe_name, "protocol": protocol,
        "external_port": external_port, "internal_ip": internal_ip, "internal_port": internal_port,
    }), 201


@bp.delete("/api/v1/port-forwards/<pf_id>")
def port_forwards_delete(pf_id: str):
    if not _PF_ID_RE.match(pf_id):
        return jsonify({"error": "not_found", "message": "Portweiterleitung unbekannt"}), 404
    prefix = f"cockpit-pf:{pf_id}:"
    nat_rows = parse_terse(core.router(f'/ip firewall nat print terse where comment~"^{prefix}"'))
    if not nat_rows:
        return jsonify({"error": "not_found", "message": "Portweiterleitung unbekannt"}), 404
    core.router(f'/ip firewall nat remove [find where comment~"^{prefix}"]')
    core.router(f'/ip firewall filter remove [find where comment~"^{prefix}"]')
    return jsonify({"ok": True})


_BACKUP_ID_RE = re.compile(r"^bkp-\d{4}-\d{2}-\d{2}-\d{6}-[0-9a-f]{4}$")


class BackupStorageUnsafe(Exception):
    pass


@bp.errorhandler(BackupStorageUnsafe)
def handle_backup_storage_unsafe(exc):
    return jsonify({"error": "backup_storage_unsafe", "message": str(exc)}), 500


def _ensure_private_dir(path: str, exc_cls: type[Exception] = None) -> None:
    """Legt ein Verzeichnis privat an (0700) und vertraut einem schon vorhandenen Verzeichnis
    nur, wenn es dem eigenen Prozess gehoert und fuer Gruppe/Andere nicht zugaenglich ist.

    Gleiches Muster wie _lookup_known_host() in routeros.py (Audit Runde 3, P0): ein Verzeichnis,
    das bereits von jemand anderem angelegt wurde (oder ein Symlink ist), koennte absichtlich
    vorbereitet worden sein, um Backups (oder seit Phase B, 10.09.2026: die lokale
    Geraete-Raum-Zuordnung) mitzulesen oder umzuleiten. Der Default von "backup_dir" liegt seit
    Audit Runde "Abschlussrunde" nicht mehr unter /tmp, dieser Check bleibt trotzdem als
    Verteidigung gegen einen abweichend konfigurierten COCKPIT_BACKUP_DIR/COCKPIT_DEVICE_ROOMS_DIR
    bestehen. "exc_cls" bestimmt, welcher Fehlercode beim Aufrufer ankommt (Default weiterhin
    BackupStorageUnsafe fuer bestehende Aufrufer) -- eine unsichere Geraete-Raum-Ablage darf nicht
    faelschlich als "backup_storage_unsafe" gemeldet werden.
    """
    exc_cls = exc_cls or BackupStorageUnsafe
    if os.path.islink(path):
        raise exc_cls(
            f"Das Verzeichnis '{path}' ist ein Symlink und wird aus Sicherheitsgruenden nicht verwendet."
        )
    if os.path.isdir(path):
        stat = os.stat(path)
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise exc_cls(
                f"Das Verzeichnis '{path}' gehoert nicht dem eigenen Benutzer oder ist fuer "
                "Gruppe/Andere zugaenglich und wird aus Sicherheitsgruenden nicht verwendet."
            )
        os.chmod(path, 0o700)
        return
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _backup_dir_for_current_router() -> str:
    # Audit A13, 09.09.: alle Router teilten sich bisher denselben Backup-Ordner -- ein
    # isolierter Test zeigte ein Backup von Router A in der Sitzung fuer Router B. Jetzt ein
    # eigener Unterordner je verbundenem Host, Zeichen ausserhalb [A-Za-z0-9.-] werden ersetzt,
    # damit der Ordnername kein Pfad-Traversal oder Sonderzeichen aus dem Hostnamen enthaelt.
    #
    # Audit Runde 5, 09.09.: nur der Host allein reicht nicht -- zwei verschiedene Router
    # koennen ueber denselben Host mit unterschiedlichem SSH-Port erreichbar sein (z.B.
    # Portweiterleitung, oder ein Router, der zwischenzeitlich getauscht wurde, aber den
    # gleichen Hostnamen/dieselbe IP behaelt). Der Port fliesst deshalb mit in den
    # Ordnernamen ein; er ist bereits als Ganzzahl 1-65535 validiert (siehe connect()),
    # also ohne eigenes Escaping unbedenklich.
    _ensure_private_dir(core.cfg.backup_dir)
    conn = core.current_conn()
    host = conn["host"]
    port = conn["ssh_port"]
    safe_host = re.sub(r"[^A-Za-z0-9.-]", "_", host) or "unbekannt"
    backup_dir = os.path.join(core.cfg.backup_dir, f"{safe_host}_{port}")
    os.makedirs(backup_dir, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    return backup_dir


def _resolve_backup_file(backup_dir: str, backup_id: str) -> str | None:
    """Loest den Pfad einer Backup-Datei sicher auf, ohne Symlinks zu folgen.

    Audit Runde 5, 09.09.: send_file() folgt anstandslos einem symbolischen Link.
    Landet je ein Praeparat mit passendem Dateinamen im Backup-Ordner (z.B. durch einen
    Fehler an anderer Stelle oder gemeinsame Dateisystemrechte), koennte darueber eine
    beliebige Datei ausserhalb des Backup-Ordners ausgeliefert werden. Nur eine echte,
    reguläre Datei zaehlt, deren aufgeloester Realpfad nachweislich innerhalb des
    erwarteten, routerspezifischen Backup-Ordners liegt.
    """
    path = os.path.join(backup_dir, f"{backup_id}.backup")
    if os.path.islink(path) or not os.path.isfile(path):
        return None
    real_dir = os.path.realpath(backup_dir)
    real_path = os.path.realpath(path)
    if os.path.dirname(real_path) != real_dir:
        return None
    return path


# ---------------------------------------------------------------------------
# Geraete-Raum-Zuordnung (Phase B, 10.09.2026, Topologie-Kacheln -- Ergebnis des Produkt-Reviews). Reine Cockpit-eigene
# Zusatzinformation ("Wohnzimmer", "Büro", ...), der Router selbst hat dafuer keine
# Datenquelle. Speicherort lokal auf dem Cockpit-Host, NICHT am Router, NICHT unter /tmp,
# pro Router getrennt -- gleiches Sicherheitsmuster wie _backup_dir_for_current_router()/
# _ensure_private_dir() (Eigentuemer-/Rechte-/Symlink-Check), aber ein eigener Ordner statt
# ein Unterordner von backup_dir, damit ein Backup-Restore/-Aufraeumen die Raum-Zuordnung
# nicht versehentlich mitreisst.

_ROOM_MAX_BYTES = 40


class DeviceRoomsStorageUnsafe(Exception):
    pass


@bp.errorhandler(DeviceRoomsStorageUnsafe)
def handle_device_rooms_storage_unsafe(exc):
    return jsonify({"error": "device_rooms_storage_unsafe", "message": str(exc)}), 500


def _validate_room(value) -> str | None:
    """Nullable Raumbezeichnung, max. 40 UTF-8-Bytes, keine Steuerzeichen.

    Landet NUR in einer lokalen JSON-Datei, nie in einem RouterOS-Befehl -- deshalb kein
    core._routeros_escape() noetig (kein "$"/RouterOS-Injection-Risiko). Steuerzeichen bleiben
    trotzdem gesperrt, dieselbe Disziplin wie bei core._routeros_text() -- bewusst KEIN
    automatisches Trimmen von Steuerzeichen (z.B. abschliessendes "\r\n"): wie core._routeros_text()
    lehnt diese Funktion einen unsauberen Wert komplett ab, statt ihn still zu bereinigen. Nur der
    exakt leere String (oder null) zaehlt als "Zuordnung entfernen", siehe Auftrag Phase B.
    Anfuehrungszeichen und andere JSON-Sonderzeichen sind unbedenklich, weil json.dump() sie
    korrekt maskiert -- kein Pfad- oder JSON-Injection-Risiko, da der Wert nie in einen Dateinamen
    oder unmaskiert in JSON-Text eingebaut wird.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("room")
    if value == "":
        return None
    if len(value.encode("utf-8")) > _ROOM_MAX_BYTES:
        raise ValueError("room")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("room")
    return value


def _device_rooms_file_for_current_router() -> str:
    # Gleiches Muster wie _backup_dir_for_current_router(): eigene Datei je Host+Port, damit
    # sich zwei verschiedene Router nicht gegenseitig die Raum-Zuordnung ueberschreiben. Der
    # Port fliesst mit ein (bereits als Ganzzahl 1-65535 validiert, siehe connect()), ein
    # Host mit demselben Namen aber anderem SSH-Port bekommt also eine eigene Datei.
    _ensure_private_dir(core.cfg.device_rooms_dir, DeviceRoomsStorageUnsafe)
    conn = core.current_conn()
    host = conn["host"]
    port = conn["ssh_port"]
    safe_host = re.sub(r"[^A-Za-z0-9.-]", "_", host) or "unbekannt"
    return os.path.join(core.cfg.device_rooms_dir, f"{safe_host}_{port}.json")


def _load_device_rooms(path: str) -> dict[str, str]:
    # Frisches/leeres Mapping darf nie abstuerzen: fehlende Datei, kaputtes JSON oder ein
    # unerwarteter Dateityp (Symlink) fuehren konservativ zu einem leeren Mapping statt zu
    # einem 500er. Der naechste Schreibvorgang ersetzt die Datei ohnehin atomar.
    if os.path.islink(path) or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        key.lower(): val
        for key, val in data.items()
        if isinstance(key, str) and isinstance(val, str) and val
    }


def _save_device_rooms(path: str, mapping: dict[str, str]) -> None:
    # Atomarer Schreibvorgang (Tempfile im selben Verzeichnis + os.replace): mehrere
    # gleichzeitige Browser-Tabs/Requests koennen sich noch gegenseitig ueberschreiben
    # (letzter Schreiber gewinnt, kein volles Locking gefordert), aber es bleibt nie eine
    # kaputte/halb geschriebene JSON-Datei zurueck, selbst wenn der Prozess mittendrin
    # abstuerzt.
    directory = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(prefix=".device-rooms-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(mapping, handle, ensure_ascii=False, sort_keys=True)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


@bp.get("/api/v1/backup")
def backup_list():
    backup_dir = _backup_dir_for_current_router()
    items = []
    for fname in sorted(os.listdir(backup_dir)):
        if not fname.endswith(".backup"):
            continue
        path = os.path.join(backup_dir, fname)
        items.append({
            "id": fname[: -len(".backup")],
            "created_at": datetime.fromtimestamp(os.path.getmtime(path)).astimezone().isoformat(),
            "size_kb": round(os.path.getsize(path) / 1024, 1),
        })
    return jsonify(items)


@bp.post("/api/v1/backup")
def backup_create():
    # Kollisionsschutz (Audit A13): Sekundengenauigkeit allein reichte bei parallelen
    # Anfragen nicht aus, deshalb zusaetzlich ein kurzes Zufallssuffix.
    backup_id = "bkp-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    core.router(f'/system backup save name="{backup_id}"')
    backup_dir = _backup_dir_for_current_router()
    local_path = os.path.join(backup_dir, f"{backup_id}.backup")
    conn = core.current_conn()
    download_file(
        conn["host"], conn["user"], conn["password"], conn["ssh_port"],
        f"{backup_id}.backup", local_path,
        known_hosts_path=core.cfg.known_hosts_path,
    )
    return jsonify({"id": backup_id, "created_at": datetime.now().astimezone().isoformat()}), 201


@bp.get("/api/v1/backup/<backup_id>/download")
def backup_download(backup_id: str):
    if not _BACKUP_ID_RE.match(backup_id):
        return jsonify({"error": "not_found", "message": "Backup unbekannt"}), 404
    backup_dir = _backup_dir_for_current_router()
    path = _resolve_backup_file(backup_dir, backup_id)
    if path is None:
        return jsonify({"error": "not_found", "message": "Backup unbekannt"}), 404
    return send_file(path, as_attachment=True, download_name=f"{backup_id}.backup")


@bp.post("/api/v1/backup/<backup_id>/restore")
def backup_restore(backup_id: str):
    # Audit A13-Rest: bisher gab es bewusst keinen Restore-Endpunkt (Risiko auf dem gemeinsam
    # genutzten Test-hAP zu hoch fuer einen unbeaufsichtigten Live-Test). Jetzt gebaut, aber mit
    # einer expliziten Bestaetigung -- "/system backup load" ueberschreibt die GESAMTE Konfiguration
    # und startet den Router sofort neu, ohne eine eigene Rueckfrage von RouterOS selbst.
    if not _BACKUP_ID_RE.match(backup_id):
        return jsonify({"error": "not_found", "message": "Backup unbekannt"}), 404
    body = request.get_json(force=True, silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({
            "error": "bad_request",
            "message": "Der Request-Body muss ein JSON-Objekt sein",
        }), 400
    if body.get("confirm") is not True:
        return jsonify({
            "error": "confirmation_required",
            "message": (
                "Eine Wiederherstellung ersetzt die komplette Konfiguration dieses Routers und "
                "startet ihn sofort neu. Zum Fortfahren 'confirm': true im Body mitschicken."
            ),
        }), 400
    backup_dir = _backup_dir_for_current_router()
    local_path = _resolve_backup_file(backup_dir, backup_id)
    if local_path is None:
        return jsonify({"error": "not_found", "message": "Backup unbekannt"}), 404
    conn = core.current_conn()
    upload_file(
        conn["host"], conn["user"], conn["password"], conn["ssh_port"],
        local_path, f"{backup_id}.backup",
        known_hosts_path=core.cfg.known_hosts_path,
    )
    # Live-Fund A13-Rest (09.09., Restore-Test): RouterOS 7.23.1 verlangt "password" als
    # Pflichtargument fuer "/system backup load", auch bei einem unverschluesselten Backup --
    # ohne den Parameter meldet RouterOS "Script Error: missing value(s) of argument(s)
    # password" mit Exitcode 0 und fuehrt den Restore NICHT aus. Leerer String ist das korrekte
    # "kein Passwort"-Signal, live verifiziert (Router startete danach tatsaechlich neu, Uptime
    # sprang von 23h auf 39s).
    core.router(f'/system backup load name="{backup_id}" password=""')
    return jsonify({"ok": True, "status": "restoring", "expect_reboot": True}), 202


# --- Sicherheits-Check (neu, 09.09.): fasst mehrere Einzelpruefungen, die es im Cockpit schon
# gibt, zu einer einzigen, verstaendlichen Kennzahl zusammen. Bewusst nur Pruefungen, die sich
# aus echtem Routerzustand ableiten lassen -- kein Check fuer "Standardpasswort geaendert" o.ae.,
# das RouterOS selbst nicht zuverlaessig beantworten kann. Ein einzelner fehlgeschlagener
# Teil-Check darf die ganze Auskunft nicht kippen, deshalb faengt jeder Block seine eigenen
# RouterOS-Fehler und meldet "unknown" statt den gesamten Endpunkt mit 502 abzubrechen.
def _security_check_service_hygiene() -> dict:
    try:
        rows = parse_terse(core.router("/ip service print terse where dynamic=no"))
    except (RouterCommandFailed, RouterUnreachable):
        return {"id": "services", "label": "Unsichere Klartext-Dienste", "status": "unknown",
                "detail": "Dienste konnten nicht gelesen werden.",
                "plain": "Konnte nicht geprüft werden, ob unsichere Altdienste wie Telnet oder "
                         "FTP an sind. Bitte später erneut prüfen."}
    risky = {row.get("name") for row in rows if row.get("name") in ("telnet", "ftp") and not row.get("disabled")}
    if risky:
        return {"id": "services", "label": "Unsichere Klartext-Dienste",
                "status": "warn", "detail": f"Noch aktiv: {', '.join(sorted(risky))}.",
                "plain": f"{', '.join(sorted(risky))} ist noch an - diese alten Dienste "
                         "übertragen Passwörter unverschlüsselt. Schalte sie unter "
                         "IP-Dienste aus, falls du sie nicht zwingend brauchst."}
    if not {"telnet", "ftp"}.issubset({row.get("name") for row in rows}):
        return {"id": "services", "label": "Unsichere Klartext-Dienste", "status": "unknown",
                "detail": "Status von Telnet und FTP konnte nicht vollständig gelesen werden.",
                "plain": "Der Status von Telnet und FTP konnte nicht vollständig gelesen "
                         "werden - keine verlässliche Aussage möglich."}
    return {"id": "services", "label": "Unsichere Klartext-Dienste", "status": "good",
            "detail": "Telnet und FTP sind deaktiviert.",
            "plain": "Telnet und FTP sind aus. Diese unsicheren Altdienste stellen kein "
                     "Risiko dar."}


def _blocks_unauthorized_input(row: dict) -> bool:
    """Ob eine Input-Regel tatsaechlich unbekannten Zugriff generell abweist.

    Audit Runde 5, 09.09.: die alte Pruefung zaehlte JEDE aktive drop/reject-Regel,
    auch die RouterOS-Standardregel "drop invalid" (nur ungueltige/kaputte Pakete, kein
    echter Zugriffsversuch) oder eine Regel mit engem Protokoll-/Port-Filter -- beide
    schuetzen nicht generell gegen unautorisierten Zugriff von aussen.
    """
    if row.get("disabled"):
        return False
    if row.get("action") not in ("drop", "reject"):
        return False
    conn_state = row.get("connection-state", "")
    if conn_state and "new" not in conn_state.split(","):
        # z.B. defconf "drop invalid" -- greift nur bei technisch kaputten Paketen,
        # nicht bei einem normalen, neuen Verbindungsversuch von aussen.
        return False
    if core._has_unresolved_matchers(row, {"in-interface", "in-interface-list", "connection-state"}):
        # Eng eingeschraenkte Regel (z.B. nur ein Port) deckt keinen generellen Schutz ab.
        return False
    return True


def _input_firewall_check(filter_path: str = "/ip firewall filter") -> tuple[bool | None, str]:
    """Prueft, ob die Input-Kette (chain=input) generell unautorisierten Zugriff sperrt.

    Extrahiert aus _security_check_input_firewall() (Audit "IPv6 Router-Selbstschutz",
    10.09.2026, RouterOS-Review), damit dieselbe Logik wahlweise auch gegen
    "/ipv6 firewall filter" laeuft -- eine global erreichbare IPv6-Adresse (z.B. per
    SLAAC/Prefix Delegation vom Provider, RouterOS-Default: IPv6-Stack aktiv) kann
    SSH/Winbox/API am Router offenlegen, selbst wenn IPv4 sauber gesperrt ist. Feldnamen
    von "/ipv6 firewall filter" live gegen den Test-hAP (10.09.2026) identisch zu IPv4
    bestaetigt, siehe auch core._guest_isolation()'s filter_path-Parameter vom selben Tag.

    True: aktive Sperrregel gefunden (good). False: nachweislich offen -- entweder eine
    allgemeine Freigabe vor jeder Sperre, oder das Kettenende ohne jede aktive Sperrregel
    (beides warn). None: vorgelagerte Freigaben/Sprungketten mit ungeklaerter Reichweite,
    oder die Kette selbst nicht lesbar (unknown).
    """
    try:
        rows = parse_terse(core.router(f'{filter_path} print terse where chain=input'))
    except (RouterCommandFailed, RouterUnreachable):
        return None, "Firewall-Regeln konnten nicht gelesen werden."
    # Eine vorherige allgemeine Freigabe beendet die Verarbeitung, bevor eine
    # spätere Sperre greifen kann. Eine solche Kette darf nie als geschützt gelten.
    metadata = {"chain", "action", "comment", "disabled", "running", "log", "log-prefix", ".id", "bytes", "packets"}
    for row in rows:
        if row.get("disabled"):
            continue
        if row.get("action") == "accept" and not any(
            value for key, value in row.items() if key not in metadata
        ):
            return False, "Eine allgemeine Freigabe steht vor einer wirksamen Zugriffssperre."
        if row.get("action") in ("accept", "jump", "return"):
            states = set(row.get("connection-state", "").split(","))
            if states and states <= {"established", "related", "untracked", "invalid"}:
                continue
            return None, "Vorgelagerte Freigaben oder Sprungketten benötigen eine vollständige Firewall-Prüfung."
        if _blocks_unauthorized_input(row):
            return True, "Eine aktive Sperrregel für unbekannten Zugriff ist vorhanden."
    return False, "Keine aktive, generell wirkende Drop/Reject-Regel in der Input-Kette gefunden."


def _security_check_input_firewall() -> dict:
    """Audit "IPv6 Router-Selbstschutz", 10.09.2026: Router-eigener Zugriffsschutz wurde bisher
    nur ueber IPv4 (chain=input) geprueft. Analog zur Gastnetz-Isolation vom selben Tag wird jetzt
    zusaetzlich "/ipv6 firewall filter" chain=input geprueft, wenn der IPv6-Stack aktiv ist
    (core._ipv6_relevant(), RouterOS-Default: aktiv). Gesamtstatus ist das jeweils schlechtere
    Ergebnis aus IPv4/IPv6 (warn > unknown > good) -- eine saubere IPv4-Sperre allein reicht nicht,
    wenn der Router zusaetzlich ueber eine globale IPv6-Adresse erreichbar ist."""
    result_v4, detail_v4 = _input_firewall_check()
    status = _isolation_status_label(result_v4)
    detail_parts = [f"IPv4: {detail_v4}"]

    try:
        ipv6_on = core._ipv6_relevant()
    except (RouterCommandFailed, RouterUnreachable):
        ipv6_on = None
    if ipv6_on is None:
        # Weder "sicher aktiv" noch "sicher aus" -- ein "good" allein auf Basis von IPv4
        # waere hier ein falsches Gruen, wenn IPv6 unbemerkt zusaetzlich offen waere.
        status = max(status, "unknown", key=_ISOLATION_SEVERITY.get)
        detail_parts.append("IPv6-Status konnte nicht ermittelt werden.")
    elif ipv6_on:
        result_v6, detail_v6 = _input_firewall_check(filter_path="/ipv6 firewall filter")
        status_v6 = _isolation_status_label(result_v6)
        detail_parts.append(f"IPv6: {detail_v6}")
        status = max(status, status_v6, key=_ISOLATION_SEVERITY.get)
    # sonst (ipv6_on is False): Stack deaktiviert oder Paket fehlt -- keine IPv6-Angriffsflaeche.

    plain = {
        "good": "Der Router blockt unbekannte Zugriffsversuche von außen - kein "
                "Handlungsbedarf.",
        "warn": "Der Router hat aktuell keine wirksame Sperre gegen unbekannte "
                "Zugriffsversuche von außen. Lege in der Firewall eine Regel an, die neue "
                "Verbindungen in der Input-Kette blockt, sofern sie nicht ausdrücklich "
                "erlaubt sein sollen.",
        "unknown": "Ob der Router gegen unbekannte Zugriffsversuche von außen geschützt ist, "
                   "konnte nicht abschließend geklärt werden. Das ist keine Bestätigung, dass "
                   "er sicher ist - bitte die Firewall-Regeln manuell prüfen.",
    }[status]
    return {"id": "input_firewall", "label": "Zugriffsschutz auf den Router", "status": status,
            "detail": " ".join(detail_parts), "plain": plain}


def _isolation_status_label(value: bool | None) -> str:
    if value is True:
        return "good"
    if value is False:
        return "warn"
    return "unknown"


_ISOLATION_SEVERITY = {"good": 0, "unknown": 1, "warn": 2}


def _security_check_guest_isolation() -> dict:
    """Audit "vollstaendige Firewall-/Gastnetz-Abnahme", 10.09.2026: schliesst die drei am
    09.09. dokumentierten Luecken (Listenmitgliedschaft -- in core._guest_isolation() selbst,
    Bridge-Paketpfad, IPv6). Reihenfolge: erst der Bridge-Blindspot (macht jede weitere
    Forward-Chain-Pruefung gegenstandslos, siehe core._guest_bridge_bypass()), dann IPv4, dann
    IPv6 falls relevant. "good" wird nur gemeldet, wenn KEINE der drei Pruefungen Zweifel
    hinterlaesst.

    Nachtrag "Bridge-Filter/VLAN-Isolation", 10.09.2026: bestaetigt der Bridge-Bypass die
    Blindstelle, wurde bisher pauschal "warn" gemeldet, obwohl ein Bridge-Firewall-Filter oder
    eine VLAN-Trennung die Luecke tatsaechlich schliessen KANN. Jetzt wird das aktiv geprueft
    (core._bridge_filter_isolation()/core._vlan_isolation()) -- nur bei einem positiven Nachweis
    wird daraus "good", sonst bleibt es bei "warn" (nie optimistischer als der bisherige Stand)."""
    interface = core.current_conn().get("guest_interface")
    if not interface:
        return {"id": "guest_isolation", "label": "Gastnetz-Isolation", "status": "unknown",
                "detail": "Kein Gastnetz-Interface für diese Sitzung ausgewählt.",
                "plain": "Für diese Sitzung ist kein Gastnetz ausgewählt - die Trennung zum "
                         "Hausnetz wurde nicht geprüft."}

    try:
        bridge_bypass = core._guest_bridge_bypass(interface)
    except (RouterCommandFailed, RouterUnreachable):
        bridge_bypass = None

    if bridge_bypass is True:
        bridge_name = None
        try:
            bridge_name = core._bridge_port_of(interface)
        except (RouterCommandFailed, RouterUnreachable):
            bridge_name = None
        filter_confirmed = vlan_confirmed = None
        if bridge_name:
            try:
                filter_confirmed = core._bridge_filter_isolation(interface, bridge_name)
            except (RouterCommandFailed, RouterUnreachable):
                filter_confirmed = None
            try:
                vlan_confirmed = core._vlan_isolation(interface, bridge_name)
            except (RouterCommandFailed, RouterUnreachable):
                vlan_confirmed = None
        if filter_confirmed is True or vlan_confirmed is True:
            proofs = []
            if filter_confirmed is True:
                proofs.append("eine aktive Bridge-Firewall-Filter-Regel (chain=forward) sperrt "
                               "den Verkehr zum Hausnetz")
            if vlan_confirmed is True:
                proofs.append("eine VLAN-Trennung hält das Gastnetz auf Layer 2 vom Hausnetz fern")
            return {"id": "guest_isolation", "label": "Gastnetz-Isolation", "status": "good",
                    "detail": ("Gastnetz und Hausnetz liegen auf derselben Bridge, "
                               "'use-ip-firewall' ist nicht aktiv, aber " + " und ".join(proofs)
                               + "."),
                    "plain": "Das Gastnetz ist vom Hausnetz getrennt. Auch wenn beide "
                             "technisch auf demselben Netzwerksegment liegen, verhindert eine "
                             "zusätzliche Regel den Zugriff aufs Hausnetz - kein "
                             "Handlungsbedarf."}
        return {"id": "guest_isolation", "label": "Gastnetz-Isolation", "status": "warn",
                "detail": ("Gastnetz und Hausnetz liegen auf derselben Bridge, 'use-ip-firewall' "
                           "ist nicht aktiv -- die IP-Firewall greift für diesen Verkehr gar "
                           "nicht, unabhängig von vorhandenen Regeln. Weder ein Bridge-Firewall-"
                           "Filter noch eine VLAN-Trennung konnten die Isolation nachweisen."),
                "plain": "Gastnetz und Hausnetz sind aktuell NICHT sauber getrennt - Geräte im "
                         "Gastnetz können möglicherweise auf dein Hausnetz zugreifen. Richte "
                         "eine Bridge-Firewall-Regel oder eine VLAN-Trennung für das "
                         "Gastnetz-Interface ein, oder trenne Gast- und Hausnetz auf "
                         "getrennte Netzwerkkarten/Bridges."}

    try:
        isolated_v4 = core._guest_isolation(interface)
    except (RouterCommandFailed, RouterUnreachable):
        return {"id": "guest_isolation", "label": "Gastnetz-Isolation", "status": "unknown",
                "detail": "Firewall-Regeln konnten nicht gelesen werden.",
                "plain": "Die Gastnetz-Isolation konnte nicht geprüft werden, weil die "
                         "Firewall-Regeln nicht gelesen werden konnten."}
    status_v4 = _isolation_status_label(isolated_v4)
    detail_parts = [{
        "good": "IPv4: aktive Drop-Regel vom Gastnetz ins Hausnetz nachgewiesen.",
        "warn": "IPv4: eine Accept-Regel erlaubt Zugriff vom Gastnetz ins Hausnetz.",
        "unknown": "IPv4: keine eindeutige Regel gefunden.",
    }[status_v4]]
    status = status_v4

    try:
        ipv6_on = core._ipv6_relevant()
    except (RouterCommandFailed, RouterUnreachable):
        ipv6_on = None
    if ipv6_on is None:
        # Weder "sicher aktiv" noch "sicher aus" -- ein "good" allein auf Basis von IPv4
        # waere hier ein falsches Gruen, wenn IPv6 unbemerkt zusaetzlich offen waere.
        status = max(status, "unknown", key=_ISOLATION_SEVERITY.get)
        detail_parts.append("IPv6-Status konnte nicht ermittelt werden.")
    elif ipv6_on:
        try:
            isolated_v6 = core._guest_isolation(interface, filter_path="/ipv6 firewall filter")
        except (RouterCommandFailed, RouterUnreachable):
            isolated_v6 = None
        status_v6 = _isolation_status_label(isolated_v6)
        detail_parts.append({
            "good": "IPv6: aktive Drop-Regel vom Gastnetz ins Hausnetz nachgewiesen.",
            "warn": "IPv6: eine Accept-Regel erlaubt Zugriff vom Gastnetz ins Hausnetz.",
            "unknown": "IPv6: aktiv, aber keine eindeutige Regel gefunden.",
        }[status_v6])
        status = max(status, status_v6, key=_ISOLATION_SEVERITY.get)
    # sonst (ipv6_on is False): Stack deaktiviert oder Paket fehlt -- keine IPv6-Angriffsflaeche.

    if bridge_bypass is None and status == "good":
        status = "unknown"
        detail_parts.append("Bridge-Zugehörigkeit konnte nicht geprüft werden.")

    plain = {
        "good": "Das Gastnetz ist vom Hausnetz getrennt - Geräte im Gastnetz kommen nicht "
                "ins Hausnetz.",
        "warn": "Geräte im Gastnetz können aktuell ins Hausnetz gelangen. Lege eine "
                "Firewall-Regel an, die Verkehr vom Gastnetz-Interface ins Hausnetz blockt "
                "(Forward-Kette, Aktion 'drop').",
        "unknown": "Es konnte nicht eindeutig geklärt werden, ob das Gastnetz vom Hausnetz "
                   "getrennt ist. Das ist keine Bestätigung der Sicherheit - bitte die "
                   "Firewall-Regeln manuell prüfen.",
    }[status]
    return {"id": "guest_isolation", "label": "Gastnetz-Isolation", "status": status,
            "detail": " ".join(detail_parts), "plain": plain}


def _security_check_firmware() -> dict:
    try:
        core.router("/system package update check-for-updates")
        info = parse_colon(core.router("/system package update print"))
    except (RouterCommandFailed, RouterUnreachable):
        return {"id": "firmware", "label": "Firmware aktuell", "status": "unknown",
                "detail": "Update-Status konnte nicht geprüft werden.",
                "plain": "Es konnte nicht geprüft werden, ob eine neue RouterOS-Version "
                         "verfügbar ist."}
    installed, latest = info.get("installed-version"), info.get("latest-version")
    # Audit Runde 5, 09.09.: fehlende Versionsdaten (z.B. Router hat noch nie erfolgreich
    # auf Updates geprueft) galten bisher faelschlich als "good" ("unbekannt ist die
    # aktuelle Version" -- ein inhaltlicher Widerspruch im eigenen Detailtext). Ohne
    # beide Werte laesst sich "aktuell" nicht belegen, also "unknown" statt "good".
    if not installed or not latest:
        return {"id": "firmware", "label": "Firmware aktuell", "status": "unknown",
                "detail": "Versionsdaten konnten nicht ermittelt werden.",
                "plain": "Es liegen keine vollständigen Versionsdaten vor - vermutlich hat "
                         "der Router noch nie erfolgreich nach Updates gesucht. Stoße unter "
                         "System eine Update-Prüfung an."}
    if installed != latest:
        return {"id": "firmware", "label": "Firmware aktuell", "status": "warn",
                "detail": f"{installed} installiert, {latest} verfügbar.",
                "plain": f"Eine neuere RouterOS-Version ({latest}) ist verfügbar, aktuell "
                         f"läuft {installed}. Plane ein Update ein, aktuelle Versionen "
                         "schließen bekannte Sicherheitslücken."}
    return {"id": "firmware", "label": "Firmware aktuell", "status": "good",
            "detail": f"{installed} ist die aktuelle Version.",
            "plain": f"RouterOS ist aktuell ({installed}) - kein Update nötig."}


def _security_check_backup() -> dict:
    try:
        backup_dir = _backup_dir_for_current_router()
        # Audit Runde 5, 09.09.: eine 0-Byte-Datei (z.B. abgebrochener/leerer Download)
        # galt bisher als gueltiges Backup. Nur Dateien mit tatsaechlichem Inhalt zaehlen.
        files = [
            f for f in os.listdir(backup_dir)
            if f.endswith(".backup") and os.path.getsize(os.path.join(backup_dir, f)) > 0
        ]
    except (OSError, BackupStorageUnsafe):
        # BackupStorageUnsafe (siehe _ensure_private_dir()) darf den gesamten Sicherheits-Check
        # nicht mit 500 abbrechen -- ein einzelner fehlgeschlagener Teil-Check meldet "unknown",
        # wie jeder andere Block hier auch (siehe Modulkommentar oben "_security_check_...").
        return {"id": "backup", "label": "Aktuelles Backup vorhanden", "status": "unknown",
                "detail": "Backup-Ordner konnte nicht gelesen werden.",
                "plain": "Der Backup-Ordner konnte nicht gelesen werden - es lässt sich "
                         "nicht sagen, ob ein aktuelles Backup vorliegt."}
    if not files:
        return {"id": "backup", "label": "Aktuelles Backup vorhanden", "status": "warn",
                "detail": "Noch kein gültiges Backup über das Cockpit erstellt.",
                "plain": "Es liegt noch kein Backup über das Cockpit vor. Erstelle jetzt "
                         "eines, damit du die Router-Konfiguration im Notfall "
                         "wiederherstellen kannst."}
    newest = max(os.path.getmtime(os.path.join(backup_dir, f)) for f in files)
    age_days = (datetime.now().timestamp() - newest) / 86400
    if age_days > 30:
        return {"id": "backup", "label": "Aktuelles Backup vorhanden", "status": "warn",
                "detail": f"Letztes Backup ist {int(age_days)} Tage alt.",
                "plain": f"Das letzte Backup ist {int(age_days)} Tage alt. Erstelle ein "
                         "neues, damit eine Wiederherstellung den aktuellen Stand trifft."}
    return {"id": "backup", "label": "Aktuelles Backup vorhanden", "status": "good",
            "detail": f"Letztes Backup ist {int(age_days)} Tag(e) alt.",
            "plain": f"Das letzte Backup ist {int(age_days)} Tag(e) alt - aktuell genug."}


def _security_check_default_user() -> dict:
    # Neu 18.09.2026: MikroTiks eigener Haertungsleitfaden (getting-started/securing-your-router)
    # beginnt mit "eigenen Benutzer anlegen, dann admin deaktivieren". Cockpit hat das bisher
    # weder geprueft noch angeboten. Der Fix selbst (Benutzer anlegen, admin abschalten) liegt in
    # der Pro-Benutzerverwaltung; die Pruefung gehoert zum Basis-Kernversprechen.
    label = "Standardbenutzer admin"
    try:
        users = core.list_users()
    except (RouterCommandFailed, RouterUnreachable):
        return {"id": "default_user", "label": label, "status": "unknown",
                "detail": "Benutzerliste konnte nicht gelesen werden.",
                "plain": "Konnte nicht geprüft werden, ob der Standardbenutzer admin noch aktiv "
                         "ist. Bitte später erneut prüfen."}
    if not users:
        return {"id": "default_user", "label": label, "status": "unknown",
                "detail": "Benutzerliste ist leer oder unlesbar.",
                "plain": "Die Benutzerliste des Routers war leer oder unlesbar - keine "
                         "verlässliche Aussage möglich."}
    admin = next((u for u in users if u["name"] == core.DEFAULT_ADMIN_USER), None)
    if admin is None or admin["disabled"]:
        return {"id": "default_user", "label": label, "status": "good",
                "detail": "admin ist deaktiviert oder entfernt.",
                "plain": "Der Standardbenutzer admin ist abgeschaltet. Angreifer müssen damit "
                         "auch den Benutzernamen raten, nicht nur das Passwort."}
    others = [u for u in core.active_full_users(users) if u["name"] != core.DEFAULT_ADMIN_USER]
    if not others:
        return {"id": "default_user", "label": label, "status": "warn",
                "detail": "admin ist aktiv und der einzige Vollzugang.",
                "plain": "Der Standardbenutzer admin ist aktiv und der einzige Vollzugang. Jeder "
                         "Angriff auf MikroTik-Router probiert diesen Namen zuerst. Lege einen eigenen "
                         "Vollzugang an (in Cockpit Pro unter Benutzer, sonst in WinBox unter "
                         "System > Users), melde dich einmal damit an und schalte admin danach ab."}
    return {"id": "default_user", "label": label, "status": "warn",
            "detail": "admin ist noch aktiv, obwohl ein eigener Vollzugang existiert.",
            "plain": "Ein eigener Vollzugang existiert bereits, admin ist aber noch aktiv. "
                     "Schalte admin ab (in Cockpit Pro unter Benutzer, sonst in WinBox unter "
                     "System > Users), sobald du dich mit dem eigenen Zugang einmal angemeldet hast."}


def _security_check_routerboard() -> dict:
    label = "RouterBOARD-Firmware"
    try:
        state = core.routerboard_state()
    except (RouterCommandFailed, RouterUnreachable):
        return {"id": "routerboard", "label": label, "status": "unknown",
                "detail": "RouterBOARD-Stand konnte nicht gelesen werden.",
                "plain": "Es konnte nicht geprüft werden, ob die RouterBOARD-Firmware zu RouterOS passt."}
    if not state.get("available"):
        return {"id": "routerboard", "label": label, "status": "unknown",
                "detail": "Kein RouterBOARD (z. B. CHR).",
                "plain": "Dieses Gerät hat keine RouterBOARD-Firmware, die Prüfung entfällt."}
    current, upgrade = state.get("current_firmware"), state.get("upgrade_firmware")
    if state["reboot_pending"]:
        return {"id": "routerboard", "label": label, "status": "warn",
                "detail": "Firmware eingespielt, Neustart fehlt.",
                "plain": "Die RouterBOARD-Firmware ist eingespielt, wird aber erst nach einem Neustart "
                         "aktiv. Starte den Router neu (in Cockpit Pro unter Wartung, sonst in WinBox "
                         "unter System > Reboot)."}
    if not current or not upgrade:
        return {"id": "routerboard", "label": label, "status": "unknown",
                "detail": "Versionsdaten der RouterBOARD-Firmware fehlen.",
                "plain": "Der Router nennt keine RouterBOARD-Firmwareversion, die Prüfung entfällt."}
    if state["upgrade_available"]:
        return {"id": "routerboard", "label": label, "status": "warn",
                "detail": f"{current} aktiv, {upgrade} bereit.",
                "plain": f"RouterOS ist aktualisiert, die RouterBOARD-Firmware (Schritt 2 eines Updates) "
                         f"noch nicht: {current} läuft, {upgrade} liegt bereit. Wende sie an und starte "
                         "neu (in Cockpit Pro unter Wartung > Firmware, sonst in WinBox unter System > "
                         "RouterBOARD > Upgrade, danach Neustart)."}
    return {"id": "routerboard", "label": label, "status": "good",
            "detail": f"{current} passt zu RouterOS.",
            "plain": f"Die RouterBOARD-Firmware ist auf dem Stand von RouterOS ({current}), Schritt 2 "
                     "des Updates ist erledigt."}


@bp.get("/api/v1/security-check")
def security_check():
    checks = [
        _security_check_service_hygiene(),
        _security_check_default_user(),
        _security_check_input_firewall(),
        _security_check_guest_isolation(),
        _security_check_firmware(),
        _security_check_routerboard(),
        _security_check_backup(),
    ]
    rated = [c for c in checks if c["status"] != "unknown"]
    good = sum(1 for c in rated if c["status"] == "good")
    score = round(100 * good / len(rated)) if rated else None
    return jsonify({"score": score, "checks": checks})


# Verifizierte IEEE-OUI-Praefixe (recherchiert 08.09.2026 gegen maclookup.app/netify.ai,
# nicht geraten). Allterco/Shelly hat KEIN eigenes OUI-Praefix in den geprueften Datenbanken --
# aeltere Shelly-Geraete (Gen1) und viele Tasmota/Sonoff-Geraete laufen aber auf Espressif-
# Modulen, daher deckt der Espressif-Eintrag einen Teil davon ab, ohne "Shelly" zu behaupten.
KNOWN_OUI_VENDORS = {
    "24:0a:c4": ("Espressif-Modul (z.B. aeltere Shelly Gen1, Tasmota, Sonoff)", 80, "http"),
    "18:fe:34": ("Espressif-Modul (z.B. aeltere Shelly Gen1, Tasmota, Sonoff)", 80, "http"),
    "1a:fe:34": ("Espressif-Modul (z.B. aeltere Shelly Gen1, Tasmota, Sonoff)", 80, "http"),
    "4c:bd:8f": ("Hikvision", 80, "http"),
    "2c:a5:9c": ("Hikvision", 80, "http"),
    "ec:71:db": ("Reolink", 80, "http"),
    "00:11:32": ("Synology", 5000, "http"),
    "90:09:d0": ("Synology", 5000, "http"),
    "24:5e:be": ("QNAP", 8080, "http"),
    "e8:43:b6": ("QNAP", 8080, "http"),
    "64:4e:d7": ("HP Drucker", 80, "http"),
    "00:1b:a9": ("Brother Drucker", 80, "http"),
    "3c:2a:f4": ("Brother Drucker", 80, "http"),
    "b4:22:00": ("Brother Drucker", 80, "http"),
    "00:80:77": ("Brother Drucker", 80, "http"),
    "74:bf:c0": ("Canon Drucker", 80, "http"),
    "84:ba:3b": ("Canon Drucker", 80, "http"),
    "00:30:c4": ("Canon Imaging Systems Drucker", 80, "http"),
}


@bp.get("/api/v1/devices/<mac>/webui-suggestion")
def webui_suggestion(mac: str):
    prefix = mac.lower().replace("-", ":")[:8]
    match = KNOWN_OUI_VENDORS.get(prefix)
    if not match:
        return jsonify({"suggested": False})
    vendor, port, scheme = match
    return jsonify({"suggested": True, "vendor": vendor, "default_port": port, "default_scheme": scheme})


_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


@bp.put("/api/v1/devices/<mac>/reservation")
def device_reservation(mac: str):
    body = request.get_json(force=True, silent=True) or {}
    ip = body.get("ip")
    has_webui = body.get("has_webui", False)
    webui_port = body.get("webui_port")
    webui_scheme = body.get("webui_scheme", "http")
    if not _MAC_RE.match(mac or ""):
        return jsonify({"error": "bad_request", "message": "'mac' ungueltig"}), 400
    if not core._valid_ipv4(ip):
        return jsonify({"error": "bad_request", "message": "'ip' fehlt oder ungueltig"}), 400
    if webui_scheme not in ("http", "https"):
        return jsonify({"error": "bad_request", "message": "'webui_scheme' muss http oder https sein"}), 400
    if has_webui and not _valid_single_port(webui_port):
        return jsonify({"error": "bad_request", "message": "'webui_port' muss 1-65535 sein"}), 400
    safe_mac = mac.lower()

    ip_owner = parse_terse(core.router(f'/ip dhcp-server lease print terse where address="{ip}"'))
    if ip_owner and ip_owner[0].get("mac-address", "").lower() != safe_mac:
        return jsonify({"error": "ip_in_use", "message": "IP bereits vergeben"}), 409

    lease = parse_terse(core.router(f'/ip dhcp-server lease print terse where mac-address="{safe_mac}"'))
    if not lease:
        return jsonify({
            "error": "device_not_found",
            "message": "Kein bekannter DHCP-Lease fuer diese MAC -- Geraet muss vorher online gewesen sein",
        }), 404
    server = core._routeros_value(lease[0].get("server", ""), "server")
    old_address = lease[0].get("address", "")

    comment = f"cockpit-webui:{webui_scheme}:{webui_port}" if has_webui else ""

    # Reihenfolge bewusst: ERST die neue statische Lease anlegen, DANACH die alte entfernen
    # (Audit A10, 09.09.: umgekehrte Reihenfolge konnte bei einem Fehler beim Anlegen die
    # bestehende, funktionierende Lease ersatzlos loeschen). Schlaegt das Anlegen fehl, bleibt
    # die alte Lease unangetastet -- run_command() wirft bei einem SSH/Exitcode-Fehler eine
    # Exception, die vor dem "remove" abbricht. Entfernt wird gezielt ueber die ALTE Adresse,
    # nicht per mac-address allein -- sonst wuerde nach erfolgreichem Anlegen auch der gerade
    # neu erstellte Eintrag mitgeloescht, weil beide dieselbe MAC tragen.
    core.router(
        f'/ip dhcp-server lease add mac-address={safe_mac} address={ip} server={server} '
        f'comment="{comment}"'
    )
    if old_address and old_address != ip:
        core.router(f'/ip dhcp-server lease remove [find mac-address="{safe_mac}" and address="{old_address}"]')
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Netzwerk-Grundeinstellungen (dem API-Vertrag, Abschnitt 10-12) -- 08.09. spaet abends,
# Erweiterung: eigene IP-Adresse, DNS, DHCP-Client, DHCP-Bereiche je VLAN,
# eine kompakte Leases-Uebersicht.
# ---------------------------------------------------------------------------

def _list_leases() -> list[dict]:
    leases = parse_terse(core.router("/ip dhcp-server lease print terse"))
    result = []
    for row in leases:
        result.append({
            "mac": row.get("mac-address", "").lower(),
            "ip": row.get("address"),
            "hostname": row.get("host-name"),
            "active": row.get("status") == "bound",
            "network": row.get("server"),
        })
    return result


@bp.get("/api/v1/network")
def network_get():
    addresses = [
        {"interface": row.get("interface"), "address": row.get("address")}
        for row in parse_terse(core.router("/ip address print terse"))
    ]
    # Live am 08.09. gefunden: "/ip dns print" bricht mehrere Server ueber Folgezeilen um
    # (ohne "servers:"-Praefix), parse_colon() liest dann nur den ersten. Gezielte Feldabfrage
    # umgeht das -- RouterOS trennt hier intern mit Semikolon, nicht mit Komma.
    dns_raw = core.router(":put [/ip dns get servers]").strip()
    dns_servers = [s.strip() for s in dns_raw.split(";") if s.strip()]
    dhcp_clients = [
        {"interface": row.get("interface"), "status": row.get("status"), "address": row.get("address")}
        for row in parse_terse(core.router("/ip dhcp-client print terse"))
    ]
    return jsonify({"addresses": addresses, "dns_servers": dns_servers, "dhcp_clients": dhcp_clients})


@bp.put("/api/v1/network/ip-address/<interface>")
def network_ip_address_put(interface: str):
    body = request.get_json(force=True, silent=True) or {}
    address = body.get("address", "")
    if not core._valid_ipv4_cidr(address):
        return jsonify({
            "error": "invalid_address",
            "message": "Adresse muss im Format 192.168.1.1/24 angegeben werden",
        }), 400
    try:
        safe_interface = core._routeros_value(interface, "interface")
    except ValueError:
        return jsonify({"error": "device_not_found", "message": "Interface unbekannt"}), 404

    existing = parse_terse(core.router(f'/ip address print terse where interface="{safe_interface}"'))
    # Audit A11, 09.09.: "set [find interface=X]" trifft bei MEHREREN Adressen auf demselben
    # Interface alle davon gleichzeitig -- die Oberfläche zeigt aber nur eine einzelne Adresse
    # an. Statt stillschweigend alle zu ueberschreiben: bei mehr als einer bestehenden Adresse
    # klar ablehnen, das kann dieses Formular (eine Adresse pro Interface) nicht sicher aufloesen.
    if len(existing) > 1:
        return jsonify({
            "error": "multiple_addresses",
            "message": "Dieses Interface hat mehrere IP-Adressen -- das kann hier nicht sicher geändert werden",
        }), 409
    if existing:
        core.router(f'/ip address set [find interface="{safe_interface}"] address="{address}"')
    else:
        core.router(f'/ip address add interface="{safe_interface}" address="{address}"')
    return jsonify({"ok": True, "interface": interface, "address": address})


@bp.put("/api/v1/network/dns")
def network_dns_put():
    body = request.get_json(force=True, silent=True) or {}
    servers = body.get("servers")
    if not isinstance(servers, list) or not (1 <= len(servers) <= 3) or not all(
        isinstance(s, str) and core._valid_ipv4(s) for s in servers
    ):
        return jsonify({
            "error": "invalid_dns",
            "message": "1 bis 3 gueltige IPv4-Adressen erwartet",
        }), 400
    core.router(f'/ip dns set servers="{",".join(servers)}"')
    return jsonify({"ok": True, "dns_servers": servers})


@bp.post("/api/v1/network/dhcp-client")
def network_dhcp_client_create():
    body = request.get_json(force=True, silent=True) or {}
    try:
        safe_interface = core._routeros_value(body.get("interface", ""), "interface")
    except ValueError:
        return jsonify({"error": "bad_request", "message": "'interface' fehlt oder ungueltig"}), 400

    existing = parse_terse(core.router(f'/ip dhcp-client print terse where interface="{safe_interface}"'))
    if existing:
        return jsonify({
            "error": "dhcp_client_exists",
            "message": "Fuer dieses Interface laeuft bereits ein DHCP-Client",
        }), 409
    core.router(f'/ip dhcp-client add interface="{safe_interface}" disabled=no')
    return jsonify({"ok": True, "interface": safe_interface}), 201


@bp.delete("/api/v1/network/dhcp-client/<interface>")
def network_dhcp_client_delete(interface: str):
    # Audit B02, 09.09.: "interface" kam roh aus dem URL-Pfad ohne die uebliche
    # core._routeros_value()-Pruefung direkt in den Router-Befehl -- live als Command Injection
    # bestaetigt. Escaping jetzt wie bei jedem anderen Interface-Namen im Projekt.
    try:
        safe_interface = core._routeros_value(interface, "interface")
    except ValueError:
        return jsonify({"error": "not_found", "message": "Kein DHCP-Client fuer dieses Interface"}), 404
    rows = parse_terse(core.router(f'/ip dhcp-client print terse where interface="{safe_interface}"'))
    if not rows:
        return jsonify({"error": "not_found", "message": "Kein DHCP-Client fuer dieses Interface"}), 404
    core.router(f'/ip dhcp-client remove [find interface="{safe_interface}"]')
    return jsonify({"ok": True})


def _dhcp_comment(range_id: str, interface: str) -> str:
    return f"cockpit-dhcp:{range_id}:{interface}"


def _dhcp_server_name(range_id: str) -> str:
    return f"cockpit-dhcp-{range_id}"


@bp.get("/api/v1/network/dhcp-ranges")
def dhcp_ranges_list():
    # Live am 08.09. gefunden: RouterOS haengt einem DHCP-Server-Kommentar je nach
    # Interface-Zustand eigenen Text VOR ("Interface not running,cockpit-dhcp:...") und
    # laesst ihn dabei UNQUOTIERT, obwohl er Leerzeichen enthaelt -- parse_terse() bricht
    # den Wert dadurch schon bei der ersten Leerstelle ab ("comment" wird nur "Interface").
    # Deshalb ueber den selbst vergebenen, eindeutigen NAMEN suchen statt ueber den
    # Kommentar -- der Name enthaelt nie Leerzeichen und wird nie von RouterOS veraendert.
    servers = parse_terse(core.router('/ip dhcp-server print terse where name~"^cockpit-dhcp-"'))
    result = []
    for srv in servers:
        name = srv.get("name", "")
        if not name.startswith("cockpit-dhcp-"):
            continue
        range_id = name[len("cockpit-dhcp-"):]
        interface = srv.get("interface")
        pool_rows = parse_terse(
            core.router(f'/ip pool print terse where name="{srv.get("address-pool")}"')
        )
        range_start, range_end = None, None
        if pool_rows:
            ranges = pool_rows[0].get("ranges", "")
            if "-" in ranges:
                range_start, range_end = ranges.split("-", 1)
        net_rows = parse_terse(
            core.router(f'/ip dhcp-server network print terse where comment~"{_dhcp_comment(range_id, interface)}"')
        )
        network = net_rows[0].get("address") if net_rows else None
        gateway = net_rows[0].get("gateway") if net_rows else None
        dns_raw = net_rows[0].get("dns-server", "") if net_rows else ""
        result.append({
            "id": range_id, "interface": interface, "network": network,
            "range_start": range_start, "range_end": range_end,
            "gateway": gateway, "dns_servers": [s for s in dns_raw.split(",") if s],
            "lease_time": srv.get("lease-time"),
        })
    return jsonify(result)


@bp.post("/api/v1/network/dhcp-ranges")
def dhcp_ranges_create():
    with core._router_create_lock():
        return _dhcp_ranges_create()


def _dhcp_ranges_create():
    body = request.get_json(force=True, silent=True) or {}
    try:
        safe_interface = core._routeros_value(body.get("interface", ""), "interface")
    except ValueError:
        return jsonify({"error": "bad_request", "message": "'interface' fehlt oder ungueltig"}), 400
    network = body.get("network", "")
    range_start = body.get("range_start", "")
    range_end = body.get("range_end", "")
    if not core._valid_ipv4_cidr(network) or not core._valid_ipv4(range_start) or not core._valid_ipv4(range_end):
        return jsonify({
            "error": "bad_request",
            "message": "'network' (CIDR), 'range_start' und 'range_end' muessen gueltig sein",
        }), 400

    # RouterOS akzeptiert einen Pool auch dann, wenn seine Grenzen nicht zum
    # angegebenen DHCP-Netz passen. Vor dem ersten Schreibbefehl deshalb die
    # gesamte Beziehung im Backend prüfen.
    dhcp_network = ipaddress.IPv4Interface(network).network
    pool_start = ipaddress.IPv4Address(range_start)
    pool_end = ipaddress.IPv4Address(range_end)
    if pool_start > pool_end:
        return jsonify({
            "error": "invalid_range",
            "message": "'range_start' muss kleiner oder gleich 'range_end' sein",
        }), 400
    if any(address not in dhcp_network for address in (pool_start, pool_end)):
        return jsonify({
            "error": "range_outside_network",
            "message": "Der DHCP-Bereich muss vollständig innerhalb des angegebenen Netzes liegen",
        }), 400
    if pool_start == dhcp_network.network_address or pool_end == dhcp_network.broadcast_address:
        return jsonify({
            "error": "invalid_range",
            "message": "Netz- und Broadcastadresse dürfen nicht im DHCP-Bereich liegen",
        }), 400

    existing = parse_terse(
        core.router(f'/ip dhcp-server print terse where interface="{safe_interface}"')
    )
    if existing:
        return jsonify({
            "error": "range_exists",
            "message": "Fuer dieses Interface existiert bereits ein DHCP-Bereich",
        }), 409

    iface_addr = parse_terse(core.router(f'/ip address print terse where interface="{safe_interface}"'))
    if not iface_addr:
        return jsonify({
            "error": "interface_no_address",
            "message": "Das Interface braucht zuerst eine eigene IP-Adresse (siehe Netzwerk-Bereich)",
        }), 400
    own_ip = iface_addr[0].get("address", "").split("/")[0]

    # Audit Runde 5, 09.09.: Ein Bereich, der die eigene Adresse des Routers auf diesem
    # Interface enthaelt, erzeugt einen sofortigen IP-Konflikt mit dem ersten per DHCP
    # versorgten Client. Diese Pruefung greift unabhaengig davon, ob "gateway" im Body
    # explizit mitgeschickt wurde oder (wie unten) auf own_ip zurueckfaellt.
    if pool_start <= ipaddress.IPv4Address(own_ip) <= pool_end:
        return jsonify({
            "error": "range_conflicts_with_router",
            "message": (
                "Der DHCP-Bereich darf die eigene IP-Adresse des Routers auf diesem "
                f"Interface ({own_ip}) nicht enthalten -- das erzeugt einen Adresskonflikt "
                "mit einem per DHCP versorgten Client."
            ),
        }), 400

    gateway = body.get("gateway") or own_ip
    dns_servers = body.get("dns_servers") or [own_ip]
    if not core._valid_ipv4(gateway) or not all(core._valid_ipv4(s) for s in dns_servers):
        return jsonify({"error": "bad_request", "message": "'gateway'/'dns_servers' ungueltig"}), 400
    gateway_ip = ipaddress.IPv4Address(gateway)
    if gateway_ip not in dhcp_network or gateway_ip in {
        dhcp_network.network_address, dhcp_network.broadcast_address,
    } or pool_start <= gateway_ip <= pool_end:
        return jsonify({
            "error": "invalid_gateway",
            "message": (
                "Das Gateway muss eine nutzbare Adresse im angegebenen Netz sein und darf "
                "nicht im DHCP-Bereich selbst liegen"
            ),
        }), 400

    range_id = "dhcp-" + uuid.uuid4().hex[:8]
    comment = _dhcp_comment(range_id, safe_interface)
    pool_name = f"cockpit-dhcp-pool-{range_id}"
    dhcp_server_name = f"cockpit-dhcp-{range_id}"

    core.router(f'/ip pool add name="{pool_name}" ranges="{range_start}-{range_end}"')
    try:
        core.router(
            f'/ip dhcp-server add name="{dhcp_server_name}" interface="{safe_interface}" '
            f'address-pool="{pool_name}" disabled=no comment="{comment}"'
        )
    except Exception:
        # Rueckbau: schlaegt das Anlegen des DHCP-Servers fehl, darf kein verwaister,
        # unbenutzter Pool zurueckbleiben (gleiches Muster wie bei port_forwards_create).
        core.router(f'/ip pool remove [find name="{pool_name}"]')
        raise
    try:
        core.router(
            f'/ip dhcp-server network add address="{network}" gateway="{gateway}" '
            f'dns-server="{",".join(dns_servers)}" comment="{comment}"'
        )
    except Exception:
        # Rueckbau: schlaegt der letzte Schritt fehl, duerfen weder DHCP-Server noch Pool
        # zurueckbleiben -- sonst ein "silent partial state" wie in fruehren Audits.
        core.router(f'/ip dhcp-server remove [find name="{dhcp_server_name}"]')
        core.router(f'/ip pool remove [find name="{pool_name}"]')
        raise
    return jsonify({
        "id": range_id, "interface": safe_interface, "network": network,
        "range_start": range_start, "range_end": range_end,
        "gateway": gateway, "dns_servers": dns_servers,
    }), 201


_DHCP_RANGE_ID_RE = re.compile(r"^dhcp-[0-9a-f]{8}$")


@bp.delete("/api/v1/network/dhcp-ranges/<range_id>")
def dhcp_ranges_delete(range_id: str):
    # Audit B03, 09.09.: "range_id" kam roh aus dem URL-Pfad in den ersten Router-Befehl, ohne
    # das Format zu pruefen, das dhcp_ranges_create() selbst erzeugt ("dhcp-" + 8 Hex-Zeichen) --
    # live als Command Injection bestaetigt. Gleiches Muster wie bei _PF_ID_RE/_BACKUP_ID_RE.
    if not _DHCP_RANGE_ID_RE.match(range_id):
        return jsonify({"error": "not_found", "message": "DHCP-Bereich unbekannt"}), 404
    # Ueber den Namen finden, nicht den Kommentar -- siehe Begruendung in dhcp_ranges_list().
    dhcp_server_name = _dhcp_server_name(range_id)
    servers = parse_terse(core.router(f'/ip dhcp-server print terse where name="{dhcp_server_name}"'))
    if not servers:
        return jsonify({"error": "not_found", "message": "DHCP-Bereich unbekannt"}), 404
    pool_name = servers[0].get("address-pool")

    # Netzwerk-Eintrag hat keinen eigenen Namen -- dessen Kommentar bleibt aber unveraendert
    # von RouterOS (kein Interface-Status-Praefix dort), Substring-Suche reicht hier sicher.
    core.router(f'/ip dhcp-server network remove [find comment~"cockpit-dhcp:{range_id}:"]')
    core.router(f'/ip dhcp-server remove [find name="{dhcp_server_name}"]')
    if pool_name:
        core.router(f'/ip pool remove [find name="{pool_name}"]')
    return jsonify({"ok": True})


@bp.get("/api/v1/network/dhcp-leases")
def dhcp_leases_get():
    return jsonify(_list_leases())
