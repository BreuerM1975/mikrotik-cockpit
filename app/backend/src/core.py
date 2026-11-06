"""Geteilte Helfer fuer mikrotik-cockpit: RouterOS-Verbindung, Session-Verwaltung,
Escaping/Validierung, sowie die einzige Stelle, an der Basis- UND Pro-Routen gemeinsam
zugreifen muessen (siehe Projektnotizen).

Nichts Feature-Spezifisches: dieses Modul kennt weder Basis- noch Pro-Routen, nur
Bausteine, die beide brauchen. `routes_basis.py`/`routes_pro.py` rufen alles hier
IMMER ueber `core.<name>(...)` auf (dotted access), nie per `from core import <name>` --
nur so patchen Tests einheitlich gegen `core.<name>`, unabhaengig davon, welches
Blueprint den Aufruf tatsaechlich ausloest (sonst wuerde ein `from core import router`
in routes_basis.py eine eigene, zur Testzeit nicht mehr patchbare Kopie binden).

Grenzfall, dokumentiert in den Projektnotizen: mehrere Funktionen hier sind eigentlich nur fuer
EINE Seite "gedacht" (z.B. die Gastnetz-Isolationspruefung fuer die Pro-Route
`/guest-network`), werden aber zusaetzlich vom Basis-Endpunkt `/security-check`
gebraucht (Gastnetz-Isolation ist Teil des Sicherheits-Scores, der laut Tabelle
Basis ist). Deshalb leben sie hier statt in `routes_pro.py`, obwohl die Tabelle sie
nicht explizit als "geteilt" auffuehrt.
"""

import contextlib
import ipaddress
import json
import os
import re
import threading
import time

from flask import request

from config import load_config
from routeros import (
    FLAG_I,
    REGEL_UNKLAR,
    RouterCommandFailed,
    RouterTimeout,
    RouterUnreachable,
    close_connection,
    parse_colon,
    parse_regeln,
    parse_terse,
    run_command,
    terse_flags,
)

cfg = load_config()

# Verbinden-Modell wie WinBox (siehe das Verbinden-Modell): keine fest
# konfigurierte Route mehr, sondern eine aktive Verbindung pro Sitzung. Lebt nur im
# Arbeitsspeicher dieses Prozesses -- ein Neustart des Diensts beendet jede Sitzung,
# genau wie das Schliessen von WinBox eine Verbindung beendet.
SESSIONS: dict[str, dict] = {}
_sessions_lock = threading.Lock()
# Begrenzter Lock-Pool: dieselbe Routeradresse samt SSH-Port wird immer
# serialisiert, ohne mit jeder Verbindung neue Lock-Objekte anzusammeln. Wird sowohl
# von Basis-Endpunkten (Portweiterleitung, DHCP-Bereiche) als auch von Pro-Endpunkten
# (Firewall-Create) verwendet -- deshalb hier und nicht in einer der beiden Routendateien.
_router_create_locks = [threading.RLock() for _ in range(64)]


def _router_create_lock():
    conn = current_conn()
    key = (conn["host"].strip().lower(), int(conn["ssh_port"]))
    return _router_create_locks[hash(key) % len(_router_create_locks)]


try:
    SESSION_IDLE_TIMEOUT_SECONDS = int(os.environ.get("COCKPIT_SESSION_IDLE_TIMEOUT", str(8 * 60 * 60)))
except ValueError:
    SESSION_IDLE_TIMEOUT_SECONDS = 8 * 60 * 60
EXEMPT_API_PATHS = {"/api/v1/connect", "/api/v1/disconnect"}

# Obergrenze gleichzeitig verbundener Geraete. Jede Sitzung haelt die Zugangsdaten ihres
# Routers im Arbeitsspeicher und eine SSH-Master-Verbindung offen -- ohne Grenze koennte ein
# fehlerhaftes Skript gegen /connect unbegrenzt viele davon anlegen. Es ist dieselbe Zahl,
# die die Oberflaeche (MAX_ROUTERS) und die Flottenabfrage verwenden; sie steht hier, damit
# es nur eine gibt.
MAX_SESSIONS = 16


class SessionGone(Exception):
    """Die Sitzung war bei der Vorpruefung noch da und ist beim Routerzugriff weg."""


# Die Flottenabfrage spricht mehrere Geraete nebenlaeufig an. In einem Arbeitsthread gibt es
# keinen Flask-Request, aus dem current_conn() die Sitzung lesen koennte -- und es waere auch
# die falsche, denn jeder Thread meint ein anderes Geraet. Mit dieser Bindung arbeiten alle
# bestehenden Pruefungen (Sicherheits-Check, Firmware, Status) unveraendert weiter, nur eben
# gegen das Geraet dieses Threads. Dasselbe Prinzip wie der state-Proxy in der Oberflaeche.
_bound_conn = threading.local()


@contextlib.contextmanager
def use_connection(conn: dict):
    previous = getattr(_bound_conn, "conn", None)
    _bound_conn.conn = conn
    try:
        yield conn
    finally:
        _bound_conn.conn = previous


def master_shared_with_other_session(conn: dict) -> bool:
    """Teilt eine andere noch offene Sitzung den Kontrollsocket dieses Geraets?

    Zwei Sitzungen auf dasselbe Geraet mit demselben Benutzer benutzen dieselbe
    SSH-Master-Verbindung. Ein "ssh -O exit" fuer die eine wuerde der anderen die Verbindung
    unter den Fuessen wegziehen. Nur unter _sessions_lock aufrufen.
    """
    return any(
        other["host"] == conn["host"]
        and other["user"] == conn["user"]
        and int(other["ssh_port"]) == int(conn["ssh_port"])
        for other in SESSIONS.values()
    )


def purge_expired_sessions() -> list[dict]:
    """Entfernt Sitzungen, die ueber das Leerlauf-Zeitfenster hinaus nicht benutzt wurden.

    Der Ablauf einer Sitzung fiel bisher erst auf, wenn sie jemand anspricht (siehe
    require_session in app.py) -- und genau das tut eine abgelaufene Sitzung nie wieder. Mit
    einer Obergrenze gleichzeitiger Sitzungen ist das nicht mehr nur unschoen: 16 vergessene
    Sitzungen wuerden den Platz dauerhaft blockieren, obwohl keine davon noch benutzt wird.
    Ihre Master-Verbindung geht mit, sonst bleibt am Router eine Sitzung offen, zu der es im
    Cockpit keine Oberflaeche mehr gibt.
    """
    now = time.monotonic()
    with _sessions_lock:
        gone = [
            session_id for session_id, conn in SESSIONS.items()
            if now - conn.get("last_activity", now) > SESSION_IDLE_TIMEOUT_SECONDS
        ]
        dropped = [SESSIONS.pop(session_id) for session_id in gone]
        # Je Kontrollsocket hoechstens ein "ssh -O exit": zwei abgelaufene Sitzungen auf
        # dasselbe Geraet teilen ihn, und nach dem ersten Aufruf ist er ohnehin weg.
        orphaned, seen = [], set()
        for conn in dropped:
            key = (conn["host"], conn["user"], int(conn["ssh_port"]))
            if key in seen or master_shared_with_other_session(conn):
                continue
            seen.add(key)
            orphaned.append(conn)
    # Bewusst ausserhalb des Locks: jeder Aufruf startet einen Unterprozess, und solange er
    # laeuft, sollen andere Anfragen nicht auf die Sitzungsverwaltung warten muessen.
    for conn in orphaned:
        close_connection(conn["host"], conn["user"], int(conn["ssh_port"]))
    return dropped


def current_conn() -> dict:
    bound = getattr(_bound_conn, "conn", None)
    if bound is not None:
        return bound
    # Zwischen require_session() und diesem Zugriff kann ein /disconnect liegen. Mit mehreren
    # gleichzeitig verbundenen Geraeten ist das kein Sonderfall mehr, sondern der Normalfall:
    # wird ein Geraet getrennt, waehrend seine Abfragen noch laufen, findet die laufende
    # Anfrage ihre Sitzung nicht mehr. Bis zum 17.10. war das ein KeyError und damit ein
    # HTTP 500 mit Stacktrace -- es ist aber dieselbe Lage wie eine abgelaufene Sitzung, und
    # genau die kennt die Oberflaeche als "not_connected" und raeumt sie sauber ab.
    try:
        return SESSIONS[request.headers["X-Cockpit-Session"]]
    except KeyError as exc:
        raise SessionGone() from exc


def router(command: str) -> str:
    conn = current_conn()
    return run_command(
        conn["host"], conn["user"], conn["password"], conn["ssh_port"], command,
        known_hosts_path=cfg.known_hosts_path,
    )


def _routeros_escape(value: str) -> str:
    # Reihenfolge wichtig: erst Backslashes verdoppeln, dann Dollarzeichen maskieren --
    # sonst wird ein bereits maskiertes "\$" versehentlich nochmal angefasst. Live am
    # 09.09. gegen den hAP bestaetigt (Audit A02): RouterOS interpretiert ein unmaskiertes
    # "$" in Strings als Variablenreferenz und ersetzt es stillschweigend durch deren Wert
    # (meist leer) -- kein Fehler, einfach ein anderer, verstuemmelter Wert. Betrifft vor
    # allem Passwoerter: der Router speichert dann einen anderen Wert als Cockpit denkt.
    return value.replace("\\", "\\\\").replace("$", "\\$")


def _routeros_value(value: str, field: str, maximum: int = 64) -> str:
    # Abschlussrunde, 10.09.2026: Steuerzeichen (ord<32, z.B. Tab/NUL/ESC) wurden bisher nur
    # ueber ein paar einzelne, an mehreren Aufrufstellen VERSCHIEDEN dupliziertes Vorab-Pruefungen
    # abgefangen. Jetzt zentral hier, damit jeder Aufrufer automatisch geschuetzt ist, ohne sich
    # an eine eigene Vorab-Pruefung erinnern zu muessen.
    if (
        not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum
        or any(ord(char) < 32 or ord(char) == 127 or char in '\r\n;"' for char in value)
    ):
        raise ValueError(field)
    return _routeros_escape(value)


def _routeros_text(value: str, field: str, maximum: int = 128) -> str:
    # Gleiche Haertung wie _routeros_value(), siehe Kommentar dort.
    if (
        not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum
        or any(ord(char) < 32 or ord(char) == 127 or char in '\r\n;"' for char in value)
    ):
        raise ValueError(field)
    return _routeros_escape(value)


def _routeros_ascii(value: str, field: str, maximum: int = 128) -> str:
    # 18.09.2026, live am hAP (RouterOS 7.23.1) bestaetigt: ueber den SSH-Exec-Kanal wirft
    # RouterOS Nicht-ASCII-Bytes STILL aus Stringliteralen (`:put [:len "ä"]` = 0). Ein Passwort
    # mit Umlaut landet also ohne Umlaut auf dem Router, Cockpit merkt sich aber den Wert mit
    # Umlaut -- der naechste Befehl scheitert mit 401, der Undo ebenfalls, der Kunde kennt sein
    # echtes Passwort nicht. Deshalb fuer Passwoerter und Benutzernamen nur druckbares ASCII
    # (32 bis 126), zusaetzlich ohne `;` und `"` wie in _routeros_text().
    if (
        not isinstance(value, str) or not value or len(value) > maximum
        or any(not 32 <= ord(char) <= 126 or char in ';"' for char in value)
    ):
        raise ValueError(field)
    return _routeros_escape(value)


# RouterOS-Standardgruppen plus die von Cockpit verwaltete Gruppe "cockpit-viewer" (Audit 18.09.,
# Befund 1): die Systemgruppe `read` darf laut Doku und live am hAP den Router neu starten
# (`reboot`), Verkehr mitschneiden (`sniff`) und alle Passwoerter im Klartext lesen (`sensitive`,
# WLAN-Passphrase, PPPoE, WireGuard-Keys). MikroTik selbst: "should not be given to untrusted
# users". Fuer Familie oder Partner legt Cockpit deshalb bei Bedarf eine eigene Gruppe an, die
# genau das nicht darf. Benutzer in sonstigen selbst angelegten Gruppen werden angezeigt, Cockpit
# bietet fuer sie keinen Gruppenwechsel an und zaehlt sie beim Schutz des letzten Vollzugangs
# bewusst NICHT mit (konservativ: lieber eine Sperre zu viel).
VIEWER_GROUP = "cockpit-viewer"
# Vollstaendig ausgeschrieben, damit kein RouterOS-Standard still etwas hinzufuegt.
VIEWER_GROUP_POLICY = (
    "read,ssh,winbox,web,api,rest-api,password,"
    "!local,!telnet,!ftp,!reboot,!write,!policy,!test,!sniff,!sensitive,!romon"
)
# Was eine bestehende Gruppe dieses Namens auf keinen Fall duerfen darf, sonst haengt Cockpit
# einen "Nur ansehen"-Benutzer in eine Gruppe, die der Kunde selbst maechtiger gebaut hat.
VIEWER_GROUP_FORBIDDEN = ("write", "policy", "sensitive", "reboot", "sniff", "ftp", "test")
USER_GROUPS = ("full", "write", "read", VIEWER_GROUP)          # Cockpit kennt und zeigt sie
USER_GROUP_TARGETS = ("full", "write", VIEWER_GROUP)          # dahin legt Cockpit an oder haengt um
DEFAULT_ADMIN_USER = "admin"


class ViewerGroupUnsafe(Exception):
    pass


def router_json(path: str) -> list[dict] | None:
    # RouterOS 7.13+ liefert Listen als JSON, damit entfaellt das Terse-Raten (Audit 18.09., Befund
    # 2: ein "disabled=true" im KOMMENTAR eines Benutzers wurde vom Terse-Parser als Feld gelesen).
    # json.no-string-conversion, sonst wird der Benutzername "12345" zur Zahl. Aeltere 7.x kennen
    # :serialize nicht ("bad command name" kommt als RouterCommandFailed) -> None, Aufrufer faellt
    # auf Terse zurueck.
    try:
        raw = router(f":put [:serialize to=json options=json.no-string-conversion value=[{path} print as-value]]")
    except RouterCommandFailed as exc:
        if "bad command name" in str(exc).lower() or "syntax error" in str(exc).lower():
            return None
        raise
    # Leere Ausgabe heisst "kein JSON" (unbekannter Befehl ohne Fehlertext), nie "keine Eintraege":
    # mindestens ein Benutzer existiert immer.
    if not raw.strip():
        return None
    try:
        rows = json.loads(raw.strip())
    except ValueError:
        return None
    return rows if isinstance(rows, list) else None


_USER_TERSE_RE = re.compile(
    r"\b(name|group|address|comment|last-logged-in)=(.*?)"
    r"(?=\s+(?:name|group|inactivity-timeout|inactivity-policy|address|comment|last-logged-in)=|$)"
)


def _list_users_terse() -> list[dict]:
    # Fallback ohne :serialize: nur die bekannten Schluessel matchen, damit ein "x=y" im
    # Kommentar nicht zum Feld wird. Live am 18.09. (hAP 7.23.1): "disabled" kommt in
    # `print terse` nur als Flag X vor dem ersten key=, E heisst "Passwort abgelaufen";
    # `last-logged-in` FEHLT komplett, wenn sich der Benutzer nie angemeldet hat.
    users = []
    for line in router("/user print terse").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        flags = "".join(line[: line.index("=")].split()[1:])
        row = {k: v.strip() for k, v in _USER_TERSE_RE.findall(line)}
        name = row.get("name")
        if not name:
            continue
        users.append({
            "name": name,
            "group": row.get("group", ""),
            "disabled": "X" in flags,
            "expired": "E" in flags,
            "last_logged_in": row.get("last-logged-in") or None,
            "address": row.get("address", ""),
            "comment": row.get("comment", ""),
        })
    return users


def list_users() -> list[dict]:
    # Gemeinsame Quelle fuer den Sicherheits-Check (Basis) und die Benutzerverwaltung (Pro).
    rows = router_json("/user")
    if rows is None:
        return _list_users_terse()
    users = []
    for row in rows:
        name = row.get("name")
        if not isinstance(name, str) or not name:
            continue
        address = row.get("address") or []
        users.append({
            "name": name,
            "group": str(row.get("group", "")),
            "disabled": row.get("disabled") is True,
            "expired": row.get("expired") is True,
            "last_logged_in": row.get("last-logged-in") or None,
            "address": ",".join(str(a) for a in address) if isinstance(address, list) else str(address),
            "comment": str(row.get("comment") or ""),
        })
    return users


def list_user_groups() -> list[dict]:
    rows = router_json("/user group")
    if rows is None:
        groups = []
        for row in parse_terse(router("/user group print terse")):
            if row.get("name"):
                groups.append({"name": row["name"], "policy": [p for p in row.get("policy", "").split(",") if p]})
        return groups
    groups = []
    for row in rows:
        if isinstance(row.get("name"), str):
            policy = row.get("policy") or []
            groups.append({"name": row["name"], "policy": [str(p) for p in policy] if isinstance(policy, list) else str(policy).split(",")})
    return groups


def ensure_viewer_group() -> None:
    # Legt "cockpit-viewer" an, falls sie fehlt, und weigert sich, eine gleichnamige Gruppe zu
    # benutzen, die mehr darf als "nur ansehen". Aufrufer haelt _router_create_lock().
    existing = next((g for g in list_user_groups() if g["name"] == VIEWER_GROUP), None)
    if existing is None:
        router(f'/user group add name="{VIEWER_GROUP}" policy={VIEWER_GROUP_POLICY}')
        existing = next((g for g in list_user_groups() if g["name"] == VIEWER_GROUP), None)
        if existing is None:
            raise RouterCommandFailed(f"Gruppe {VIEWER_GROUP} wurde nicht angelegt")
    granted = {p for p in existing["policy"] if not p.startswith("!")}
    unsafe = sorted(granted & set(VIEWER_GROUP_FORBIDDEN))
    if unsafe:
        raise ViewerGroupUnsafe(", ".join(unsafe))


def active_full_users(users: list[dict]) -> list[dict]:
    return [u for u in users if u["group"] == "full" and not u["disabled"]]


def _valid_ipv4_cidr(value: str) -> bool:
    # Audit A11, 09.09.: ipaddress.ip_interface() akzeptiert auch IPv6 -- dieser Helfer heisst
    # bewusst "ipv4", also explizit IPv4Interface statt des allgemeinen ip_interface().
    try:
        ipaddress.IPv4Interface(value)
        return "/" in value
    except (ValueError, TypeError):
        return False


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except (ValueError, TypeError):
        return False


def _fw_ordered_ids(path: str, chain: str) -> list[str]:
    # Von Basis (Portweiterleitung, place-before) UND Pro (Firewall-Create) verwendet --
    # deshalb hier statt in routes_pro.py, siehe Moduldocstring.
    safe_chain = _routeros_value(chain, "chain")
    output = router(f':foreach i in=[{path} find where chain="{safe_chain}"] do={{:put $i}}')
    return [line.strip() for line in output.splitlines() if line.strip()]


def list_wireless_networks() -> list[dict]:
    networks = []
    # Klassischer Treiber (cAP ac und aeltere Hardware). Existiert das Paket nicht
    # (z.B. auf dem CHR-Labor-Router ohne Funk-Interface, oder auf einem Geraet mit nur dem
    # neueren wifi-Treiber wie L009), liefert RouterOS einen Fehler statt einer leeren Liste --
    # das ist hier kein Ausfall, sondern "nicht vorhanden". Live-Fund an einem L009
    # (10.09.2026): dieser Fehler kam als "bad command name wireless" zurueck, das ist
    # RouterCommandFailed, NICHT RouterUnreachable (siehe _ROUTEROS_ERROR_RE in routeros.py) --
    # wurde bisher nicht gefangen und liess GET /wifi mit einem Serverfehler abbrechen, obwohl
    # der zweite (wifi-Treiber-)Zweig darunter laengst genau fuer diesen Fall gebaut war.
    try:
        for row in parse_terse(router("/interface wireless print terse")):
            networks.append({
                "interface": row.get("name"),
                "ssid": row.get("ssid"),
                "band": row.get("band"),
                "hidden": row.get("hide-ssid") == "true",
                "driver": "wireless",
                "running": row.get("running"),
                "disabled": row.get("disabled"),
            })
    except (RouterUnreachable, RouterCommandFailed):
        pass
    # Neuerer wifiwave2/wifi-Treiber (hAP ax2, wAP ax, L009).
    try:
        for row in parse_terse(router("/interface wifi print terse")):
            networks.append({
                "interface": row.get("name"),
                "ssid": row.get("configuration.ssid"),
                "band": row.get("configuration.band"),
                "hidden": row.get("configuration.hide-ssid") == "true",
                "driver": "wifi",
                "running": row.get("running"),
                "disabled": row.get("disabled"),
            })
    except (RouterUnreachable, RouterCommandFailed):
        pass
    return networks


def _wireless_driver(interface: str, *, validated: bool = False) -> str | None:
    safe_interface = interface if validated else _routeros_value(interface, "interface")
    for driver, command in (
        ("wireless", f'/interface wireless print terse where name="{safe_interface}"'),
        ("wifi", f'/interface wifi print terse where name="{safe_interface}"'),
    ):
        try:
            if parse_terse(router(command)):
                return driver
        # Gleicher Live-Fund wie bei list_wireless_networks() (L009, 10.09.2026): fehlt das
        # klassische "wireless"-Paket, kommt "bad command name wireless" als
        # RouterCommandFailed zurueck, nicht RouterUnreachable -- ohne diesen Fang wuerde der
        # naechste Zweig (wifi-Treiber) nie erreicht, WLAN-Name/-Passwort waeren auf reinen
        # wifi-Treiber-Geraeten komplett unbedienbar.
        except (RouterUnreachable, RouterCommandFailed, ValueError):
            continue
    return None


# ---------------------------------------------------------------------------
# Gastnetz-/Isolationsnachweis (Audits "Listenmitgliedschaft" + "Bridge-Filter/VLAN-Isolation",
# 10.09.2026): geteilt zwischen der Pro-Route `/guest-network` (Gastnetz an/aus, SSID/Status)
# und dem Basis-Endpunkt `/security-check` (Gastnetz-Isolation ist Teil des dortigen Scores) --
# siehe Grenzfall-Hinweis im Moduldocstring oben.
# ---------------------------------------------------------------------------

_FIREWALL_METADATA = {".id", "chain", "action", "comment", "disabled", "running",
                      "log", "log-prefix", "bytes", "packets", "reject-with"}


def _has_unresolved_matchers(row: dict, supported: set[str]) -> bool:
    # Unbekannte RouterOS-Matcher dürfen einen vollständigen Schutzbeleg nie
    # unbemerkt einschränken (z.B. Adresslisten, Zeitfenster oder Paketmarkierungen).
    return any(value for key, value in row.items()
               if key not in _FIREWALL_METADATA and key not in supported)


def _terse_ohne_abgeschaltete(output: str) -> list[dict]:
    """Wie parse_terse(), aber ohne Zeilen mit dem Flag X.

    Bewusst nicht row["disabled"]: Das wird auch aus einem "disabled=true" im Kommentar wahr, und
    eine aktive Regel verschwaende damit aus der Pruefung.
    """
    aktive = []
    for zeile in output.splitlines():
        if "X" not in terse_flags(zeile):
            aktive.extend(parse_terse(zeile))
    return aktive


# Eingebaute Listen ohne Mitgliederzeilen, gemessen am CHR: "member print where list=all" ist leer,
# obwohl die Liste alle Interfaces enthaelt. "none" ist dagegen wirklich leer.
_LISTEN_OHNE_ZEILEN = {"all", "dynamic", "static"}


def _resolve_interface_list_members(list_name: str, nur_aktive: bool = False) -> set[str] | None:
    """Löst eine RouterOS-Interface-Liste (z.B. "LAN") zu ihren tatsächlichen Mitgliedsnamen auf.

    Audit "Listenmitgliedschaft", 10.09.2026: vorher wurde jede Liste, die nicht wörtlich "LAN"
    hieß, pauschal als unauflösbar behandelt -- auch wenn ihre Mitgliedschaft per
    "/interface list member print" trivial nachlesbar gewesen wäre (z.B. eine selbst benannte
    Liste "Hausnetz", die exakt dieselben Interfaces wie "LAN" enthält). Live-Beispiel gegen den
    Test-hAP (10.09.2026): die Liste "LAN" enthält dort ein einzelnes Mitglied, "bridge" (die
    Bridge selbst, nicht die einzelnen Ports) -- ".../list member print" liefert genau das.

    None: nicht sicher auflösbar (Router nicht erreichbar, Befehl fehlgeschlagen, oder ein
    Eintrag ohne lesbares "interface"-Feld) -- dann lieber ehrlich unklar bleiben als raten.

    nur_aktive (2026-11-05): Ein abgeschaltetes Mitglied wirkt im Router nicht. Fragt man, was eine
    REGEL trifft, darf es deshalb nicht zaehlen (nur_aktive=True). Fragt man dagegen, was als
    HAUSNETZ gilt, bleibt es drin: Dort wuerde Weglassen die Pruefung milder machen, etwa beim
    Bridge-Bypass, und das Gastnetz saehe sicherer aus, als es ist. Ein dynamisches Mitglied (Flag
    D, etwa von Detect Internet) kann sich jederzeit aendern und belegt nichts: None.

    include=/exclude= und die eingebauten Listen tauchen in den Mitgliederzeilen nicht auf, wirken
    aber (am CHR gemessen: Regel auf eine Liste mit include=all zaehlt Pakete, Zeilen leer). "Keine
    Zeile" hiesse dort faelschlich "kein Mitglied", deshalb None.
    """
    if list_name in _LISTEN_OHNE_ZEILEN:
        return None
    try:
        definition = parse_terse(router(f'/interface list print terse where name="{list_name}"'))
        output = router(f'/interface list member print terse where list="{list_name}"')
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if any(row.get(feld) not in (None, "", "none") for row in definition for feld in ("include", "exclude")):
        return None
    members = set()
    for zeile in output.splitlines():
        flags = terse_flags(zeile)
        for row in parse_terse(zeile):
            iface = row.get("interface")
            if not iface:
                return None
            if nur_aktive and "D" in flags:
                return None
            if nur_aktive and "X" in flags:
                continue
            members.add(iface)
    return members


def _interface_list_covers_lan(list_name: str, ausser: frozenset[str] | set[str] = frozenset()) -> bool | None:
    """Vergleicht eine beliebige Interface-Liste mit der Liste "LAN" über ihre tatsächlichen
    Mitglieder statt über den Listennamen.

    True: deckt alle LAN-Mitglieder ab (verhält sich für eine Drop-Regel wie "LAN" selbst).
    False: nachweislich disjunkt zu LAN (die Regel betrifft das Hausnetz nachweislich nicht).
    None: teilweise Überschneidung oder nicht auflösbar -- bleibt ehrlich unklar.

    ausser: Was fuer diesen Vergleich nicht zum Hausnetz zaehlt, etwa das Gastnetz selbst oder
    Bridge-Ports, die im Routing nicht vorkommen (siehe _gast_ausnahmen()).
    """
    lan_members = _resolve_interface_list_members("LAN")
    if not lan_members:
        return None
    lan_members = lan_members - ausser
    if not lan_members:
        return None
    members = _resolve_interface_list_members(list_name, nur_aktive=True)
    if members is None:
        return None
    if lan_members <= members:
        return True
    if lan_members.isdisjoint(members):
        return False
    return None


def _static_address_list_networks(list_name: str) -> set[ipaddress.IPv4Network | ipaddress.IPv6Network] | None:
    """Liest ausschließlich vollständig statische Einträge einer Firewall-Adressliste.

    Ein dynamischer Eintrag (etwa eine durch DHCP oder eine Firewall-Regel befüllte Liste) kann
    sich jederzeit ändern. Er ist daher kein belastbarer Beleg für eine vollständige Gastnetz-
    oder LAN-Abdeckung. ``None`` heißt folglich sowohl „nicht lesbar" als auch „dynamisch oder
    nicht eindeutig"; eine leere, nachweislich statische Liste bleibt dagegen die leere Menge.
    """
    try:
        safe_name = _routeros_value(list_name, "address_list")
    except ValueError:
        return None
    try:
        dynamic = router(f'/ip firewall address-list print terse where list="{safe_name}" and dynamic=yes')
        if dynamic.strip():
            # Auch bei einem für parse_terse unlesbaren Ergebnis niemals annehmen, die Liste sei
            # statisch. RouterOS-Flags können je nach Version ohne eigenes key=value erscheinen.
            return None
        output = router(f'/ip firewall address-list print terse where list="{safe_name}" and dynamic=no')
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if output.strip() and not parse_terse(output):
        return None
    networks = set()
    # 2026-11-05, am CHR gemessen: "where dynamic=no" liefert auch abgeschaltete Zeilen, nur am
    # Flag X zu erkennen. Sie zaehlen im Router keine Pakete und belegen deshalb keine Abdeckung.
    for row in _terse_ohne_abgeschaltete(output):
        value = row.get("address")
        if not value:
            return None
        try:
            networks.add(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return None
    return networks


def _address_list_covers_interface(list_name: str, interface: str, ausser: frozenset[str] | set[str] = frozenset()) -> bool | None:
    """Vergleicht eine statische Adressliste mit allen IPv4/IPv6-Netzen eines Interfaces.

    True bedeutet: Jede Adresse des Interfaces liegt nachweislich in mindestens einem einzelnen
    Listeneintrag. False bedeutet: Die Liste ist vollständig disjunkt. Teilüberdeckungen und
    mehrere Einträge, die ein Netz nur gemeinsam abdecken könnten, bleiben absichtlich unknown.

    interface="LAN": Mitglieder aus "ausser" zaehlen nicht, und ein Mitglied ohne Adresse ist kein
    geroutetes Netz. Bridge-Ports und VLAN-Bruecken ohne IP sind dort der Normalfall.
    """
    listed = _static_address_list_networks(list_name)
    if listed is None:
        return None
    interface_networks = set()
    interfaces = _resolve_interface_list_members("LAN") if interface == "LAN" else {interface}
    if not interfaces:
        return None
    for name in interfaces - ausser:
        try:
            safe_interface = _routeros_value(name, "interface")
            output = router(f'/ip address print terse where interface="{safe_interface}"')
        except (ValueError, RouterCommandFailed, RouterUnreachable):
            return None
        rows = parse_terse(output)
        if output.strip() and not rows:
            return None
        for row in rows:
            value = row.get("address")
            if not value:
                return None
            try:
                interface_networks.add(ipaddress.ip_interface(value).network)
            except ValueError:
                return None
    if not interface_networks:
        return None
    if all(any(network.subnet_of(candidate) for candidate in listed if network.version == candidate.version)
           for network in interface_networks):
        return True
    if all(not any(network.overlaps(candidate) for candidate in listed if network.version == candidate.version)
           for network in interface_networks):
        return False
    return None


def _bridge_port_of(safe_interface: str) -> str | None:
    """Liefert den Bridge-Namen, wenn "safe_interface" ein Bridge-Port ist, sonst None."""
    # Ein Port darf mehrere Zeilen haben (am CHR gemessen), nur eine aktive verbindet ihn wirklich.
    rows = _terse_ohne_abgeschaltete(router(f'/interface bridge port print terse where interface="{safe_interface}"'))
    return rows[0].get("bridge") if rows else None


def _guest_bridge_bypass(safe_interface: str) -> bool | None:
    """Prüft den "Bridge-Blindspot": liegen Gastnetz- und LAN-Interfaces auf derselben Bridge,
    entscheidet NICHT die IP-Firewall (forward-Chain), sondern die globale Bridge-Einstellung
    "use-ip-firewall" (/interface bridge settings, RouterOS-Default: "no"), ob dieser Verkehr
    die IP-Firewall überhaupt erreicht. Bei "no" läuft Verkehr zwischen zwei Ports derselben
    Bridge rein auf Layer 2 (RouterOS-Switch-Fabric) -- jede Forward-Chain-Drop-Regel ist für
    genau diesen Verkehr wirkungslos, unabhängig davon wie vollständig sie sonst aussieht.

    Live bestätigt am Test-hAP (10.09.2026): "/interface bridge settings print" ->
    use-ip-firewall=no (RouterOS-Default, siehe auch manual.mikrotik.com/docs/bridging-and-
    switching, Abruf 10.09.2026). Auf dem Testgerät liegt das aktuell gewählte Gastnetz-
    Interface ("Gastnetz", eine virtuelle AP-Schnittstelle auf wlan1) selbst NICHT als Port auf
    der Bridge "bridge" -- der Bypass greift dort also (noch) nicht, ist aber laut Praxis eine
    sehr verbreitete Konfiguration (WLAN-Interface direkt als weiterer Bridge-Port statt
    routed/VLAN-getrennt).

    True: Bypass bestätigt (gleiche Bridge wie ein LAN-Mitglied, use-ip-firewall != yes).
    False: nachweislich kein Bypass (kein Bridge-Port, andere Bridge ohne LAN-Bezug, oder
    use-ip-firewall=yes -- dann greift die Forward-Chain-Prüfung wie gehabt).
    None: nicht sicher entscheidbar (z.B. Bridge-Einstellungen nicht lesbar).
    """
    try:
        bridge_name = _bridge_port_of(safe_interface)
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if not bridge_name:
        return False
    lan_members = _resolve_interface_list_members("LAN")
    if not lan_members:
        # Eine leere Liste sagt nichts ueber das Hausnetz, "kein Bypass" waere ein Grund fuer Gruen.
        return None
    same_bridge_is_lan = bridge_name in lan_members
    if not same_bridge_is_lan:
        # Ohne VLAN-Filter erreicht ein Gast, der selbst taggt, jedes VLAN-Interface dieser Bridge.
        # Im Labor gemessen, siehe Szenario bridge-ohne-vlanfilter.
        try:
            vlan_rows = _terse_ohne_abgeschaltete(router(f'/interface vlan print terse where interface="{bridge_name}"'))
        except (RouterCommandFailed, RouterUnreachable):
            return None
        same_bridge_is_lan = any(row.get("name") in lan_members for row in vlan_rows) and not _bridge_vlan_filter(bridge_name)
    if not same_bridge_is_lan:
        # Die Bridge selbst ist kein LAN-Mitglied -- prüfen, ob ein ANDERER Port derselben
        # Bridge individuell in der LAN-Liste steht (falls die Liste einzelne Ports statt der
        # Bridge selbst enthält).
        try:
            all_ports = _terse_ohne_abgeschaltete(router(f'/interface bridge port print terse where bridge="{bridge_name}"'))
        except (RouterCommandFailed, RouterUnreachable):
            return None
        siblings = {row.get("interface") for row in all_ports if row.get("interface") != safe_interface}
        if not (siblings & lan_members):
            return False
    try:
        settings = parse_colon(router("/interface bridge settings print"))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if not settings:
        return None
    bypass = settings.get("use-ip-firewall", "no").strip().lower() != "yes"
    if not bypass and _port_im_switch_chip(safe_interface) is not False:
        return None
    return bypass


def _port_im_switch_chip(safe_interface: str) -> bool | None:
    """Flag H: Verkehr zwischen Switch-Ports erreicht die CPU nicht, Bridge-Filter und use-ip-firewall
    sehen ihn dann nicht (manual.mikrotik.com, Bridging and Switching). Das Feld hw=yes sagt nur, dass
    Offload erlaubt ist: Es steht auch am CHR und am hAP ax2, die kein Flag H zeigen, der L009 zeigt es."""
    try:
        ausgabe = router(f'/interface bridge port print terse where interface="{safe_interface}"')
    except (RouterCommandFailed, RouterUnreachable):
        return None
    return any("H" in flags and "X" not in flags for flags in map(terse_flags, ausgabe.splitlines()))


def _bridge_zeile(bridge_name: str) -> dict | None:
    """Die Zeile der Bridge aus "/interface bridge". None: nicht lesbar oder nicht vorhanden."""
    try:
        rows = parse_terse(router(f'/interface bridge print terse where name="{bridge_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    return rows[0] if rows else None


def _bridge_vlan_filter(bridge_name: str) -> bool:
    zeile = _bridge_zeile(bridge_name)
    return bool(zeile) and zeile.get("vlan-filtering", "").lower() in ("yes", "true")


def _bridge_siblings(bridge_name: str, exclude: str) -> set[str] | None:
    """Alle Ports derselben Bridge außer "exclude" (typischerweise das Gastnetz-Interface
    selbst). None: Portliste nicht lesbar."""
    try:
        rows = _terse_ohne_abgeschaltete(router(f'/interface bridge port print terse where bridge="{bridge_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    return {row.get("interface") for row in rows if row.get("interface") and row.get("interface") != exclude}


def _bridge_lan_ports(bridge_name: str, safe_interface: str) -> set[str] | None:
    """Bestimmt, welche Ports derselben Bridge als "Hausnetz" gelten -- gemeinsame Grundlage für
    den Bridge-Firewall-Filter- UND den VLAN-Nachweis (Audit "Bridge-Filter/VLAN-Isolation",
    10.09.2026, RouterOS-Review). Nutzt dieselbe Auflösung wie _guest_bridge_bypass():
    steht die Bridge selbst in der Liste "LAN" (live am Test-hAP der Regelfall -- die Liste "LAN"
    enthält dort nur "bridge" selbst, keine Einzel-Ports), zählt jeder ANDERE Port dieser Bridge
    als Hausnetz-Port. Steht die Liste stattdessen aus einzeln benannten Ports, zählen nur die
    tatsächlich genannten. None: nicht sicher auflösbar."""
    lan_members = _resolve_interface_list_members("LAN")
    if lan_members is None:
        return None
    siblings = _bridge_siblings(bridge_name, safe_interface)
    if siblings is None:
        return None
    if bridge_name in lan_members:
        return siblings
    return lan_members & siblings


def _interface_list_covers_ports(list_name: str, ports: set[str]) -> bool | None:
    """Wie _interface_list_covers_lan(), aber gegen eine beliebige Portmenge statt gegen die
    Liste "LAN" selbst -- Grundlage für den Bridge-Filter-Nachweis, wo "Hausnetz" die vorher via
    _bridge_lan_ports() ermittelte Portmenge ist, nicht die IP-Ebenen-Liste "LAN".

    True: deckt alle übergebenen Ports ab. False: nachweislich disjunkt. None: teilweise
    Überschneidung oder nicht auflösbar."""
    if not ports:
        return None
    members = _resolve_interface_list_members(list_name, nur_aktive=True)
    if members is None:
        return None
    if ports <= members:
        return True
    if ports.isdisjoint(members):
        return False
    return None


def _bridge_filter_isolation(safe_interface: str, bridge_name: str) -> bool | None:
    """Prüft, ob ein aktiver Eintrag in "/interface bridge filter" (chain=forward) den
    Bridge-Bypass (siehe _guest_bridge_bypass()) tatsächlich schließt -- eine Drop-Regel auf
    Bridge-Ebene wirkt VOR "use-ip-firewall" und greift damit auch bei "use-ip-firewall=no"
    (manual.mikrotik.com/docs/cli-reference/interface/bridge/filter/filter, Abruf 10.09.2026:
    chain=forward, action drop/accept/passthrough/jump/return/log/mark-packet/set-priority,
    in-interface/out-interface sind die tatsächlichen Bridge-PORTS, nicht die Bridge selbst;
    in-bridge/out-bridge referenzieren die Bridge als Ganzes).

    Audit "Bridge-Filter/VLAN-Isolation", 10.09.2026 (RouterOS-Review). Struktur bewusst
    analog zu _guest_isolation(): nur eine konkrete, uneingeschränkte Drop-Regel vom Gastnetz-Port
    Richtung Hausnetz-Ports zählt als Nachweis; eine vorgelagerte Accept-Regel macht den Nachweis
    unbrauchbar. "passthrough"/"log"/"mark-packet"/"set-priority" beenden die Kette nicht (RouterOS
    wertet die nächste Regel trotzdem aus) und werden deshalb übersprungen, nicht als Endzustand
    gewertet.

    True: aktive, uneingeschränkte Drop-Regel gefunden -- Bridge-Filter schließt den Bypass.
    False: eine Accept-Regel erlaubt den Verkehr zwischen Gastnetz- und Hausnetz-Port ausdrücklich.
    None: keine passende Regel gefunden, Regeln nicht lesbar, oder Reichweite (Interface-
    Liste/Bridge-Bezug) nicht sicher auflösbar -- inkl. dem Regelfall am Test-hAP (10.09.2026, kein
    Bridge-Filter konfiguriert, "/interface bridge filter print" liefert eine leere Liste)."""
    lan_ports = _bridge_lan_ports(bridge_name, safe_interface)
    if not lan_ports:
        # None: nicht auflösbar. Leeres Set: kein anderer Bridge-Port zählt als Hausnetz --
        # in beiden Fällen kein belastbarer Nachweis möglich (konservativ, wie _vlan_isolation()).
        return None
    try:
        output = router('/interface bridge filter print terse where chain=forward')
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if output.strip() and not parse_terse(output):
        return None
    for row in parse_regeln(output):
        if row.get(REGEL_UNKLAR) or row.get(FLAG_I):
            return None
        action = row.get("action", "accept")
        if action in ("passthrough", "log", "mark-packet", "set-priority"):
            continue
        if action in ("jump", "return"):
            return None
        in_bridge = row.get("in-bridge")
        if in_bridge:
            if in_bridge.startswith("!"):
                if in_bridge[1:] == bridge_name:
                    continue
                return None
            if in_bridge != bridge_name:
                continue
        in_if_list = row.get("in-interface-list")
        if in_if_list:
            if in_if_list.startswith("!"):
                return None
            members = _resolve_interface_list_members(in_if_list, nur_aktive=True)
            if members is None:
                return None
            if safe_interface not in members:
                continue
        else:
            in_if = row.get("in-interface")
            if in_if and in_if.startswith("!"):
                if in_if[1:] == safe_interface:
                    continue
                return None
            if in_if and in_if != safe_interface:
                continue
        out_bridge = row.get("out-bridge")
        if out_bridge:
            if out_bridge.startswith("!"):
                if out_bridge[1:] == bridge_name:
                    continue
                return None
            if out_bridge != bridge_name:
                continue
        out_if_list = row.get("out-interface-list")
        out_if = row.get("out-interface")
        list_targets_lan = False
        list_unresolved = False
        if out_if_list:
            if out_if_list.startswith("!"):
                return None
            covers = _interface_list_covers_ports(out_if_list, lan_ports)
            list_targets_lan = covers is True
            list_unresolved = covers is None
        if action == "accept" and (out_if or list_unresolved):
            return False
        # Ein einzelner Ausgangsport ist nur dann "das Hausnetz", wenn es keinen zweiten gibt: Eine
        # Sperre auf ether2 laesst ether3 offen. Die Accept-Richtung steht schon oben.
        targets_lan = list_targets_lan or (bool(out_if) and lan_ports == {out_if})
        targets_anything = not out_if_list and not out_if
        if not (targets_lan or targets_anything):
            continue
        if action == "accept":
            return False
        if action != "drop":
            continue
        if _has_unresolved_matchers(row, {"in-interface", "in-interface-list", "out-interface",
                                           "out-interface-list", "in-bridge", "out-bridge"}):
            continue
        return True
    return None


def _vlan_id_in(feld: str, vlan_id: str) -> bool:
    """Steht die VLAN-ID in "10,20-30"? Unlesbares zaehlt als ja, das haelt das Urteil vorsichtig."""
    for teil in (t.strip() for t in feld.split(",")):
        if not teil:
            continue
        try:
            von, _, bis = teil.partition("-")
            if int(von) <= int(vlan_id) <= int(bis or von):
                return True
        except ValueError:
            return True
    return False


def _funknetz(interface: str) -> tuple[bool, str | None]:
    """(ist WLAN, SSID) eines Interfaces. Die SSID fehlt, wenn sie aus einem Profil kommt."""
    for pfad, feld in (("wifi", "configuration.ssid"), ("wireless", "ssid")):
        try:
            rows = parse_terse(router(f'/interface {pfad} print terse where name="{interface}"'))
        except (RouterCommandFailed, RouterUnreachable):
            continue
        if rows:
            return True, rows[0].get(feld) or None
    return False, None


def _vlan_isolation(safe_interface: str, bridge_name: str) -> bool | None:
    """Prüft, ob VLAN-Filterung auf der Bridge das Gastnetz Layer-2-getrennt hält --
    (manual.mikrotik.com/docs/bridging-and-switching/user-guides/bridge-vlan-table, Abruf
    10.09.2026: PVID taggt jeden eingehenden untagged Frame mit der eigenen VLAN-ID, die
    Bridge-VLAN-Tabelle entscheidet je VLAN-ID, welche Ports das Paket beim Egress überhaupt
    verlassen dürfen -- fehlt ein Port in "tagged"/"untagged" für diese VLAN-ID, kommt dort kein
    Paket dieser VLAN an, selbst innerhalb derselben Bridge).

    Audit "Bridge-Filter/VLAN-Isolation", 10.09.2026 (RouterOS-Review). Nur relevant, wenn
    VLAN-Filterung an der Bridge selbst aktiv ist ("/interface bridge" -> vlan-filtering=yes,
    RouterOS-Default: nein/inaktiv) -- ohne das wird die VLAN-Tabelle nicht durchgesetzt, PVID
    und tagged/untagged sind dann wirkungslose Konfiguration. Nutzt "current-tagged"/
    "current-untagged" (tatsächlich angewandter Zustand inkl. automatisch durch PVID erzeugter
    Einträge) statt der rohen "tagged"/"untagged"-Konfiguration.

    True: Das VLAN des Gastnetz-Ports ist auf Layer 2 vom Hausnetz getrennt.
    False: Ein Hausnetz-Port haengt ungetaggt im selben VLAN, die Bridge selbst gehoert zum
    selben VLAN und zum Hausnetz, oder der Gast kann sich am Port selbst in ein anderes VLAN taggen.
    None: VLAN-Filterung nicht aktiv, kein Tabelleneintrag oder etwas nicht lesbar.

    2026-11-05, am hAP ax2 gelesen und im Labor gemessen: Getrennt wird per VLAN-ID, nicht per Port.
    Ein Trunk fuehrt Gast- und Hausnetz-VLAN getaggt und ist kein Leck. Das sagt nur etwas ueber
    Layer 2. Ob der Router zwischen den VLANs routet, prueft _guest_isolation()."""
    zeile = _bridge_zeile(bridge_name)
    if not zeile or zeile.get("vlan-filtering", "").lower() not in ("yes", "true"):
        return None
    try:
        port_rows = _terse_ohne_abgeschaltete(router(f'/interface bridge port print terse where interface="{safe_interface}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if not port_rows:
        return None
    pvid = port_rows[0].get("pvid", "1")
    # Am CHR gemessen (Szenario vlan-ohne-ingress): Ohne Ingress-Filter gelangt ein selbst getaggtes
    # Paket vom Gast-Port in jedes VLAN. Nur "admit-only-untagged" haelt es dann noch auf.
    ingress = port_rows[0].get("ingress-filtering", "").lower()
    frames = port_rows[0].get("frame-types", "")
    if ingress in ("no", "false") and not frames.startswith("admit-only-untagged"):
        return False
    if ingress not in ("yes", "true", "no", "false"):
        return None
    # Setzt das WLAN sein VLAN selbst, sagt die PVID des Ports nichts ueber das VLAN des Gastes.
    if _wlan_setzt_vlan(safe_interface) is not False:
        return None

    lan_members = _resolve_interface_list_members("LAN")
    siblings = _bridge_siblings(bridge_name, safe_interface)
    if not lan_members or not siblings:
        # Kein anderer Bridge-Port oder leeres LAN: kein belastbarer Vergleich (z.B. ein Ein-Port-Testaufbau).
        return None

    try:
        vlan_rows = _terse_ohne_abgeschaltete(router(f'/interface bridge vlan print terse where bridge="{bridge_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    matching = [row for row in vlan_rows if _vlan_id_in(row.get("vlan-ids", ""), pvid)]
    # Der Ingress-Filter prueft nur die Mitgliedschaft. Steht der Gast-Port auch in einem fremden VLAN,
    # kommt er mit selbst getaggten Paketen dorthin (im Labor gemessen, Szenario gast-tagged-haus-vlan).
    if not frames.startswith("admit-only-untagged"):
        for row in vlan_rows:
            # Auch eine Sammelzeile "vlan-ids=10,20" fuehrt in fremde VLANs. Dort zeigt current-* aber
            # auch Ports, die nur ueber ihre PVID dabei sind, deshalb zaehlt nur die Konfiguration.
            if row in matching and row.get("vlan-ids", "").strip() == pvid:
                continue
            felder = ("tagged", "untagged") if row in matching else ("current-tagged", "current-untagged", "tagged", "untagged")
            for key in felder:
                if safe_interface in {v.strip() for v in row.get(key, "").split(",")}:
                    return False
    if not matching:
        # Kein Tabelleneintrag fuer diese VLAN-ID -- RouterOS' Default-Verhalten (Egress-Drop
        # ohne Eintrag) koennte tatsaechlich isolieren, ist hier aber bewusst nicht als Nachweis
        # gewertet, siehe Docstring.
        return None

    ungetaggt: set[str] = set()
    for row in matching:
        statisch = {v.strip() for v in row.get("untagged", "").split(",") if v.strip()}
        aktuell = {v.strip() for v in row.get("current-untagged", "").split(",") if v.strip()}
        if row.get("vlan-ids", "").strip() != pvid:
            pvids = _port_pvids(bridge_name)
            if pvids is None:
                return None
            # Fest untagged in der Sammelzeile: Gastverkehr verlaesst auch einen Port mit fremder PVID.
            if any(pvids.get(port, pvid) != pvid for port in statisch - {safe_interface}):
                return False
            aktuell = {port for port in aktuell if pvids.get(port, pvid) == pvid}
        ungetaggt |= statisch | aktuell
    ungetaggt.discard(safe_interface)

    bridge_ist_lan = bridge_name in lan_members
    if bridge_ist_lan and pvid == zeile.get("pvid", "1"):
        return False
    # Ein zweites Funkband desselben Gastnetzes ist kein Hausnetz.
    _, gast_ssid = _funknetz(safe_interface)
    unklar = False
    for port in ungetaggt:
        ist_wlan, ssid = _funknetz(port)
        if ist_wlan and gast_ssid and ssid == gast_ssid:
            continue
        if port in lan_members and not ist_wlan:
            return False
        # Ob ein anderes WLAN oder ein Port ausserhalb der Liste zum Hausnetz gehoert, steht nirgends.
        if port in lan_members or bridge_ist_lan or _vlan_interface_in_lan(bridge_name, pvid, lan_members):
            unklar = True
    return None if unklar else True


def _port_pvids(bridge_name: str) -> dict[str, str] | None:
    try:
        rows = _terse_ohne_abgeschaltete(router(f'/interface bridge port print terse where bridge="{bridge_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    return {row["interface"]: row["pvid"] for row in rows if row.get("interface") and row.get("pvid")}


def _vlan_interface_in_lan(bridge_name: str, vlan_id: str, lan_members: set[str]) -> bool:
    try:
        rows = _terse_ohne_abgeschaltete(router(f'/interface vlan print terse where interface="{bridge_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return True
    return any(row.get("vlan-id") == vlan_id and row.get("name") in lan_members for row in rows)


def _gast_vlan_mitglieder(safe_interface: str, bridge_name: str, pvid: str) -> set[str] | None:
    """Alle anderen Ports im VLAN des Gastes, ohne die Bridge selbst. None: nicht lesbar."""
    try:
        rows = _terse_ohne_abgeschaltete(router(f'/interface bridge vlan print terse where bridge="{bridge_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    mitglieder: set[str] = set()
    for row in rows:
        if _vlan_id_in(row.get("vlan-ids", ""), pvid):
            for key in ("current-tagged", "current-untagged", "tagged", "untagged"):
                mitglieder |= {v.strip() for v in row.get(key, "").split(",") if v.strip()}
    return mitglieder - {safe_interface, bridge_name}


def _befehl_fehlt(exc: RouterCommandFailed) -> bool:
    """Das Menue gibt es hier nicht. Jeder andere Fehler heisst: Es liess sich nicht lesen."""
    text = str(exc).lower()
    return "bad command name" in text or "no such command" in text


def _wlan_setzt_vlan(safe_interface: str) -> bool | None:
    """True, wenn das WLAN-Interface selbst ein VLAN setzt. Dann sagt die PVID des Ports nichts.

    Am CHR nicht messbar, er hat kein WLAN. Am hAP ax2 gelesen: Ein Gast-WLAN ueber die PVID zeigt
    weder "datapath=" noch "datapath.vlan-id=" noch "configuration=". Ein benanntes Profil kann ein VLAN
    mitbringen, das diese Abfrage nicht sieht, deshalb zaehlt schon das Profil. Dazu kommen VLANs je
    Geraet (Access-List) und je Passwort (Multi-Passphrase).
    """
    for pfad in ("/interface wifi access-list", "/interface wifi security multi-passphrase", "/interface wireless access-list"):
        try:
            rows = _terse_ohne_abgeschaltete(router(f"{pfad} print terse"))
        except RouterCommandFailed as exc:
            if _befehl_fehlt(exc):
                continue
            return None
        except RouterUnreachable:
            return None
        if any(row.get("vlan-id") not in (None, "", "none") for row in rows):
            return True
    for pfad, felder in (("wifi", ("datapath", "datapath.vlan-id", "configuration")), ("wireless", ("vlan-id",))):
        try:
            rows = parse_terse(router(f'/interface {pfad} print terse where name="{safe_interface}"'))
        except RouterCommandFailed as exc:
            if _befehl_fehlt(exc):
                continue
            return None
        except RouterUnreachable:
            return None
        for row in rows:
            if pfad == "wireless" and row.get("vlan-mode", "no-tag") != "no-tag":
                return True
            if pfad == "wifi" and any(row.get(feld) not in (None, "", "none") for feld in felder):
                return True
    return False


def _hat_routbare_adresse(interface: str, filter_path: str) -> bool | None:
    """Traegt das Interface eine Adresse, mit der der Router hier routet? Link-Local zaehlt nicht."""
    pfad = "/ipv6 address" if filter_path.startswith("/ipv6") else "/ip address"
    try:
        rows = _terse_ohne_abgeschaltete(router(f'{pfad} print terse where interface="{interface}"'))
    except RouterCommandFailed as exc:
        # Nur das fehlende IPv6-Paket heisst "keine Adresse". Jeder andere Fehler bleibt unklar.
        fehlt = pfad == "/ipv6 address" and ("bad command name" in str(exc).lower() or "no such command" in str(exc).lower())
        return False if fehlt else None
    except RouterUnreachable:
        return None
    return any(row.get("address") and not row["address"].lower().startswith("fe80") for row in rows)


_PRIVATE_NETZE = tuple(ipaddress.ip_network(netz) for netz in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def _adress_zeilen(filter_path: str) -> list[dict] | None:
    pfad = "/ipv6 address" if filter_path.startswith("/ipv6") else "/ip address"
    try:
        ausgabe = router(f"{pfad} print terse")
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if ausgabe.strip() and not parse_terse(ausgabe):
        return None
    return [row for row in _terse_ohne_abgeschaltete(ausgabe)
            if row.get("interface") and row.get("address")
            and not row["address"].lower().startswith("fe80") and row["interface"] != "lo"]


def _privat_adressiert(filter_path: str) -> set[str]:
    """Interfaces mit privater Adresse. Eine unlesbare Adresse zaehlt dazu, das ist die vorsichtige Seite."""
    namen = set()
    for row in _adress_zeilen(filter_path) or []:
        try:
            ip = ipaddress.ip_interface(row["address"]).ip
        except ValueError:
            namen.add(row["interface"])
            continue
        if any(ip in netz for netz in _PRIVATE_NETZE):
            namen.add(row["interface"])
    return namen


def _geroutete_ziele(filter_path: str, eingang: set[str]) -> set[str] | None:
    """Wohin der Router das Gastnetz routen kann: jedes Interface mit Adresse ausser Eingang und WAN.

    Die Liste "LAN" allein reicht nicht. Steht das Haus-VLAN nicht darin, trifft eine Sperre auf "LAN"
    es nie (im Labor gemessen, Szenario lan-nur-bridge). Ein WAN mit privater Adresse bleibt ein Ziel:
    Der Router haengt dann hinter einem anderen Router, etwa einer FritzBox, und Geraete dort sind ueber
    den Internetausgang erreichbar (Szenario hinter-router-sperre-lan). None: nicht lesbar.
    """
    zeilen = _adress_zeilen(filter_path)
    if zeilen is None:
        return None
    wan = _resolve_interface_list_members("WAN") or set()
    return {row["interface"] for row in zeilen} - eingang - (wan - _privat_adressiert(filter_path))


def _zustand_unzuverlaessig(filter_path: str) -> bool:
    """Connection-State-Regeln gelten nur, wenn der Router Verbindungen auch verfolgt.

    Im Labor gemessen: notrack in der Raw-Kette macht aus Gastverkehr "untracked", die uebliche Freigabe
    "established,related,untracked" laesst dann alles durch. Ohne Tracking greift "new" nie.
    """
    raw = "/ipv6 firewall raw" if filter_path.startswith("/ipv6") else "/ip firewall raw"
    try:
        if parse_colon(router("/ip firewall connection tracking print")).get("enabled", "").strip().lower() == "no":
            return True
        return any(row.get(REGEL_UNKLAR) or row.get("action") == "notrack" for row in parse_regeln(router(f"{raw} print terse")))
    except (RouterCommandFailed, RouterUnreachable):
        return True


def _keine_ipsec_policy() -> bool:
    """True, wenn nur die Vorlage existiert: Dann trifft eine Regel mit ipsec-policy keinen Gastverkehr."""
    try:
        zeilen = router("/ip ipsec policy print terse").splitlines()
    except (RouterCommandFailed, RouterUnreachable):
        return False
    # Das Flag T ist echt. Eine echte Policy traegt kein Feld template, "comment=alt template=yes"
    # saehe im Feld wie eine Vorlage aus (am CHR gemessen, 2026-11-06).
    return all("T" in flags or "X" in flags for flags in map(terse_flags, filter(str.strip, zeilen)))


def _absender_schliesst_gast_aus(row: dict, eingang: set[str], filter_path: str) -> bool:
    """Eine Freigabe nur fuer fremde Absender trifft den Gast nur, wenn er seine Adresse faelschen kann.

    Im Labor gemessen, Szenarien spoof-*: Ohne rp-filter kommt das gefaelschte Paket am Haus-Client an, mit
    strict nicht. Loose prueft nur, ob es irgendeine Route zum Absender gibt, das zaehlt hier nicht. Am L009
    steht strict. Das gibt es nur fuer IPv4.
    """
    if filter_path != "/ip firewall filter":
        return False
    wert = row.get("src-address", "")
    try:
        if parse_colon(router("/ip settings print")).get("rp-filter", "").strip().lower() != "strict":
            return False
        absender = ipaddress.ip_network(wert, strict=False)
        for name in eingang:
            zeilen = _terse_ohne_abgeschaltete(router(f'/ip address print terse where interface="{name}"'))
            if not zeilen:
                return False
            for zeile in zeilen:
                if ipaddress.ip_interface(zeile["address"]).network.overlaps(absender):
                    return False
    except (RouterCommandFailed, RouterUnreachable, ValueError, KeyError):
        return False
    return True


def _gast_eingang(safe_interface: str, filter_path: str = "/ip firewall filter", auch_ohne_adresse: bool = False) -> set[str] | None:
    """Ueber welches Interface kommt Gastverkehr im Router an? Danach richtet sich die Firewall.

    Am CHR gemessen (2026-11-05): Geroutet trifft Verkehr von einem Bridge-Port nie in-interface=<Port>.
    - Kein Bridge-Port: das Gast-Interface selbst.
    - Bridge ohne VLAN-Filter: die Bridge.
    - Bridge mit VLAN-Filter: das VLAN-Interface zur PVID des Ports, die Bridge nur bei gleicher PVID.

    Leere Menge: Auf diesem Geraet gibt es keinen Router fuer das Gastnetz. None: nicht bestimmbar,
    auch wenn das WLAN selbst ein VLAN setzt.
    auch_ohne_adresse: Fuer IPv6 braucht der Router keine Adresse im Gastnetz, der Gast kann ueber die
    Link-Local-Adresse routen (im Labor gemessen, Szenario fe80-gateway).
    """
    try:
        bridge_name = _bridge_port_of(safe_interface)
        if not bridge_name:
            return {safe_interface}
        port_rows = _terse_ohne_abgeschaltete(router(f'/interface bridge port print terse where interface="{safe_interface}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    zeile = _bridge_zeile(bridge_name)
    if not zeile or not port_rows:
        return None
    if zeile.get("vlan-filtering", "").lower() in ("yes", "true"):
        if _wlan_setzt_vlan(safe_interface) is not False:
            return None
        pvid = port_rows[0].get("pvid", "1")
        try:
            vlan_rows = _terse_ohne_abgeschaltete(router(f'/interface vlan print terse where interface="{bridge_name}"'))
        except (RouterCommandFailed, RouterUnreachable):
            return None
        kandidaten = {row["name"] for row in vlan_rows if row.get("vlan-id") == pvid and row.get("name")}
        if pvid == zeile.get("pvid", "1"):
            kandidaten.add(bridge_name)
    else:
        kandidaten = {bridge_name}
    if auch_ohne_adresse:
        return kandidaten
    eingang = set()
    for name in kandidaten:
        hat_adresse = _hat_routbare_adresse(name, filter_path)
        if hat_adresse is None:
            return None
        if hat_adresse:
            eingang.add(name)
    return eingang


def _gast_ausnahmen(eingang: set[str], eigener_eingang: bool) -> set[str] | None:
    """Was in der Liste "LAN" im Routing nicht das Hausnetz ist.

    Das Gastnetz selbst steht oft in "LAN", am hAP ax2 und am L009 etwa. Bridge-Ports trifft eine
    Regel auf out-interface-list im Routing nie (im Labor gemessen, Szenario lan-nur-ports). Teilen
    sich Gast und Haus eine Bridge, ist deren Eingang zugleich das Hausnetz und bleibt deshalb drin.
    """
    try:
        ports = parse_terse(router("/interface bridge port print terse"))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    ausnahmen = {row["interface"] for row in ports if row.get("interface")}
    if eigener_eingang:
        ausnahmen |= eingang
    return ausnahmen


def _ipv6_relevant() -> bool | None:
    """Erkennt, ob der IPv6-Stack auf dem Router aktiv ist (RouterOS-Standard: aktiviert,
    "/ipv6 settings" -> disable-ipv6=no). Ist er aktiv, muss Gastnetz-Isolation zusätzlich über
    "/ipv6 firewall filter" nachgewiesen werden -- eine saubere IPv4-Sperre schützt nicht vor
    IPv6-Verkehr, der komplett eigenen Regeln folgt (separate Chain, eigene Adressen).

    Live bestätigt am Test-hAP (10.09.2026): frisches defconf hat disable-ipv6=no, und jedes
    Interface (auch das Gastnetz) bekommt automatisch eine Link-Local-Adresse -- IPv6 ist damit
    praktisch immer "relevant", sobald das ipv6-Paket installiert ist.

    True: Stack aktiv. False: Stack deaktiviert ODER das ipv6-Paket fehlt ganz (beides bedeutet:
    kein IPv6-Bypass-Weg möglich). None: Status aus anderem Grund nicht lesbar.
    """
    try:
        settings = parse_colon(router("/ipv6 settings print"))
    except RouterCommandFailed as exc:
        message = str(exc).lower()
        if "bad command name" in message or "no such command" in message:
            return False
        return None
    except RouterUnreachable:
        return None
    if not settings:
        return None
    return settings.get("disable-ipv6", "no").strip().lower() != "yes"


# RouterBOARD-Firmware (Schritt 2 eines MikroTik-Updates). Live am hAP 19.09.2026:
# `/system routerboard upgrade` laeuft ueber den SSH-Befehlskanal ohne Rueckfrage durch
# (Exit 0, keine Ausgabe) und flasht auch bei gleicher Version. Danach steht ueber dem
# print die Kommentarzeile ";;; Firmware upgraded successfully, please reboot for changes
# to take effect!", nach dem Neustart ist sie weg -- das ist der Marker fuer
# "eingespielt, Neustart fehlt". Geraete ohne RouterBOARD (CHR) antworten "routerboard: no",
# x86 kennt das Menue gar nicht ("bad command name", CLI-Referenz "!i386").
_ROUTERBOARD_KEY_VALUE_RE = re.compile(r"^\s*[\w-]+:\s")
_FIRMWARE_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:(beta|rc)(\d+))?$", re.IGNORECASE)


def _routerboard_reboot_marker(output: str) -> bool:
    # Der Kommentarblock steht vor der ersten "key: value"-Zeile. RouterOS bricht ihn um; die
    # Folgezeile beginnt je nach Version mit ";;;" (hAP 7.23.1 live) oder ohne (Doku routerboot.md).
    # Audit 19.09., Befund 1: nicht an einer einzelnen Zeile haengen bleiben.
    header = []
    for line in output.splitlines():
        if _ROUTERBOARD_KEY_VALUE_RE.match(line):
            break
        header.append(line.strip().lstrip(";").strip())
    text = " ".join(part for part in header if part).lower()
    return "upgraded successfully" in text or "reboot" in text


def _firmware_version_key(value: str | None) -> tuple | None:
    match = _FIRMWARE_VERSION_RE.match((value or "").strip())
    if not match:
        return None
    major, minor, patch, stage, stage_num = match.groups()
    stage_rank = {"beta": 0, "rc": 1}.get((stage or "").lower(), 2)
    return (int(major), int(minor), int(patch or 0), stage_rank, int(stage_num or 0))


def routerboard_state() -> dict:
    try:
        output = router("/system routerboard print")
    except RouterCommandFailed as exc:
        text = str(exc).lower()
        if "bad command name" in text or "no such command" in text:
            return {"available": False}
        raise
    info = parse_colon(output)
    if not info:
        return {"available": None, "error": "leere Ausgabe von /system routerboard print"}
    if info.get("routerboard", "yes").strip().lower() == "no":
        return {"available": False}
    current = info.get("current-firmware") or None
    upgrade = info.get("upgrade-firmware") or None
    # Doku: nur eine HOEHERE upgrade-firmware ist ein ausstehender Schritt 2. Nach einem
    # RouterOS-Downgrade ist die aktive Firmware neuer als die mitgelieferte -- dann nichts tun
    # (Audit 19.09., Befund 2).
    cur_key, up_key = _firmware_version_key(current), _firmware_version_key(upgrade)
    if cur_key and up_key:
        upgrade_available, firmware_newer = up_key > cur_key, up_key < cur_key
    else:
        upgrade_available = bool(current and upgrade and current != upgrade)
        firmware_newer = False
    settings = parse_colon(router("/system routerboard settings print"))
    return {
        "available": True,
        "current_firmware": current,
        "upgrade_firmware": upgrade,
        "upgrade_available": upgrade_available,
        "firmware_newer": firmware_newer,
        "reboot_pending": _routerboard_reboot_marker(output),
        "auto_upgrade": settings.get("auto-upgrade", "").strip().lower() in ("yes", "true"),
        "protected_routerboot": settings.get("protected-routerboot", "").strip().lower() == "enabled",
    }


def device_mode_state() -> dict:
    """Liest den Device-Mode (Doku device-mode.md). Nur lesend, aendern geht ohnehin nur am Geraet."""
    try:
        output = router("/system device-mode print")
    except RouterCommandFailed as exc:
        text = str(exc).lower()
        if "bad command name" in text or "no such command" in text:
            return {"available": False}
        raise
    info = parse_colon(output)
    if not info.get("mode"):
        return {"available": None}
    # None heisst "nicht ablesbar". RouterOS 6.49.21 liefert laut Forum nur "mode: enterprise";
    # ein fehlender Wert darf nie als "nicht markiert" gelten.
    flagged = {"yes": True, "true": True, "no": False, "false": False}.get(info.get("flagged", "").strip().lower())
    return {
        "available": True,
        "mode": info["mode"],
        "flagged": flagged,
        "flagging_enabled": info.get("flagging-enabled", "").strip().lower() not in ("no", "false"),
    }


def _guest_isolation(
    safe_interface: str,
    filter_path: str = "/ip firewall filter",
    eigener_eingang: bool = True,
    eingang: set[str] | None = None,
) -> bool | None:
    """Bestätigt Isolation nur über eine aktive, konkrete Forward-Drop-Regel.

    Ein Gastnetz-Interface allein beweist keine Trennung. Wir akzeptieren deshalb
    ausschließlich die explizite RouterOS-Kombination Gast-Interface -> LAN-Liste.
    Eine davorliegende aktive Accept-Regel für denselben Pfad macht den Nachweis
    unbrauchbar.

    Audit Runde 5, 09.09.: zwei falsch-positive Faelle behoben.
    (a) Eine FRUEHERE, allgemeinere Accept-Regel wurde uebersehen, wenn sie
    "out-interface-list" gar nicht gesetzt hatte (matcht in RouterOS trotzdem JEDES
    Zielinterface, auch LAN) -- die alte Pruefung verlangte eine exakt gesetzte
    "out-interface-list=LAN" und ueberging so jede allgemeinere Regel per continue,
    obwohl RouterOS diese Regel als erste zutreffende zuerst anwendet.
    (b) Eine Drop-Regel, die nur ein einzelnes Protokoll/Port sperrt (z.B. TCP Port 80),
    wurde bereits als vollstaendige Isolation gewertet, obwohl jeder andere Port/Protokoll
    weiterhin offen bleibt.

    Audit "Listenmitgliedschaft", 10.09.2026: (c) "in-interface-list"/"out-interface-list"
    wurden bisher IMMER als unaufloesbar behandelt, sobald sie nicht woertlich "LAN" hiessen
    bzw. ueberhaupt gesetzt waren -- selbst wenn ihre tatsaechliche Mitgliedschaft ueber
    "/interface list member print" trivial nachlesbar gewesen waere. Jetzt wird real aufgeloest
    (siehe _resolve_interface_list_members()/_interface_list_covers_lan()); eine negierte Liste
    (z.B. das RouterOS-IPv6-Defconf-Muster "in-interface-list=!LAN") bleibt bewusst unaufgeloest
    -- zu vieldeutig fuer diese Version. (d) "filter_path" erlaubt dieselbe Auswertung auch
    gegen "/ipv6 firewall filter" -- Feldnamen live gegen den Test-hAP (10.09.2026) identisch
    zu IPv4 bestaetigt.
    """
    output = router(f'{filter_path} print terse where chain=forward')
    if not parse_terse(output):
        return None
    # Die Regeln muessen den Eingang im Router treffen, nicht zwingend das Gast-Interface, siehe
    # _gast_eingang(). Leer heisst: Hier wird das Gastnetz nicht geroutet, siehe _gast_befund().
    if eingang is None:
        eingang = _gast_eingang(safe_interface, filter_path)
    if not eingang:
        return None
    ausser = _gast_ausnahmen(eingang, eigener_eingang)
    if ausser is None:
        return None
    ziele = _geroutete_ziele(filter_path, eingang)
    if ziele is None:
        return None
    privat = _privat_adressiert(filter_path)
    zustand_unzuverlaessig = _zustand_unzuverlaessig(filter_path)
    invalid_gesperrt = False
    for row in parse_regeln(output):
        if row.get(REGEL_UNKLAR):
            return None
        # Eine Sperre, die wir nicht ganz verstehen, oeffnet trotzdem nichts: Sie ist kein Beleg, aber auch
        # kein Grund aufzugeben. Bei einer Freigabe bleibt es unklar. Sonst waere jede Standardfirewall unklar.
        sperrt = row.get("action") in ("drop", "reject")
        # Nur bestehende Verbindungen eroeffnen nichts, auch bei negiertem Eingang. Am L009 steht so die
        # FastTrack-Regel aus dem CAKE-Umbau: in-interface=!pppoe-out1.
        if not zustand_unzuverlaessig and set(row.get("connection-state", "-").split(",")) <= {"established", "related", "untracked"}:
            continue
        in_if_list = row.get("in-interface-list")
        if in_if_list:
            if in_if_list.startswith("!"):
                if sperrt:
                    continue
                return None
            members = _resolve_interface_list_members(in_if_list, nur_aktive=True)
            if members is None:
                if sperrt:
                    continue
                return None
            if not members & eingang:
                continue
            # Gastnetz ist Mitglied dieser Liste -- Regel gilt fuer das Gastnetz, genau wie ein
            # direktes "in-interface=<Gastnetz>".
        else:
            in_if = row.get("in-interface")
            if in_if and in_if.startswith("!"):
                if in_if[1:] in eingang or sperrt:
                    continue
                return None
            if in_if and in_if.startswith("all-"):
                # all-vlan, all-ethernet und Co. enthalten den Eingang vermutlich, das steht aber in keiner Liste.
                if sperrt:
                    continue
                return None
            if in_if and in_if not in eingang:
                continue
        # Regeln, die ausschliesslich schon bestehende Verbindungen betreffen (z.B. die
        # RouterOS-Standardregel "accept established,related,untracked"), koennen keine
        # NEUE Verbindung vom Gastnetz ins Hausnetz eroeffnen -- ohne eine bereits akzeptierte
        # "new"-Verbindung gibt es nichts, das "established" werden koennte. Sie zaehlen
        # deshalb nicht als Bruch der Isolation.
        conn_state = row.get("connection-state", "")
        if "!" in conn_state or (conn_state and zustand_unzuverlaessig):
            if sperrt:
                continue
            return None
        if conn_state and "new" not in conn_state.split(","):
            if sperrt and "invalid" in conn_state.split(",") and not _has_unresolved_matchers(row, {"in-interface", "in-interface-list", "connection-state"}):
                invalid_gesperrt = True
            continue
        if row.get("action") == "accept" and row.get("src-address") and _absender_schliesst_gast_aus(row, eingang, filter_path):
            continue
        source_list = row.get("src-address-list")
        destination_list = row.get("dst-address-list")
        # IPv6-Adresslisten sind eigene Listen, auch bei gleichem Namen. Gelesen werden unten aber
        # nur die IPv4-Listen und -Adressen. Damit laesst sich fuer IPv6 nichts belegen.
        if (source_list or destination_list) and filter_path != "/ip firewall filter":
            if sperrt:
                continue
            return None
        if source_list:
            source_covers_guest = all(_address_list_covers_interface(source_list, name) is True for name in eingang)
            # Eine eingeschränkte Accept-Regel könnte einzelnen Gastadressen Zugang geben;
            # eine eingeschränkte Drop-Regel kann nicht die gesamte Gastgruppe schützen. In
            # beiden Fällen lässt sich ohne vollständige Adressraum-Simulation nichts Ehrliches
            # behaupten. Dynamische und Teil-Listen fallen ebenfalls hier hinein.
            if not source_covers_guest:
                if sperrt:
                    continue
                return None
        if destination_list:
            destination_covers_lan = _address_list_covers_interface(destination_list, "LAN", ausser)
            if destination_covers_lan is not True or not all(_address_list_covers_interface(destination_list, ziel) is True for ziel in ziele):
                if sperrt:
                    continue
                return None
        out_if_list = row.get("out-interface-list")
        out_if = row.get("out-interface")
        if row.get("action") in ("jump", "return"):
            return None
        # Eine Sperre "alles ausser WAN" trifft auch das Hausnetz, wenn WAN nachweislich nicht dazugehoert.
        # Sie wirkt dann wie eine Regel ohne Ziel. Am L009 steht sie als out-interface=!pppoe-out1.
        negiertes_ziel = set()
        if out_if_list and out_if_list.startswith("!"):
            # Am CHR gemessen: "member print where list=!WAN" ist leer. Die Liste galte sonst als
            # disjunkt zum Hausnetz, und eine Freigabe "out-interface-list=!WAN" fiele durch.
            ausgenommen = _resolve_interface_list_members(out_if_list[1:])
            if not sperrt or (ausgenommen or set()) & ziele or _interface_list_covers_lan(out_if_list[1:], ausser) is not False:
                return None
            out_if_list = None
        if out_if and out_if.startswith("!") and sperrt:
            lan_alle = _resolve_interface_list_members("LAN")
            if lan_alle and lan_alle - ausser and out_if[1:] not in lan_alle and out_if[1:] not in ziele:
                out_if = None
                negiertes_ziel = {"out-interface"}
        list_targets_lan = out_if_list == "LAN"
        list_unresolved = bool(out_if_list) and out_if_list != "LAN"
        if list_unresolved:
            covers = _interface_list_covers_lan(out_if_list, ausser)
            list_targets_lan = covers is True
            list_unresolved = covers is None
        elif list_targets_lan:
            lan_alle = _resolve_interface_list_members("LAN")
            lan_aktiv = _resolve_interface_list_members("LAN", nur_aktive=True)
            if lan_aktiv is None or not (lan_alle or set()) - ausser:
                # Unlesbar, leer oder nur Gastnetz und Bridge-Ports: Die Regel belegt nichts ueber das Hausnetz.
                list_targets_lan = False
                list_unresolved = True
            elif row.get("action") == "accept":
                # Trifft die Freigabe mindestens ein aktives Mitglied, ist das Leck belegt. Ohne
                # aktives Mitglied trifft sie nichts.
                list_targets_lan = bool(lan_aktiv - ausser)
            elif (lan_alle - lan_aktiv) - ausser:
                # Die Sperre deckt "LAN" nur teilweise ab: Das abgeschaltete Mitglied bleibt Hausnetz,
                # wird von ihr aber nicht erfasst. Das Gastnetz selbst zaehlt dabei nicht.
                list_targets_lan = False
                list_unresolved = True
        if row.get("action") == "accept" and out_if:
            # Am L009 und im Labor: "accept in=Gast out=WAN" ist die uebliche Internet-Freigabe.
            # Ein Leck ins Hausnetz ist nur belegt bei LAN oder einem privaten Netz ausserhalb von WAN. Ein
            # oeffentliches Ziel ausserhalb der Liste WAN ist vermutlich der Internetzugang. Hinter einem
            # privaten WAN kann eine Sperre per Adresse davor stehen, das liest diese Pruefung nicht.
            lan_alle = _resolve_interface_list_members("LAN") or set()
            wan = _resolve_interface_list_members("WAN") or set()
            if out_if in (lan_alle - ausser) or (out_if in ziele & privat and out_if not in wan):
                if _has_unresolved_matchers(row, {"in-interface", "in-interface-list", "out-interface", "connection-state"}):
                    return None
                return False
            if out_if in wan and out_if not in ziele:
                continue
            return None
        if row.get("action") == "accept" and list_unresolved:
            # Ob eine nicht aufloesbare Liste LAN-Mitglieder enthält, ist nicht nachgewiesen.
            return None
        rule_list_members = None
        if out_if_list:
            rule_list_members = _resolve_interface_list_members(out_if_list, nur_aktive=True)
            # Eine Freigabe auf eine Liste ausserhalb von LAN erreicht trotzdem jedes geroutete Mitglied.
            # Belegt ist das Leck nur bei einem privaten Netz ausserhalb von WAN, wie bei out-interface oben.
            if row.get("action") == "accept" and rule_list_members and not list_targets_lan:
                getroffen = rule_list_members & ziele
                if getroffen & privat - (_resolve_interface_list_members("WAN") or set()):
                    list_targets_lan = True
                elif getroffen:
                    return None
        targets_lan = list_targets_lan or out_if == "LAN"
        targets_anything = not out_if_list and not out_if
        if not (targets_lan or targets_anything):
            continue
        action = row.get("action")
        if action == "accept":
            # Eine Accept-Regel ohne Interface-Einschraenkung, aber mit z.B.
            # ipsec-policy=in,ipsec, darf nicht als pauschale Freigabe gelten. Der frühere
            # targets_anything-Zweig übersah solche Matcher und meldete fälschlich ein Leck.
            unterstuetzt = {
                "in-interface", "in-interface-list", "out-interface", "out-interface-list",
                "connection-state", "src-address-list", "dst-address-list",
            }
            if row.get("ipsec-policy") and not _has_unresolved_matchers(row, unterstuetzt | {"ipsec-policy"}) and _keine_ipsec_policy():
                continue
            if _has_unresolved_matchers(row, unterstuetzt):
                return None
            return False
        if not sperrt:
            continue
        # Nur eine Drop-Regel OHNE Protokoll-/Port-Einschraenkung deckt wirklich jeden
        # Verkehr zwischen Gastnetz und Hausnetz ab. Eine Regel, die z.B. nur
        # "protocol=tcp dst-port=80" sperrt, laesst jeden anderen Port/jedes andere
        # Protokoll offen -- das ist keine vollstaendige Isolation.
        if _has_unresolved_matchers(row, {"in-interface", "in-interface-list", "out-interface-list", "connection-state", "src-address-list", "dst-address-list"} | negiertes_ziel):
            continue
        # Die Sperre muss auch jedes andere geroutete Netz treffen, nicht nur die Liste "LAN".
        if out_if_list and (rule_list_members is None or ziele - rule_list_members):
            continue
        # Ohne Sperre fuer invalid kommen einzelne Pakete an einer Regel fuer "new" vorbei.
        if conn_state and not invalid_gesperrt and "invalid" not in conn_state.split(","):
            continue
        return True
    return None


def _gast_layer2(safe_interface: str) -> dict:
    """Layer-2-Urteil. "getrennt": True, False oder None, dazu wie es belegt ist.

    "eigener_eingang" sagt, ob der Eingang im Router dem Gastnetz allein gehoert. Bei einem
    Bridge-Filter auf einer gemeinsamen Bridge ist er zugleich das Hausnetz.
    """
    try:
        bridge_name = _bridge_port_of(safe_interface)
    except (RouterCommandFailed, RouterUnreachable):
        return {"getrennt": None, "bridge": None, "eigener_eingang": True, "beleg": "unlesbar"}
    if not bridge_name:
        # Am hAP ax2 gemessen: Ein Name mit dem Rohbyte 0xB2 steht in terse als "axB2", eine Abfrage damit
        # findet nichts. Ohne diese Probe hiesse das "kein Bridge-Port", also getrennt.
        try:
            vorhanden = parse_terse(router(f'/interface print terse where name="{safe_interface}"'))
        except (RouterCommandFailed, RouterUnreachable):
            return {"getrennt": None, "bridge": None, "eigener_eingang": True, "beleg": "unlesbar"}
        if not vorhanden:
            return {"getrennt": None, "bridge": None, "eigener_eingang": True, "beleg": "name_unbekannt"}
        return {"getrennt": True, "bridge": None, "eigener_eingang": True, "beleg": "keine_bridge"}
    if _bridge_vlan_filter(bridge_name):
        vlan = _vlan_isolation(safe_interface, bridge_name)
        if vlan is True:
            return {"getrennt": True, "bridge": bridge_name, "eigener_eingang": True, "beleg": "vlan"}
        if _port_im_switch_chip(safe_interface) is False and _bridge_filter_isolation(safe_interface, bridge_name) is True:
            return {"getrennt": True, "bridge": bridge_name, "eigener_eingang": False, "beleg": "filter"}
        return {"getrennt": vlan, "bridge": bridge_name, "eigener_eingang": True, "beleg": "vlan_geteilt" if vlan is False else "vlan_unklar"}
    bypass = _guest_bridge_bypass(safe_interface)
    if bypass is False:
        return {"getrennt": True, "bridge": bridge_name, "eigener_eingang": True, "beleg": "eigene_bridge"}
    if bypass is None:
        return {"getrennt": None, "bridge": bridge_name, "eigener_eingang": True, "beleg": "unlesbar"}
    if _port_im_switch_chip(safe_interface) is False and _bridge_filter_isolation(safe_interface, bridge_name) is True:
        return {"getrennt": True, "bridge": bridge_name, "eigener_eingang": False, "beleg": "filter"}
    return {"getrennt": False, "bridge": bridge_name, "eigener_eingang": False, "beleg": "bypass"}


def _gast_hat_weiteren_weg(safe_interface: str, bridge_name: str) -> bool:
    """Fuehrt ein anderer Port aus dem Gast-VLAN oder der Gast-Bridge hinaus? Im Zweifel ja."""
    try:
        port_rows = _terse_ohne_abgeschaltete(router(f'/interface bridge port print terse where interface="{safe_interface}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return True
    if not port_rows:
        return True
    if _bridge_vlan_filter(bridge_name):
        mitglieder = _gast_vlan_mitglieder(safe_interface, bridge_name, port_rows[0].get("pvid", "1"))
    else:
        mitglieder = _bridge_siblings(bridge_name, safe_interface)
    return mitglieder is None or bool(mitglieder)


def _gast_layer3(safe_interface: str, schicht2: dict, filter_path: str) -> bool | str | None:
    """Layer-3-Urteil fuer eine Adressfamilie: True, False, None, "extern" oder "insel".

    "extern": Hier routet nichts, aber das Gast-VLAN verlaesst das Geraet. Der Router steht woanders.
    "insel": Hier routet nichts, und es gibt keinen Weg hinaus.
    """
    # L3-Hardware-Offload routet im Chip an der Firewall vorbei (manual.mikrotik.com, L3 Hardware
    # Offloading). Am hAP ax2 steht das Feld nicht, am CHR nicht messbar.
    try:
        if any(row.get("l3-hw-offloading", "").lower() in ("yes", "true")
               for row in _terse_ohne_abgeschaltete(router("/interface ethernet switch print terse"))):
            return None
    except RouterUnreachable:
        return None
    except RouterCommandFailed as exc:
        if not _befehl_fehlt(exc):
            return None
    eingang = _gast_eingang(safe_interface, filter_path)
    if eingang is None:
        return None
    ist_ipv6 = filter_path.startswith("/ipv6")
    if ist_ipv6:
        kandidaten = eingang or _gast_eingang(safe_interface, filter_path, auch_ohne_adresse=True)
        if kandidaten is None:
            return None
        if kandidaten:
            ziele = _geroutete_ziele(filter_path, kandidaten)
            if ziele is None:
                return None
            if not ziele:
                return "keine_adresse"
            return _guest_isolation(safe_interface, filter_path=filter_path, eigener_eingang=schicht2["eigener_eingang"], eingang=kandidaten)
    if not eingang:
        if not schicht2["bridge"] or _gast_hat_weiteren_weg(safe_interface, schicht2["bridge"]):
            return "extern"
        return "insel"
    return _guest_isolation(safe_interface, filter_path=filter_path, eigener_eingang=schicht2["eigener_eingang"])


def _gast_befund(safe_interface: str) -> dict:
    """Das eine Urteil fuer Sicherheitscheck und Pro-Karte, Layer 2 und Layer 3 zusammen.

    "good" gilt nur, wenn Gast und Hausnetz auf beiden Wegen getrennt sind. Eine VLAN-Trennung allein
    reicht nicht: Der Router kann zwischen den VLANs routen, am CHR mit echten Clients gemessen.
    """
    schicht2 = _gast_layer2(safe_interface)
    v4 = _gast_layer3(safe_interface, schicht2, "/ip firewall filter")
    ipv6_an = _ipv6_relevant()
    if ipv6_an:
        v6 = _gast_layer3(safe_interface, schicht2, "/ipv6 firewall filter")
    else:
        v6 = True if ipv6_an is False else None

    teile = [schicht2["getrennt"], v4, v6]
    if False in teile:
        status = "warn"
    elif all(teil is True or teil in ("insel", "keine_adresse") for teil in teile):
        status = "good"
    else:
        status = "unknown"
    hinter_router = bool((_resolve_interface_list_members("WAN") or set()) & _privat_adressiert("/ip firewall filter"))
    return {"status": status, "schicht2": schicht2, "v4": v4, "v6": v6, "ipv6_an": ipv6_an, "hinter_router": hinter_router}


def _guest_row(interface: str) -> tuple[str, dict] | None:
    """Liest ein bereits validiertes Gastnetz-Interface, treiberunabhaengig (wireless/wifi)."""
    safe_interface = interface
    driver = _wireless_driver(safe_interface, validated=True)
    if driver is None:
        return None
    path = "wireless" if driver == "wireless" else "wifi"
    ssid_field = "ssid" if driver == "wireless" else "configuration.ssid"
    rows = parse_terse(router(f'/interface {path} print terse where name="{safe_interface}"'))
    if not rows:
        return None
    row = rows[0]
    return path, {
        "enabled": not row["disabled"],
        "ssid": row.get(ssid_field),
        "isolated": {"good": True, "warn": False}.get(_gast_befund(safe_interface)["status"]),
    }
