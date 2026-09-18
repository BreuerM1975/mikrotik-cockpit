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

import ipaddress
import os
import threading

from flask import request

from config import load_config
from routeros import (
    RouterCommandFailed,
    RouterUnreachable,
    parse_colon,
    parse_terse,
    run_command,
)

cfg = load_config()

# Verbinden-Modell wie WinBox (siehe dem Verbinden-Modell): keine fest
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


def current_conn() -> dict:
    return SESSIONS[request.headers["X-Cockpit-Session"]]


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


# RouterOS-Standardgruppen. Benutzer in selbst angelegten Gruppen (eigene Policy-Kombination)
# werden angezeigt, aber Cockpit bietet fuer sie keinen Gruppenwechsel an und zaehlt sie beim
# Schutz des letzten Vollzugangs bewusst NICHT mit (konservativ: lieber eine Sperre zu viel).
USER_GROUPS = ("full", "write", "read")
DEFAULT_ADMIN_USER = "admin"


def list_users() -> list[dict]:
    # Gemeinsame Quelle fuer den Sicherheits-Check (Basis) und die Benutzerverwaltung (Pro).
    # Live am 18.09. (Dossier mikrotik-experte, hAP 7.23.1): "disabled" kommt in `print terse`
    # nur als Flag X vor dem ersten key= (parse_terse setzt row["disabled"] daraus), das Flag E
    # heisst "Passwort abgelaufen"; `last-logged-in` FEHLT komplett, wenn sich der Benutzer nie
    # angemeldet hat, und enthaelt sonst ein Leerzeichen zwischen Datum und Uhrzeit.
    rows = parse_terse(router("/user print terse"))
    users = []
    for row in rows:
        name = row.get("name")
        if not name:
            continue
        users.append({
            "name": name,
            "group": row.get("group", ""),
            "disabled": bool(row.get("disabled")),
            "last_logged_in": row.get("last-logged-in") or None,
            "address": row.get("address", ""),
            "comment": row.get("comment", ""),
        })
    return users


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


def _resolve_interface_list_members(list_name: str) -> set[str] | None:
    """Löst eine RouterOS-Interface-Liste (z.B. "LAN") zu ihren tatsächlichen Mitgliedsnamen auf.

    Audit "Listenmitgliedschaft", 10.09.2026: vorher wurde jede Liste, die nicht wörtlich "LAN"
    hieß, pauschal als unauflösbar behandelt -- auch wenn ihre Mitgliedschaft per
    "/interface list member print" trivial nachlesbar gewesen wäre (z.B. eine selbst benannte
    Liste "Hausnetz", die exakt dieselben Interfaces wie "LAN" enthält). Live-Beispiel gegen den
    Test-hAP (10.09.2026): die Liste "LAN" enthält dort ein einzelnes Mitglied, "bridge" (die
    Bridge selbst, nicht die einzelnen Ports) -- ".../list member print" liefert genau das.

    None: nicht sicher auflösbar (Router nicht erreichbar, Befehl fehlgeschlagen, oder ein
    Eintrag ohne lesbares "interface"-Feld) -- dann lieber ehrlich unklar bleiben als raten.
    """
    try:
        rows = parse_terse(router(f'/interface list member print terse where list="{list_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    members = set()
    for row in rows:
        iface = row.get("interface")
        if not iface:
            return None
        members.add(iface)
    return members


def _interface_list_covers_lan(list_name: str) -> bool | None:
    """Vergleicht eine beliebige Interface-Liste mit der Liste "LAN" über ihre tatsächlichen
    Mitglieder statt über den Listennamen.

    True: deckt alle LAN-Mitglieder ab (verhält sich für eine Drop-Regel wie "LAN" selbst).
    False: nachweislich disjunkt zu LAN (die Regel betrifft das Hausnetz nachweislich nicht).
    None: teilweise Überschneidung oder nicht auflösbar -- bleibt ehrlich unklar.
    """
    lan_members = _resolve_interface_list_members("LAN")
    if not lan_members:
        return None
    members = _resolve_interface_list_members(list_name)
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
    rows = parse_terse(output)
    if output.strip() and not rows:
        return None
    networks = set()
    for row in rows:
        value = row.get("address")
        if not value:
            return None
        try:
            networks.add(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return None
    return networks


def _address_list_covers_interface(list_name: str, interface: str) -> bool | None:
    """Vergleicht eine statische Adressliste mit allen IPv4/IPv6-Netzen eines Interfaces.

    True bedeutet: Jede Adresse des Interfaces liegt nachweislich in mindestens einem einzelnen
    Listeneintrag. False bedeutet: Die Liste ist vollständig disjunkt. Teilüberdeckungen und
    mehrere Einträge, die ein Netz nur gemeinsam abdecken könnten, bleiben absichtlich unknown.
    """
    listed = _static_address_list_networks(list_name)
    if listed is None:
        return None
    interface_networks = set()
    interfaces = _resolve_interface_list_members("LAN") if interface == "LAN" else {interface}
    if not interfaces:
        return None
    for name in interfaces:
        try:
            safe_interface = _routeros_value(name, "interface")
            output = router(f'/ip address print terse where interface="{safe_interface}"')
        except (ValueError, RouterCommandFailed, RouterUnreachable):
            return None
        rows = parse_terse(output)
        if (output.strip() and not rows) or not rows:
            return None
        for row in rows:
            value = row.get("address")
            if not value:
                return None
            try:
                interface_networks.add(ipaddress.ip_interface(value).network)
            except ValueError:
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
    rows = parse_terse(router(f'/interface bridge port print terse where interface="{safe_interface}"'))
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
    if lan_members is None:
        return None
    same_bridge_is_lan = bridge_name in lan_members
    if not same_bridge_is_lan:
        # Die Bridge selbst ist kein LAN-Mitglied -- prüfen, ob ein ANDERER Port derselben
        # Bridge individuell in der LAN-Liste steht (falls die Liste einzelne Ports statt der
        # Bridge selbst enthält).
        try:
            all_ports = parse_terse(router(f'/interface bridge port print terse where bridge="{bridge_name}"'))
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
    return settings.get("use-ip-firewall", "no").strip().lower() != "yes"


def _bridge_siblings(bridge_name: str, exclude: str) -> set[str] | None:
    """Alle Ports derselben Bridge außer "exclude" (typischerweise das Gastnetz-Interface
    selbst). None: Portliste nicht lesbar."""
    try:
        rows = parse_terse(router(f'/interface bridge port print terse where bridge="{bridge_name}"'))
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
    members = _resolve_interface_list_members(list_name)
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
    rows = parse_terse(output)
    if output.strip() and not rows:
        return None
    for row in rows:
        if row.get("disabled"):
            continue
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
            members = _resolve_interface_list_members(in_if_list)
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
        targets_lan = list_targets_lan or (bool(out_if) and out_if in lan_ports)
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

    True: die VLAN-ID des Gastnetz-Ports hat nachweislich KEINEN Hausnetz-Port als Mitglied.
    False: mindestens ein Hausnetz-Port teilt sich nachweislich dieselbe VLAN-ID.
    None: VLAN-Filterung nicht aktiv, kein Tabelleneintrag für die Gastnetz-VLAN-ID gefunden
    (absichtlich konservativ -- kein Rückschluss auf RouterOS' Default-Drop-Verhalten ohne
    Tabelleneintrag), oder etwas davon nicht lesbar/auflösbar -- inkl. dem Regelfall am Test-hAP
    (10.09.2026: vlan-filtering=no, keine VLAN-Tabelleneinträge)."""
    try:
        bridge_rows = parse_terse(router(f'/interface bridge print terse where name="{bridge_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if not bridge_rows:
        return None
    if bridge_rows[0].get("vlan-filtering", "no").strip().lower() != "yes":
        return None

    try:
        port_rows = parse_terse(router(f'/interface bridge port print terse where interface="{safe_interface}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    if not port_rows:
        return None
    pvid = port_rows[0].get("pvid", "1")

    lan_ports = _bridge_lan_ports(bridge_name, safe_interface)
    if lan_ports is None:
        return None

    try:
        vlan_rows = parse_terse(router(f'/interface bridge vlan print terse where bridge="{bridge_name}"'))
    except (RouterCommandFailed, RouterUnreachable):
        return None
    matching = [row for row in vlan_rows
                if not row.get("disabled") and pvid in {v.strip() for v in row.get("vlan-ids", "").split(",") if v.strip()}]
    if not matching:
        # Kein Tabelleneintrag fuer diese VLAN-ID -- RouterOS' Default-Verhalten (Egress-Drop
        # ohne Eintrag) koennte tatsaechlich isolieren, ist hier aber bewusst nicht als Nachweis
        # gewertet, siehe Docstring.
        return None

    members: set[str] = set()
    for row in matching:
        for key in ("current-tagged", "current-untagged", "tagged", "untagged"):
            members |= {v.strip() for v in row.get(key, "").split(",") if v.strip()}
    members.discard(safe_interface)

    if not lan_ports:
        # Kein anderer Bridge-Port zaehlt als Hausnetz (z.B. ein Ein-Port-Testaufbau) --
        # kein belastbarer Nachweis, konservativ unklar.
        return None
    if members & lan_ports:
        return False
    return True


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


def _guest_isolation(safe_interface: str, filter_path: str = "/ip firewall filter") -> bool | None:
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
    rows = parse_terse(output)
    if output.strip() and not rows:
        return None
    for row in rows:
        if row.get("disabled"):
            continue
        in_if_list = row.get("in-interface-list")
        if in_if_list:
            if in_if_list.startswith("!"):
                return None
            members = _resolve_interface_list_members(in_if_list)
            if members is None:
                return None
            if safe_interface not in members:
                continue
            # Gastnetz ist Mitglied dieser Liste -- Regel gilt fuer das Gastnetz, genau wie ein
            # direktes "in-interface=<Gastnetz>".
        else:
            in_if = row.get("in-interface")
            if in_if and in_if.startswith("!"):
                if in_if[1:] == safe_interface:
                    continue
                return None
            if in_if and in_if != safe_interface:
                continue
        # Regeln, die ausschliesslich schon bestehende Verbindungen betreffen (z.B. die
        # RouterOS-Standardregel "accept established,related,untracked"), koennen keine
        # NEUE Verbindung vom Gastnetz ins Hausnetz eroeffnen -- ohne eine bereits akzeptierte
        # "new"-Verbindung gibt es nichts, das "established" werden koennte. Sie zaehlen
        # deshalb nicht als Bruch der Isolation.
        conn_state = row.get("connection-state", "")
        if "!" in conn_state:
            return None
        if conn_state and "new" not in conn_state.split(","):
            continue
        source_list = row.get("src-address-list")
        if source_list:
            source_covers_guest = _address_list_covers_interface(source_list, safe_interface)
            # Eine eingeschränkte Accept-Regel könnte einzelnen Gastadressen Zugang geben;
            # eine eingeschränkte Drop-Regel kann nicht die gesamte Gastgruppe schützen. In
            # beiden Fällen lässt sich ohne vollständige Adressraum-Simulation nichts Ehrliches
            # behaupten. Dynamische und Teil-Listen fallen ebenfalls hier hinein.
            if source_covers_guest is not True:
                return None
        destination_list = row.get("dst-address-list")
        if destination_list:
            destination_covers_lan = _address_list_covers_interface(destination_list, "LAN")
            if destination_covers_lan is not True:
                return None
        out_if_list = row.get("out-interface-list")
        out_if = row.get("out-interface")
        if row.get("action") in ("jump", "return"):
            return None
        list_targets_lan = out_if_list == "LAN"
        list_unresolved = bool(out_if_list) and out_if_list != "LAN"
        if list_unresolved:
            covers = _interface_list_covers_lan(out_if_list)
            list_targets_lan = covers is True
            list_unresolved = covers is None
        if row.get("action") == "accept" and (out_if or list_unresolved):
            # Ob das einzelne Ziel bzw. eine nicht aufloesbare Liste LAN-Mitglieder enthält,
            # ist ohne Topologie-/Listenauflösung nicht nachgewiesen.
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
            if _has_unresolved_matchers(row, {
                "in-interface", "in-interface-list", "out-interface", "out-interface-list",
                "connection-state", "src-address-list", "dst-address-list",
            }):
                return None
            return False
        if action != "drop":
            continue
        # Nur eine Drop-Regel OHNE Protokoll-/Port-Einschraenkung deckt wirklich jeden
        # Verkehr zwischen Gastnetz und Hausnetz ab. Eine Regel, die z.B. nur
        # "protocol=tcp dst-port=80" sperrt, laesst jeden anderen Port/jedes andere
        # Protokoll offen -- das ist keine vollstaendige Isolation.
        if _has_unresolved_matchers(row, {"in-interface", "in-interface-list", "out-interface-list", "connection-state", "src-address-list", "dst-address-list"}):
            continue
        return True
    return None


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
        "isolated": _guest_isolation(safe_interface),
    }
