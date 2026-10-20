import hashlib
import os
import re
import subprocess
import threading


class RouterUnreachable(Exception):
    pass


class RouterTimeout(Exception):
    pass


class RouterAuthFailed(Exception):
    pass


class RouterCommandFailed(Exception):
    pass


class HostKeyUnknown(Exception):
    # Audit A18: Erstkontakt zu einem Router -- der Fingerprint wurde noch nie bestaetigt.
    def __init__(self, fingerprint: str, key_type: str, known_hosts_line: str) -> None:
        super().__init__(fingerprint)
        self.fingerprint = fingerprint
        self.key_type = key_type
        self.known_hosts_line = known_hosts_line


class HostKeyChanged(Exception):
    # Audit A18: der Router praesentiert einen anderen Schluessel als den zuvor bestaetigten --
    # entweder ein neu aufgesetztes Geraet oder ein Man-in-the-Middle. Es gibt bewusst keinen
    # API-Weg, das automatisch zu uebernehmen; der Eintrag muss manuell aus der known_hosts-
    # Datei entfernt werden, nachdem der Kunde den Grund geprueft hat.
    def __init__(self, fingerprint: str, key_type: str) -> None:
        super().__init__(fingerprint)
        self.fingerprint = fingerprint
        self.key_type = key_type


_KEY_TYPE_PREFERENCE = [
    "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
]


def _scan_host_key(host: str, port: int, timeout: int = 10) -> str:
    # Fragt den Schluessel ab, den der Router JETZT anbietet -- ohne ihn zu vertrauen. Bei
    # mehreren angebotenen Algorithmen wird bewusst der staerkste gewaehlt.
    result = subprocess.run(
        # "--" trennt Optionen vom Hostargument: ohne das liest ssh-keyscan einen Wert, der
        # mit "-" beginnt, als eigene Option. Der Wert wird zusaetzlich am Eingang geprueft
        # (routes_basis._verbindungs_host), das hier ist die zweite Schranke.
        ["ssh-keyscan", "-p", str(port), "-T", str(timeout), "--", host],
        capture_output=True, text=True, timeout=timeout + 5,
    )
    lines = [line for line in result.stdout.splitlines() if line and not line.startswith("#")]
    if not lines:
        raise RouterUnreachable(
            result.stderr.strip() or f"Kein SSH-Dienst auf Port {port} erreichbar"
        )

    def rank(line: str) -> int:
        parts = line.split()
        key_type = parts[1] if len(parts) > 1 else ""
        return _KEY_TYPE_PREFERENCE.index(key_type) if key_type in _KEY_TYPE_PREFERENCE else len(_KEY_TYPE_PREFERENCE)

    lines.sort(key=rank)
    return lines[0]


def _fingerprint_of(known_hosts_line: str) -> str:
    result = subprocess.run(
        ["ssh-keygen", "-lf", "-"], input=known_hosts_line + "\n",
        capture_output=True, text=True, timeout=5,
    )
    for token in result.stdout.split():
        if token.startswith("SHA256:"):
            return token
    return result.stdout.strip()


def _lookup_known_host(host: str, port: int, known_hosts_path: str) -> list[tuple[str, str]]:
    if not os.path.exists(known_hosts_path):
        return []
    # Audit Runde 3, Befund 1 (P0): eine Datei, die nicht dem eigenen Prozess gehoert oder fuer
    # Gruppe/Andere beschreibbar ist, koennte von einem Dritten VOR dem ersten echten Connect
    # dort platziert worden sein (live nachgewiesen: das hebelt den ganzen Fingerprint-Dialog
    # unsichtbar aus, wenn der Dritte den echten Schluessel vorab per ssh-keyscan eingetragen
    # hat). Deren Inhalt wird deshalb NICHT vertraut -- als "kein gespeicherter Eintrag" behandelt,
    # was fuer diesen Host wieder den regulaeren, vom Menschen zu bestaetigenden Erstkontakt
    # erzwingt, statt den fremden Eintrag zu glauben.
    stat = os.stat(known_hosts_path)
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        return []
    lookup_host = f"[{host}]:{port}" if port != 22 else host
    result = subprocess.run(
        ["ssh-keygen", "-F", lookup_host, "-f", known_hosts_path],
        capture_output=True, text=True, timeout=5,
    )
    entries = []
    for line in result.stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            entries.append((parts[1], parts[2]))
    return entries


def ensure_host_key_trusted(host: str, port: int, known_hosts_path: str, timeout: int = 10) -> None:
    """Wirft HostKeyUnknown beim allerersten Kontakt, HostKeyChanged bei einem abweichenden
    Schluessel gegenueber einem bereits gespeicherten. Kehrt sonst kommentarlos zurueck."""
    raw_line = _scan_host_key(host, port, timeout)
    parts = raw_line.split()
    key_type = parts[1]
    key_value = parts[2] if len(parts) > 2 else ""
    stored = _lookup_known_host(host, port, known_hosts_path)
    if not stored:
        raise HostKeyUnknown(_fingerprint_of(raw_line), key_type, raw_line)
    if (key_type, key_value) not in stored:
        raise HostKeyChanged(_fingerprint_of(raw_line), key_type)


def trust_host_key(known_hosts_path: str, known_hosts_line: str) -> None:
    # Audit Runde 3, Befund 1: Verzeichnis nur fuer den eigenen Nutzer lesbar/betretbar anlegen,
    # und die Datei von Anfang an mit 0600 statt sie erst per open()+chmod() danach zu haerten
    # (das offene Zeitfenster mit Default-Rechten dazwischen ist unnoetig).
    directory = os.path.dirname(known_hosts_path) or "."
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o700)
    fd = os.open(known_hosts_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.write(fd, (known_hosts_line.strip() + "\n").encode())
    finally:
        os.close(fd)
    os.chmod(known_hosts_path, 0o600)


# Audit A14, 09.09.: RouterOS gibt bei bestimmten Fehlern (ungueltiger Wert, fehlende Rechte,
# Syntaxfehler in Skript-Kontext) trotzdem Exitcode 0 zurueck -- der SSH-Aufruf "gelingt", nur
# die eigentliche Aktion nicht. Live bestaetigt: "/ip pool add ... ranges=nicht-valide" liefert
# Exitcode 0 mit "value of range must have ip address before '-' (/ip/pool/add (range); line 1)"
# auf stdout. Erfolgreiche schreibende Befehle (add/set/remove/enable/disable) geben normalerweise
# GAR NICHTS aus -- diese Muster sind eine bekannte, aber nicht zwingend vollstaendige Liste von
# RouterOS-eigenen Fehlertexten, kein Ersatz fuer eine echte Nachpruefung des Ergebnisses.
# Audit Runde 3, Befund 2: "bad command name" (fehlendes RouterOS-Menue/-Paket, z.B. WireGuard
# auf einem alten RouterOS-6-Geraet ohne das Paket) fehlte hier -- live beobachtet, dass RouterOS
# diesen Fehler nicht zuverlaessig mit einem bestimmten Exitcode verknuepft (7 von 8 Durchlaeufen
# Exitcode 1, einmal Exitcode 0 bei identischem Befehl/Router). Der Text selbst ist das einzig
# verlaessliche Signal.
# Live-Fund A13-Rest (09.09., Restore-Test): "/system backup load" ohne "password" liefert
# "Script Error: missing value(s) of argument(s) password (...)" -- ebenfalls Exitcode 0,
# ebenfalls bisher unerkannt. "script error" deckt diese ganze RouterOS-Fehlerklasse (fehlende
# Pflichtparameter bei Menü-Befehlen) generisch ab, nicht nur diesen einen Fall.
_ROUTEROS_ERROR_RE = re.compile(
    r"^(failure:|no such item|bad command name|input does not match|expected end of command|"
    r"ambiguous value|syntax error|script error|value of .+ (must|is not|out of range)|"
    r"not enough permissions|invalid value for argument)",
    re.IGNORECASE,
)


# SSH-Verbindungsmultiplexing (Schritt 0 des Multisession-Umbaus).
#
# Bisher startete jeder einzelne Routerbefehl einen eigenen ssh-Prozess mit vollem Handshake.
# Ein kompletter Oberflaechen-Durchlauf ("loadAll") sind rund zwoelf Befehle -- also zwoelf
# Anmeldungen und zwoelf gleichzeitige Sitzungen am Router. Fuer Multisession mit mehreren
# Geraeten vervielfacht sich das, und wer so pollt, sammelt am Router hunderte offene Sitzungen
# an, weil jeder Aufruf eine neue aufmacht und keine davon geschlossen wird.
#
# Mit Multiplexing haelt eine Master-Verbindung offen, alle Befehle laufen als Kanal darueber.
# Am 2026-10-17 live am hAP ac Lite gemessen, zwoelf Befehle:
#   nacheinander  7,22 s -> 0,90 s (602 ms -> 75 ms je Befehl)
#   gleichzeitig  5,54 s -> 1,06 s, und die gleichzeitigen Routersitzungen 12 -> 1
#
# Sicherheit: Der Kontrollsocket ist, solange er lebt, ein passwortfreier Zugang zum Router.
# Wer ihn lesen/schreiben kann, kann darueber Befehle ausfuehren, ohne das Routerpasswort zu
# kennen. Er gehoert deshalb in dasselbe private ~/.config-Verzeichnis wie known_hosts und die
# Backups (Audit Runde 3, Befund 1: ein world-schreibbarer /tmp-Pfad mit vorhersehbarem Namen
# war dort schon einmal ein P0-Fund) und niemals nach /tmp. Der Dateiname ist ein Hash aus
# Benutzer, Host und Port -- so steht im Dateisystem nicht, welche Router hier verwaltet werden.
#
# Fail-safe statt fail-closed: Laesst sich das Verzeichnis nicht sicher herstellen oder ist der
# Pfad zu lang fuer einen Unix-Socket, wird Multiplexing still uebersprungen. Der Rueckfall ist
# genau das bisherige, bereits geprueft abgesicherte Verhalten -- ein Prozess je Befehl. Eine
# Optimierung darf das Werkzeug nicht blockieren.
_CONTROL_DIR = os.environ.get(
    "COCKPIT_SSH_CONTROL_DIR",
    os.path.join(os.path.expanduser("~/.config/mikrotik-cockpit"), "ssh"),
)
_CONTROL_PERSIST = os.environ.get("COCKPIT_SSH_CONTROL_PERSIST", "60s")
# Linux begrenzt Unix-Socket-Pfade auf 108 Zeichen (sun_path); ssh haengt an den ControlPath
# zeitweise noch ".<zufall>" an. 100 laesst dafuer Luft.
_CONTROL_PATH_MAX = 100


def multiplexing_enabled() -> bool:
    return os.environ.get("COCKPIT_SSH_MULTIPLEXING", "1").strip().lower() not in (
        "0", "false", "no", "off",
    )


def _control_path(host: str, user: str, port: int) -> str | None:
    """Pfad des Kontrollsockets fuer genau diese Verbindung, oder None, wenn Multiplexing
    hier nicht sicher oder nicht moeglich ist.

    Benutzer, Host und Port gehen zusammen in den Hash: zwei Routerbenutzer am gleichen Geraet
    duerfen sich keinen Socket teilen, sonst liefen Befehle mit den Rechten des falschen Kontos.
    Das Passwort geht bewusst NICHT ein -- sonst waere nach einem Passwortwechsel die alte
    Verbindung noch nutzbar, ohne dass sie jemand findet und beendet.
    """
    if not multiplexing_enabled():
        return None
    try:
        if os.path.islink(_CONTROL_DIR):
            return None
        if os.path.isdir(_CONTROL_DIR):
            stat = os.stat(_CONTROL_DIR)
            if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
                return None
            os.chmod(_CONTROL_DIR, 0o700)
        else:
            os.makedirs(_CONTROL_DIR, mode=0o700, exist_ok=True)
            os.chmod(_CONTROL_DIR, 0o700)
    except OSError:
        return None
    digest = hashlib.sha256(f"{user}@{host}:{int(port)}".encode()).hexdigest()[:16]
    path = os.path.join(_CONTROL_DIR, f"cm-{digest}")
    if len(path) > _CONTROL_PATH_MAX:
        return None
    return path


def _control_opts(host: str, user: str, port: int) -> list[str]:
    """Optionen fuer einen gewoehnlichen Befehl: bestehende Master-Verbindung mitbenutzen,
    aber **nie selbst Master werden**.

    Bewusst `ControlMaster=no` statt `auto`. Mit `auto` war die Aenderung im realistischen Fall
    wirkungslos: die Oberflaeche schickt die rund zwoelf Abfragen eines Durchlaufs per
    `Promise.allSettled` **gleichzeitig**, und zwoelf gleichzeitig startende Prozesse finden alle
    keinen Socket und werden alle selbst Master. Am 2026-10-17 live gemessen: zwoelf parallele
    Befehle am hAP, 5,75 s gegen 5,00 s und in beiden Faellen zehn gleichzeitige Routersitzungen.
    Der Master wird deshalb vorher von genau einem Thread aufgebaut, siehe `_ensure_master()`.

    Fehlt der Socket, baut ssh wie bisher eine eigene Verbindung auf -- langsamer, aber korrekt.
    """
    path = _control_path(host, user, port)
    if path is None:
        return []
    return ["-o", "ControlMaster=no", "-o", f"ControlPath={path}"]


# Begrenzter Lock-Pool wie `_router_create_locks` in core.py: dasselbe Ziel wird beim
# Verbindungsaufbau serialisiert, ohne mit jedem Geraet neue Lock-Objekte anzusammeln.
_master_locks = [threading.Lock() for _ in range(32)]


def _master_running(path: str, host: str, user: str, port: int) -> bool:
    try:
        return subprocess.run(
            ["ssh", "-O", "check", "-o", f"ControlPath={path}", "-p", str(port), f"{user}@{host}"],
            capture_output=True, text=True, timeout=5,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _ensure_master(
    host: str, user: str, password: str, port: int,
    timeout: int, known_hosts_path: str | None, host_key_opts: list[str],
) -> None:
    """Stellt sicher, dass fuer dieses Ziel eine Master-Verbindung laeuft.

    Serialisiert je Ziel: von zwoelf gleichzeitigen Abfragen baut genau eine die Verbindung
    auf, die anderen elf warten kurz und benutzen sie dann mit. Ohne diese Serialisierung
    bringt Multiplexing im parallelen Fall nichts (siehe `_control_opts`).

    Wirft nie. Scheitert der Aufbau -- falsches Passwort, Geraet weg, Multiplexing nicht
    moeglich -- laeuft der eigentliche Befehl danach ohne Socket weiter und liefert seinen
    eigenen, bereits behandelten Fehler. So bleibt die Unterscheidung zwischen
    RouterAuthFailed (sshpass-Exitcode 5) und RouterUnreachable unveraendert erhalten.
    """
    path = _control_path(host, user, port)
    if path is None:
        return
    if os.path.exists(path) and _master_running(path, host, user, port):
        return
    with _master_locks[hash(path) % len(_master_locks)]:
        # Zweite Pruefung unter dem Lock: waehrend des Wartens hat ihn vielleicht schon
        # ein anderer Thread aufgebaut.
        if os.path.exists(path) and _master_running(path, host, user, port):
            return
        try:
            subprocess.run(
                [
                    "sshpass", "-e", "ssh",
                    "-M", "-N", "-f",
                    "-p", str(port),
                    *host_key_opts,
                    "-o", f"ControlPath={path}",
                    "-o", f"ControlPersist={_CONTROL_PERSIST}",
                    "-o", f"ConnectTimeout={timeout}",
                    f"{user}@{host}",
                ],
                env={**os.environ, "SSHPASS": password},
                capture_output=True, text=True, timeout=timeout + 5,
            )
        except (OSError, subprocess.SubprocessError):
            return


def close_connection(host: str, user: str, port: int) -> bool:
    """Beendet die Master-Verbindung zu diesem Geraet, falls eine laeuft.

    Gehoert zum Trennen einer Cockpit-Sitzung: ohne diesen Aufruf bliebe die Routersitzung noch
    die Dauer von ControlPersist offen, obwohl es im Cockpit keine Oberflaeche mehr dazu gibt.
    Gibt True zurueck, wenn eine Verbindung beendet wurde. Wirft nie -- Trennen ist idempotent
    und darf nicht an einem schon verschwundenen Socket scheitern.
    """
    path = _control_path(host, user, port)
    if path is None or not os.path.exists(path):
        return False
    try:
        result = subprocess.run(
            ["ssh", "-O", "exit", "-o", f"ControlPath={path}", "-p", str(port), f"{user}@{host}"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def run_command(
    host: str, user: str, password: str, port: int, command: str,
    timeout: int = 10, known_hosts_path: str | None = None,
    eigene_verbindung: bool = False,
) -> str:
    """Fuehrt einen Befehl auf dem Router aus.

    `eigene_verbindung=True` schaltet die Mitbenutzung eines bestehenden Kontrollsockets ab.
    Das braucht genau eine Stelle: die Passwortpruefung beim Verbinden (routes_basis.connect).
    2026-10-19 gefunden: _control_path() hasht bewusst nur user@host:port ohne Passwort, und
    bei lebendem Socket kehrt _ensure_master() sofort zurueck. Der Pruefbefehl lief dann ueber
    die bereits authentifizierte Verbindung, SSHPASS wurde nie benutzt, und ein /connect mit
    FALSCHEM Passwort antwortete 200, solange die echte Sitzung den Socket offen hielt. Zwei
    Folgen: die Passwortabfrage war in diesem Zeitfenster wirkungslos, und ein Tippfehler im
    Passwort wurde als gueltig gespeichert und fiel erst Tage spaeter auf.
    """
    # Audit A18: "accept-new" hat den allerersten Kontakt zu einem Router still und ohne
    # jede Rueckfrage vertraut -- ensure_host_key_trusted() muss vorher gelaufen sein (siehe
    # app.py:connect()), danach steht der Schluessel bereits fest in known_hosts_path und
    # "yes" verlangt eine exakte Uebereinstimmung, statt einen neuen Schluessel klaglos
    # anzunehmen.
    host_key_opts = (
        ["-o", f"UserKnownHostsFile={known_hosts_path}", "-o", "StrictHostKeyChecking=yes"]
        if known_hosts_path else ["-o", "StrictHostKeyChecking=accept-new"]
    )
    if eigene_verbindung:
        control_opts = ["-o", "ControlPath=none"]
    else:
        _ensure_master(host, user, password, port, timeout, known_hosts_path, host_key_opts)
        control_opts = _control_opts(host, user, port)
    ssh_cmd = [
        "sshpass", "-e", "ssh",
        "-p", str(port),
        *host_key_opts,
        *control_opts,
        "-o", f"ConnectTimeout={timeout}",
        f"{user}@{host}",
        command,
    ]
    env = {**os.environ, "SSHPASS": password}
    try:
        result = subprocess.run(
            ssh_cmd, env=env, capture_output=True, text=True, timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired as exc:
        raise RouterTimeout(str(exc)) from exc
    # Audit Runde 3, Befund 2: dieser Text-Check laeuft jetzt bewusst VOR der Exitcode-
    # Verzweigung. RouterOS' eigener "bad command name"-Fehler ist live sowohl mit Exitcode 0
    # als auch 1 beobachtet worden -- der Fehlertext selbst ist das verlaessliche Signal, nicht
    # der Exitcode, mit dem er zufaellig einhergeht.
    first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    if _ROUTEROS_ERROR_RE.match(first_line):
        raise RouterCommandFailed(first_line)
    # sshpass gibt bei falschem Passwort gezielt Exitcode 5 zurueck (siehe sshpass(1)) --
    # das ist die einzige zuverlaessige Art, "falsches Passwort" von "Geraet nicht erreichbar"
    # zu unterscheiden, wichtig fuer eine verstaendliche Fehlermeldung im Verbinden-Bildschirm.
    if result.returncode == 5:
        raise RouterAuthFailed(result.stderr.strip() or "Benutzername oder Passwort falsch")
    if result.returncode != 0:
        raise RouterUnreachable(result.stderr.strip())
    return result.stdout


def download_file(
    host: str, user: str, password: str, port: int, remote_name: str, local_path: str,
    timeout: int = 20, known_hosts_path: str | None = None,
) -> None:
    host_key_opts = (
        ["-o", f"UserKnownHostsFile={known_hosts_path}", "-o", "StrictHostKeyChecking=yes"]
        if known_hosts_path else ["-o", "StrictHostKeyChecking=accept-new"]
    )
    _ensure_master(host, user, password, port, timeout, known_hosts_path, host_key_opts)
    scp_cmd = [
        "sshpass", "-e", "scp",
        "-P", str(port),
        *host_key_opts,
        *_control_opts(host, user, port),
        f"{user}@{host}:{remote_name}",
        local_path,
    ]
    env = {**os.environ, "SSHPASS": password}
    result = subprocess.run(scp_cmd, env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RouterUnreachable(result.stderr.strip())


def upload_file(
    host: str, user: str, password: str, port: int, local_path: str, remote_name: str,
    timeout: int = 20, known_hosts_path: str | None = None,
) -> None:
    # Audit A13-Rest: Gegenstueck zu download_file() fuer die Wiederherstellung -- schiebt eine
    # lokal gespeicherte .backup-Datei zurueck auf den Router, bevor "/system backup load" sie
    # einliest.
    host_key_opts = (
        ["-o", f"UserKnownHostsFile={known_hosts_path}", "-o", "StrictHostKeyChecking=yes"]
        if known_hosts_path else ["-o", "StrictHostKeyChecking=accept-new"]
    )
    _ensure_master(host, user, password, port, timeout, known_hosts_path, host_key_opts)
    scp_cmd = [
        "sshpass", "-e", "scp",
        "-P", str(port),
        *host_key_opts,
        *_control_opts(host, user, port),
        local_path,
        f"{user}@{host}:{remote_name}",
    ]
    env = {**os.environ, "SSHPASS": password}
    result = subprocess.run(scp_cmd, env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RouterUnreachable(result.stderr.strip())


def wg_generate_keypair() -> tuple[str, str]:
    private_key = subprocess.run(
        ["wg", "genkey"], capture_output=True, text=True, timeout=5, check=True,
    ).stdout.strip()
    public_key = subprocess.run(
        ["wg", "pubkey"], input=private_key, capture_output=True, text=True, timeout=5, check=True,
    ).stdout.strip()
    return private_key, public_key


def parse_colon(output: str) -> dict:
    # RouterOS gibt Einzelobjekte (z.B. /system identity, /system resource) im
    # "key: value"-Format aus, nicht als terse-Liste -- "print terse" scheitert dort
    # mit "bad parameter terse" (live am 08.09. gegen chr01 gefunden).
    result = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        result[key.strip()] = value.strip()
    return result


def parse_terse(output: str) -> list[dict]:
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Werte werden nicht nach dem ersten Leerzeichen abgeschnitten, sondern laufen bis
        # zum naechsten "key=" oder Zeilenende -- am 09.09. live gefunden: RouterOS 7.24
        # quotet in "print terse" ueberhaupt nichts, auch mehrwortige Werte wie Kommentare
        # ("comment=Kamera Einfahrt") oder Interface-Bezeichnungen ("Atheros AR9300") nicht.
        # Ein reines "bis zum naechsten Leerzeichen" brach damit jeden Kommentar mit Leerzeichen
        # -- betraf auch die schon laufende Portweiterleitung.
        pairs = re.findall(r'([\w.-]+)=("[^"]*"|.*?)(?=\s+[\w.-]+=|$)', line)
        row = {k: v.strip('"') for k, v in pairs}
        if not row:
            continue
        # RouterOS codiert "running"/"disabled" oft nur als Flag-Buchstabe vor dem ersten
        # key=value (z.B. "0 R name=ether1 ..."), nicht als eigenes Feld -- live am 08.09.
        # gegen chr01 gefunden, wo genau das den Status-Endpunkt faelschlich "down" meldete.
        prefix = line[: line.index("=")] if "=" in line else line
        flags = "".join(prefix.split()[1:])
        row["running"] = row.get("running", "").lower() == "true" or "R" in flags
        row["disabled"] = row.get("disabled", "").lower() == "true" or "X" in flags
        rows.append(row)
    return rows
