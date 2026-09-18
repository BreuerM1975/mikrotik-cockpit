import os
import re
import subprocess


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
        ["ssh-keyscan", "-p", str(port), "-T", str(timeout), host],
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


def run_command(
    host: str, user: str, password: str, port: int, command: str,
    timeout: int = 10, known_hosts_path: str | None = None,
) -> str:
    # Audit A18: "accept-new" hat den allerersten Kontakt zu einem Router still und ohne
    # jede Rueckfrage vertraut -- ensure_host_key_trusted() muss vorher gelaufen sein (siehe
    # app.py:connect()), danach steht der Schluessel bereits fest in known_hosts_path und
    # "yes" verlangt eine exakte Uebereinstimmung, statt einen neuen Schluessel klaglos
    # anzunehmen.
    host_key_opts = (
        ["-o", f"UserKnownHostsFile={known_hosts_path}", "-o", "StrictHostKeyChecking=yes"]
        if known_hosts_path else ["-o", "StrictHostKeyChecking=accept-new"]
    )
    ssh_cmd = [
        "sshpass", "-e", "ssh",
        "-p", str(port),
        *host_key_opts,
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
    scp_cmd = [
        "sshpass", "-e", "scp",
        "-P", str(port),
        *host_key_opts,
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
    scp_cmd = [
        "sshpass", "-e", "scp",
        "-P", str(port),
        *host_key_opts,
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
