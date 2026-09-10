import os


class Config:
    def __init__(self) -> None:
        # Kein fest konfigurierter Router mehr -- siehe dem Verbinden-Modell.
        # Verbindungsdaten (Host/User/Passwort/Port) kommen jetzt zur Laufzeit ueber
        # POST /api/v1/connect und leben nur in app.SESSIONS, nicht in der Konfiguration.
        self.wan_interface = os.environ.get("COCKPIT_WAN_INTERFACE", "ether1")
        # Gastnetz-Interface: seit 09.09. keine feste Konfiguration mehr, sondern Teil der
        # Sitzung (conn["guest_interface"], gesetzt ueber PUT /api/v1/guest-network/interface).
        # Siehe den Projektnotizen, Eintrag "Gastnetz-Erkennung repariert".
        self.wireguard_interface = os.environ.get("COCKPIT_WIREGUARD_INTERFACE", "wg-vpn")
        # Abschlussrunde, 10.09.2026: der bisherige Default lag unter /tmp -- world-lesbares/
        # -betretbares Verzeichnis mit festem, vorhersehbarem Namen. Genau das Muster, das bei
        # known_hosts_path (Audit Runde 3, P0) schon einmal ein Sicherheitsfund war: ein anderer
        # lokaler Nutzer auf demselben Rechner kann /tmp/mikrotik-cockpit-backups VOR dem ersten
        # Start selbst anlegen (oder eine Router-spezifische Unterordner-ID als Symlink vorlegen)
        # und sich damit Lese-/Schreibzugriff auf Backups sichern, die die komplette
        # Router-Konfiguration inkl. Zugangsdaten enthalten koennen. known_hosts_path wurde
        # deswegen bereits auf ein privates ~/.config-Verzeichnis umgestellt -- backup_dir war der
        # einzige verbliebene /tmp-Pfad im Projekt und ist jetzt symmetrisch dazu verschoben.
        # _ensure_private_dir() in app.py haertet zusaetzlich gegen ein abweichend per
        # COCKPIT_BACKUP_DIR konfiguriertes, unsicheres Verzeichnis ab.
        self.backup_dir = os.environ.get(
            "COCKPIT_BACKUP_DIR",
            os.path.join(os.path.expanduser("~/.config/mikrotik-cockpit"), "backups"),
        )
        # Audit A18: eigene known_hosts-Datei statt des System-Standardpfads -- Cockpit
        # verwaltet damit seine eigenen, per Fingerprint-Dialog bestaetigten Router-Schluessel,
        # unabhaengig davon, was im ~/.ssh/known_hosts des Betriebssystem-Nutzers steht.
        # Audit Runde 3, Befund 1 (P0): der alte Default lag unter /tmp -- world-writable,
        # fester im Code stehender Dateiname. Ein Dritter konnte dort VOR dem ersten echten
        # Connect den echten Router-Schluessel platzieren und den kompletten Fingerprint-Dialog
        # damit unsichtbar umgehen (live nachgewiesen). Jetzt ein privates, nur dem eigenen
        # Nutzer gehoerendes Verzeichnis; _lookup_known_host() prueft zusaetzlich Eigentuemer/
        # Rechte, bevor es dem Inhalt vertraut (siehe routeros.py).
        self.known_hosts_path = os.environ.get(
            "COCKPIT_KNOWN_HOSTS_FILE",
            os.path.join(os.path.expanduser("~/.config/mikrotik-cockpit"), "known_hosts"),
        )
        # Phase B, 10.09.2026: Raum-Zuordnung je Geraet (Topologie-Kacheln, Ergebnis des Produkt-Reviews) ist reine Cockpit-eigene Zusatzinformation -- der Router selbst hat
        # dafuer keine Datenquelle. Gleiches Sicherheitsmuster wie backup_dir: privates
        # ~/.config-Verzeichnis statt /tmp, ueber _ensure_private_dir() in app.py abgesichert
        # (Eigentuemer-/Rechte-/Symlink-Check). Eigener Ordner statt Unterordner von backup_dir,
        # damit ein Backup-Restore/-Aufraeumen die Raum-Zuordnungen nicht versehentlich mitreisst.
        self.device_rooms_dir = os.environ.get(
            "COCKPIT_DEVICE_ROOMS_DIR",
            os.path.join(os.path.expanduser("~/.config/mikrotik-cockpit"), "device-rooms"),
        )
        self.backend_port = int(os.environ.get("COCKPIT_BACKEND_PORT", "8787"))
        # Oberflaeche und API laufen seit dem Ein-Dienst-Umbau auf demselben Ursprung (127.0.0.1,
        # ein Port) -- CORS greift dadurch im Normalbetrieb gar nicht mehr, bleibt aber als
        # harmloses Sicherheitsnetz fuer abweichende lokale Setups bestehen.
        self.allowed_origin = os.environ.get("COCKPIT_ALLOWED_ORIGIN", "http://127.0.0.1:8787")


def load_config() -> Config:
    return Config()
