// Muster fuer Saetze, in die zur Laufzeit Werte eingesetzt werden (siehe i18n.js).
//
// Ein exakter Woerterbuch-Treffer scheitert hier, weil im DOM z.B. "Zuletzt geprueft: 18:42" steht.
// Reihenfolge zaehlt: das erste passende Muster gewinnt, deshalb stehen spezielle Faelle oben.

window.COCKPIT_PATTERNS_EN = [
  [/^Zuletzt geprüft: (.+)$/, "Last checked: $1"],
  [/^(\d+) von (\d+) Prüfungen bestanden$/, "$1 of $2 checks passed"],
  [/^Backend nicht erreichbar unter (.+)$/, "Backend unreachable at $1"],
  [/^Backend-Fehler \((\d+)\)$/, "Backend error ($1)"],
  [/^(.+): (.+) Vorhandene Daten können veraltet sein\.$/, "$1: $2 Existing data may be out of date."],
  [/^Weboberfläche erkannt: (.+) · Port (.+)$/, "Web interface detected: $1 · port $2"],
  [/^Raum „(.+)“ gespeichert\.$/, "Room “$1” saved."],
  [/^Backup „(.+)“ überschreibt die komplette Konfiguration dieses Routers und startet ihn sofort neu\.$/,
    "Backup “$1” will overwrite this router's entire configuration and restart it immediately."],
  [/^Der Dienst „(.+)“ kann den Router von außen erreichbar machen\.$/,
    "The “$1” service can make the router reachable from outside."],
  [/^Dieser Router wurde noch nie bestätigt\.\n\nSSH-Fingerprint \((.+)\):\n(.+)\n\n$/,
    "This router has never been confirmed.\n\nSSH fingerprint ($1):\n$2\n\n"],
  [/^Quellport (.+)$/, "Source port $1"],
  [/^Zielport (.+)$/, "Destination port $1"],
  [/^Uptime (.+)$/, "Uptime $1"],
  [/^(\d+) Einträge$/, "$1 entries"],
  [/^Kann den Zugang sperren oder das Netzwerk öffnen\.$/,
    "Can lock out access or open up the network."],

  // Sicherheits-Check: das Backend setzt Versionen, Tage und Dienstnamen ein.
  [/^(.+) ist noch an - diese alten Dienste übertragen Passwörter unverschlüsselt\. Schalte sie unter IP-Dienste aus, falls du sie nicht zwingend brauchst\.$/,
    "$1 is still switched on — those old services send passwords unencrypted. Turn them off under IP services unless you genuinely need them."],
  [/^(.+) installiert, (.+) verfügbar\.$/, "$1 installed, $2 available."],
  [/^Eine neuere RouterOS-Version \((.+)\) ist verfügbar, aktuell läuft (.+)\. Plane ein Update ein, aktuelle Versionen schließen bekannte Sicherheitslücken\.$/,
    "A newer RouterOS version ($1) is available; you are running $2. Plan an update — current versions close known security holes."],
  [/^RouterOS ist aktuell \((.+)\) - kein Update nötig\.$/,
    "RouterOS is up to date ($1) — no update needed."],
  [/^Noch aktiv: (.+)\.$/, "Still switched on: $1."],
  [/^VLAN (.+) ist bereits auf einem anderen Interface eingerichtet$/,
    "VLAN $1 is already configured on another interface"],
  [/^(.+) ist die aktuelle Version\.$/, "$1 is the current version."],
  [/^Letztes Backup ist (\d+) Tage alt\.$/, "Last backup is $1 days old."],
  [/^Letztes Backup ist (\d+) Tag\(e\) alt\.$/, "Last backup is $1 day(s) old."],
  [/^Das letzte Backup ist (\d+) Tage alt\. Erstelle ein neues, damit eine Wiederherstellung den aktuellen Stand trifft\.$/,
    "The last backup is $1 days old. Create a new one so a restore brings back the current state."],
  [/^Das letzte Backup ist (\d+) Tag\(e\) alt - aktuell genug\.$/,
    "The last backup is $1 day(s) old — recent enough."],
  [/^'room' darf höchstens (.+)$/, "'room' may be at most $1"],
  [/^Neue SSID für (.+)$/, "New SSID for $1"],
  [/^Neues Passwort für (.+)$/, "New password for $1"],
  [/^RouterOS (.+)$/, "RouterOS $1"],
];
