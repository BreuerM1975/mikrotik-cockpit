// Englisches Woerterbuch fuer die Sprachschicht (siehe i18n.js).
//
// Schluessel ist der deutsche Text, wie er im DOM steht -- getrimmt. Begriffe, die in beiden
// Sprachen gleich lauten (TCP, NAT, Firmware, Masquerade, Interface, Status, Router ...), stehen
// bewusst nicht drin: kein Eintrag bedeutet keine Aenderung.
//
// Fragmente entstehen, wo <em>/<strong>/<code> einen Satz zerschneiden. Sie sind so uebersetzt,
// dass sie in der Zielsprache wieder aneinanderpassen.

window.COCKPIT_DICT_EN = {
  // --- Navigation, Kopfzeile, Grundgeruest ---
  "Übersicht": "Overview",
  "Startseite": "Home",
  "WLAN & Gäste": "Wi-Fi & guests",
  "Geräte & Netzwerk": "Devices & network",
  "Sicherheit": "Security",
  "Wartung & VPN": "Maintenance & VPN",
  "Hilfe": "Help",
  "Hauptnavigation": "Main navigation",
  "MikroTik Cockpit Startseite": "MikroTik Cockpit home",
  "Backend wird geladen": "Connecting to backend",
  "Lokale API": "Local API",
  "Dein Heimnetz": "Your home network",
  "Dein Router im Überblick": "Your router at a glance",
  "Lokal · keine Cloud": "Local · no cloud",
  "Router verbunden": "Router connected",
  "Dunkel": "Dark",
  "Hell": "Light",
  "Farbschema wechseln": "Switch colour scheme",
  "Verbindung trennen": "Disconnect",
  "MIKROTIK COCKPIT · PROTOTYP": "MIKROTIK COCKPIT · PROTOTYPE",
  "Lokales Backend · Änderungen werden am Router gespeichert":
    "Local backend · changes are saved on the router",

  // --- Willkommensbildschirm ---
  "Willkommen": "Welcome",
  "Was möchtest du heute erledigen?": "What would you like to do today?",
  "Wähle ein Ziel. Nach dem Verbinden führt dich Cockpit direkt dorthin.":
    "Pick a goal. Once connected, Cockpit takes you straight there.",
  "WLAN ändern": "Change Wi-Fi",
  "Name oder Passwort deines WLANs anpassen": "Change your Wi-Fi name or password",
  "Gastnetz aktivieren": "Turn on the guest network",
  "Besucher ins WLAN lassen, ohne das Heimnetz zu öffnen":
    "Let visitors online without opening up your home network",
  "Sicherheit prüfen": "Check security",
  "Sehen, was heute Aufmerksamkeit braucht": "See what needs attention today",
  "Von unterwegs zugreifen": "Access from anywhere",
  "Eigenen VPN-Zugang einrichten": "Set up your own VPN access",
  "Nur reinschauen": "Just have a look",
  "Erst einmal den aktuellen Zustand ansehen": "Start by looking at the current state",
  "Überspringen": "Skip",

  // --- Verbindungsbildschirm ---
  "Mit Gerät verbinden": "Connect to a device",
  "Verbinde dein MikroTik-Gerät": "Connect your MikroTik device",
  "Gib die Adresse und deine RouterOS-Zugangsdaten ein – genauso wie bei WinBox.":
    "Enter the address and your RouterOS credentials — exactly like WinBox.",
  "IP-Adresse oder Hostname": "IP address or hostname",
  "Benutzername": "Username",
  "Passwort": "Password",
  "SSH-Port": "SSH port",
  "(optional)": "(optional)",
  "Verbinden": "Connect",
  "Bleibt bei dir:": "Stays with you:",
  "Die Verbindung läuft lokal auf diesem Rechner. Es gibt keine Cloud-Anmeldung, und dein Passwort wird nicht gespeichert.":
    "The connection runs locally on this machine. There is no cloud login, and your password is never stored.",

  // --- Statusseite ---
  "Status-Dashboard": "Status dashboard",
  "Routerstatus": "Router status",
  "Noch nicht geprüft": "Not checked yet",
  "Wird geprüft": "Checking",
  "Wird geprüft …": "Checking …",
  "Wird geladen …": "Loading …",
  "Prüfung": "Check",
  "Verbindung zum Backend wird aufgebaut.": "Connecting to the backend.",
  "Verbundene Geräte": "Connected devices",
  "Geräte in deinem Netzwerk": "Devices on your network",
  "Live vom Router": "Live from the router",
  "Routername": "Router name",
  "Namen ändern →": "Change name →",
  "Namen speichern": "Save name",
  "WAN-Adresse": "WAN address",
  "Öffentliche IP-Adresse": "Public IP address",
  "Adresse kopieren →": "Copy address →",
  "WAN-Interface": "WAN interface",
  "Interface auswählen": "Select interface",
  "Sicherheits-Score": "Security score",
  "Details ansehen →": "View details →",
  "Uptime –": "Uptime –",

  // --- WLAN ---
  "Deine Funknetze": "Your wireless networks",
  "↻ Aktualisieren": "↻ Refresh",
  "Was kannst du hier einstellen?": "What can you change here?",
  "Du kannst das Passwort eines WLANs ändern. Das ist sinnvoll, wenn du es mit zu vielen Personen geteilt hast. Danach müssen sich alle Geräte neu verbinden.":
    "You can change a network's password. That is worth doing if you have shared it with too many people. Afterwards every device has to reconnect.",

  // --- Geraete ---
  "Netzwerk": "Network",
  "Was ist sinnvoll?": "What is worth doing?",
  "Vergib einen verständlichen Namen und eine feste IP für Geräte, die du regelmäßig erreichst. Unbekannte Geräte kannst du trennen – prüfe vorher, ob nicht gerade jemand aus der Familie online ist.":
    "Give a clear name and a fixed IP to devices you reach regularly. You can disconnect unknown devices — but check first that it is not simply someone in the family being online.",
  "Gerät": "Device",
  "Adresse": "Address",

  // --- Gastnetz ---
  "Zugang für Besucher": "Access for visitors",
  "Gastnetz": "Guest network",
  "Gastnetz auswählen": "Select guest network",
  "Wähle das WLAN, das als Gastnetz verwaltet werden soll.":
    "Choose the wireless network that should be managed as the guest network.",
  "WLAN-Interface": "Wi-Fi interface",
  "Name und SSID helfen dir, das richtige Funknetz zu erkennen.":
    "The name and SSID help you spot the right network.",
  "Isolation ungeprüft": "Isolation unverified",
  "Die Trennung vom privaten Netzwerk ist noch nicht geprüft. Ein aktiviertes Gastnetz allein ist kein Nachweis für geschützte private Geräte.":
    "Separation from your private network has not been verified. An enabled guest network on its own is no proof that private devices are protected.",
  "Einstellung speichern": "Save setting",

  // --- Portfreigaben ---
  "Zugriff von außen": "Access from outside",
  "Portfreigaben": "Port forwards",
  "Vorsicht": "Take care",
  "Was bedeutet das?": "What does this mean?",
  "Eine Portfreigabe macht einen Dienst aus dem Internet erreichbar. Lege nur Freigaben an, die du wirklich brauchst, und sichere den Dienst zusätzlich ab.":
    "A port forward makes a service reachable from the internet. Only create the ones you genuinely need, and secure that service separately.",
  "+ Portfreigabe anlegen": "+ Add port forward",
  "Name": "Name",
  "Protokoll": "Protocol",
  "Außenport": "External port",
  "Ziel-IP": "Target IP",
  "Zielport": "Target port",
  "Speichern": "Save",

  // --- Wartung ---
  "Pflege & Sicherheit": "Care & security",
  "Wartung": "Maintenance",
  "RouterOS aktuell halten": "Keep RouterOS up to date",
  "Installiert": "Installed",
  "Verfügbar": "Available",
  "Updates schließen Sicherheitslücken und verbessern die Stabilität. Während der Installation startet der Router kurz neu.":
    "Updates close security holes and improve stability. The router restarts briefly during installation.",
  "Update starten": "Start update",
  "Konfiguration sichern": "Back up the configuration",
  "Ein Backup hilft dir, nach einem Fehler schnell zu einem funktionierenden Zustand zurückzukehren. Erstelle eines vor größeren Änderungen.":
    "A backup gets you back to a working state quickly after a mistake. Create one before any bigger change.",
  "+ Backup erstellen": "+ Create backup",
  "VPN-Zugang": "VPN access",
  "Sicher von unterwegs verbinden": "Connect securely from anywhere",
  "Ein persönlicher WireGuard-Zugang verbindet dich verschlüsselt mit deinem Heimnetz. Für jedes Gerät legst du einen eigenen Zugang an.":
    "A personal WireGuard connection links you to your home network in encrypted form. Create a separate access for each device.",
  "WireGuard-Interface": "WireGuard interface",
  "Mehrere VPN-Interfaces gefunden. Wähle, über welches davon neue Zugänge verwaltet werden.":
    "Several VPN interfaces found. Choose which one new connections should be managed through.",
  "Name für neues Gerät": "Name for the new device",
  "Client-IP im VPN": "Client IP inside the VPN",
  "Öffentliche VPN-Adresse (IP oder DDNS-Name)": "Public VPN address (IP or DDNS name)",
  "Externer UDP-Port (optional)": "External UDP port (optional)",
  "Keine lokale Router-IP eintragen. Die Adresse muss von unterwegs erreichbar sein. DDNS, Firewall und eine mögliche Portweiterleitung werden hier nicht eingerichtet oder geprüft.":
    "Do not enter a local router IP. The address has to be reachable from outside. DDNS, firewall rules and any port forwarding are neither set up nor checked here.",
  "VPN-Zugang erstellen": "Create VPN access",
  "Router-Zugang": "Router login",
  "Passwort des aktuellen Benutzers": "Password of the current user",
  "Das Passwort wird direkt am Router geändert und nicht im Cockpit gespeichert. Die aktuelle Sitzung bleibt danach bestehen.":
    "The password is changed on the router itself and never stored in Cockpit. Your current session stays open.",
  "Neues Passwort": "New password",
  "Passwort wiederholen": "Repeat password",
  "Passwort ändern": "Change password",
  "Router neu starten": "Restart router",

  // --- Netzwerk-Grundeinstellungen ---
  "Grundeinstellungen": "Basic settings",
  "IP-Adressen": "IP addresses",
  "Ändere hier die Adresse eines Router-Interfaces. Eine Änderung kann die aktuelle Verbindung sofort trennen.":
    "Change the address of a router interface here. A change can drop your current connection instantly.",
  "DNS-Server": "DNS servers",
  "Diese Server lösen Webadressen wie example.com in IP-Adressen auf.":
    "These servers turn web addresses such as example.com into IP addresses.",
  "Server, durch Komma getrennt": "Servers, separated by commas",
  "DNS speichern": "Save DNS",
  "DHCP-Client": "DHCP client",
  "Ein DHCP-Client bezieht automatisch eine IP-Adresse, meist für den Internetanschluss.":
    "A DHCP client picks up an IP address automatically, usually for the internet connection.",
  "Interface": "Interface",
  "DHCP-Client hinzufügen": "Add DHCP client",

  // --- DHCP-Bereiche ---
  "DHCP-Bereiche": "DHCP ranges",
  "Vorhandene Bereiche": "Existing ranges",
  "Ein Bereich verteilt automatisch IP-Adressen an Geräte in einem VLAN oder Netzwerk.":
    "A range hands out IP addresses automatically to devices on a VLAN or network.",
  "Bereich anlegen": "Add a range",
  "Netzwerk (CIDR)": "Network (CIDR)",
  "Von": "From",
  "Bis": "To",
  "Gateway": "Gateway",
  "DHCP-Bereich anlegen": "Add DHCP range",

  // --- PPPoE ---
  "Internetzugang": "Internet connection",
  "PPPoE-Verbindung": "PPPoE connection",
  "Was brauchst du?": "What do you need?",
  "Deine Provider-Zugangsdaten und das WAN-Interface, an dem das Modem oder der Hausanschluss steckt. Service-Name und VLAN-ID sind nur nötig, wenn dein Provider sie vorgibt.":
    "Your provider credentials and the WAN interface your modem or line is plugged into. Service name and VLAN ID are only needed if your provider requires them.",
  "Bestehende Verbindungen": "Existing connections",
  "Hier siehst du, ob der Router bereits eine PPPoE-Verbindung eingerichtet hat.":
    "This shows whether the router already has a PPPoE connection set up.",
  "Neue Verbindung einrichten": "Set up a new connection",
  "Verbindungsname": "Connection name",
  "Provider-Benutzername": "Provider username",
  "Provider-Passwort": "Provider password",
  "Service-Name": "Service name",
  "VLAN-ID": "VLAN ID",
  "(optional, 1–4094)": "(optional, 1–4094)",
  "Standardroute automatisch setzen": "Set the default route automatically",
  "DNS-Server des Providers verwenden": "Use the provider's DNS servers",
  "PPPoE-Verbindung herstellen": "Establish PPPoE connection",

  // --- Sicherheits-Check ---
  "Überblick": "Overview",
  "Sicherheits-Check": "Security check",
  "Fasst zusammen, was WinBox nie an einer Stelle zeigt: ist dieser Router aus heutiger Sicht sauber abgesichert? Jede Zeile ist ein echter, live geprüfter Zustand am Router – keine Vermutung.":
    "Sums up what WinBox never shows in one place: is this router properly secured as things stand today? Every line is a real, live-checked state on the router — never a guess.",

  // --- Firewall ---
  "Firewall-Regeln": "Firewall rules",
  "Vollzugriff": "Full access",
  "Hier änderst du die echte Router-Firewall.": "This changes the router's real firewall.",
  "Eine falsche Regel kann Geräte aussperren oder Dienste aus dem Internet öffnen. Neue Regeln werden automatisch vor die letzte Regel der Kette gesetzt. Eine manuelle Reihenfolge ist in dieser Version nicht verfügbar.":
    "A wrong rule can lock devices out or expose services to the internet. New rules are placed automatically before the last rule of the chain. Manual ordering is not available in this version.",
  "Verkehr durch den Router": "Traffic passing through the router",
  "Forward-Regel anlegen": "Add forward rule",
  "Aktion": "Action",
  "Erlauben": "Accept",
  "Verwerfen": "Drop",
  "Zurückweisen": "Reject",
  "Protokollieren": "Log",
  "Durchreichen": "Passthrough",
  "Alle": "All",
  "Quelladresse": "Source address",
  "Zieladresse": "Destination address",
  "Kommentar": "Comment",
  "Zugriff auf den Router selbst": "Access to the router itself",
  "Input-Regel anlegen": "Add input rule",
  "Adress- und Portübersetzung": "Address and port translation",
  "NAT-Regel anlegen": "Add NAT rule",
  "Kette": "Chain",
  "dstnat – eingehend": "dstnat — inbound",
  "srcnat – ausgehend": "srcnat — outbound",
  "Übersetzungsziel": "Translate to address",
  "(bei dst-nat/src-nat Pflicht)": "(required for dst-nat/src-nat)",
  "Übersetzungsport": "Translate to port",

  // --- IP-Dienste ---
  "Router-Zugänge": "Router access points",
  "IP-Dienste": "IP services",
  "Diese Dienste öffnen Zugänge zum Router.": "These services open ways into the router.",
  "Schalte nur ab, was du nicht brauchst. Wenn du": "Only switch off what you do not need. If you disable",
  "deaktivierst, trennt sich Cockpit selbst vom Gerät und kann die Verbindung nicht wiederherstellen. Für SSH brauchst du danach WinBox, eine serielle Verbindung oder einen direkten Zugang.":
    ", Cockpit cuts its own connection to the device and cannot restore it. To get SSH back you then need WinBox, a serial connection or direct access.",

  // --- Haeufige Fragen ---
  "Häufige Fragen": "Frequently asked questions",
  "Ich habe SSH deaktiviert und komme jetzt nicht mehr rein — was tue ich?":
    "I disabled SSH and can no longer get in — what now?",
  "Cockpit spricht ausschließlich SSH mit dem Router. Ohne SSH gibt es über diese Oberfläche keinen Weg zurück. Verbinde dich per WinBox über Port 8291 (der bleibt unabhängig von SSH offen, solange du ihn nicht auch deaktiviert hast) oder direkt am Gerät und schalte SSH unter":
    "Cockpit talks to the router over SSH and nothing else. Without SSH there is no way back through this interface. Connect with WinBox on port 8291 (it stays open independently of SSH, as long as you have not disabled that too) or go to the device directly and switch SSH back on under",
  "IP → Services": "IP → Services",
  "wieder ein.": ".",
  "Was ist der Unterschied zwischen einer Portfreigabe und einer Firewall-Regel?":
    "What is the difference between a port forward and a firewall rule?",
  "Eine Portfreigabe leitet eingehenden Verkehr von außen zu einem bestimmten Gerät in deinem Netz weiter (technisch:":
    "A port forward sends incoming traffic from outside to a particular device on your network (technically:",
  ") — sie sagt \"wohin\". Die Firewall entscheidet, ob Verkehr überhaupt durchgelassen wird — sie sagt \"ob\". Beides zusammen ergibt Zugriff von außen: eine Portfreigabe ohne passende Firewall-Regel bleibt oft wirkungslos, eine Firewall-Regel ohne Portfreigabe leitet nichts weiter.":
    ") — it says \"where to\". The firewall decides whether traffic is let through at all — it says \"whether\". Access from outside needs both: a port forward without a matching firewall rule often does nothing, and a firewall rule without a port forward has nowhere to send traffic.",
  "Warum zeigt die Gastnetz-Isolation manchmal \"ungeprüft\" oder \"unknown\" an?":
    "Why does guest network isolation sometimes show \"unverified\" or \"unknown\"?",
  "Cockpit erkennt Isolation nur, wenn am Router eine eindeutige, aktive Regel existiert, die Verkehr vom Gastnetz ins Hausnetz verwirft. Ohne diese Regel zeigt Cockpit bewusst \"ungeprüft\" statt zu behaupten, das Netz sei sicher — ein eingeschaltetes Gastnetz allein ist kein Beweis für Trennung.":
    "Cockpit only reports isolation when the router has a clear, active rule that drops traffic from the guest network into the home network. Without such a rule Cockpit deliberately says \"unverified\" instead of claiming the network is safe — an enabled guest network on its own proves nothing about separation.",
  "Was genau macht ein Backup, und was passiert beim Wiederherstellen?":
    "What exactly does a backup do, and what happens when I restore one?",
  "Ein Backup sichert die komplette RouterOS-Konfiguration in eine Datei, die Cockpit lokal auf deinem Rechner ablegt (pro Router ein eigener Ordner). \"Wiederherstellen\" spielt diese Datei zurück auf den Router — das":
    "A backup saves the complete RouterOS configuration into a file that Cockpit stores locally on your machine (one folder per router). \"Restore\" plays that file back onto the router — which",
  "ersetzt die gesamte aktuelle Konfiguration": "replaces the entire current configuration",
  "und startet den Router sofort neu. Deshalb verlangt Cockpit dafür eine ausdrückliche Bestätigung und keine Vorschau vorher.":
    "and restarts the router immediately. That is why Cockpit asks for an explicit confirmation and offers no preview beforehand.",
  "Warum steht beim Sicherheits-Score kein Punkt für \"Passwort geändert\"?":
    "Why is there no \"password changed\" item in the security score?",
  "RouterOS speichert nirgends, ob ein Passwort noch der Werkszustand ist — Cockpit kann das ehrlich nicht zuverlässig prüfen und zeigt deshalb lieber keinen Check als einen erratenen. Alle angezeigten Punkte beruhen auf echtem, auslesbarem Routerzustand.":
    "RouterOS stores nothing about whether a password is still the factory one — Cockpit genuinely cannot check that reliably, and would rather show no check than a guessed one. Every item shown is based on real, readable router state.",
  "Ich habe das Router-Passwort im Cockpit geändert — muss ich mich neu anmelden?":
    "I changed the router password in Cockpit — do I have to log in again?",
  "Nein. RouterOS trennt die laufende SSH-Verbindung beim Passwortwechsel nicht, Cockpit führt deine aktuelle Sitzung automatisch mit dem neuen Passwort fort. Beim nächsten eigenständigen Verbinden (neuer Browser, neues Gerät) brauchst du dann das neue Passwort.":
    "No. RouterOS does not drop the running SSH connection when the password changes, and Cockpit carries your current session on with the new password automatically. The next time you connect from scratch (new browser, new device) you will need the new password.",
  "Kann ich eine Änderung im Cockpit rückgängig machen?":
    "Can I undo a change made in Cockpit?",
  "Es gibt keinen allgemeinen \"Zurück\"-Knopf — jede Aktion wirkt sofort und direkt am Router, genau wie bei WinBox. Der zuverlässige Weg zurück ist ein Backup":
    "There is no general \"undo\" button — every action takes effect immediately and directly on the router, exactly as in WinBox. The reliable way back is a backup",
  "vor": "before",
  "größeren Änderungen und im Notfall die Wiederherstellung daraus.":
    "any bigger change, and restoring from it if the worst happens.",
  "Warum sehe ich bei manchen Bereichen (VPN, WAN-Liste, Gastnetz) leere Listen?":
    "Why are some areas (VPN, WAN list, guest network) showing empty lists?",
  "Eine leere Liste heißt meist: am Router ist dafür noch nichts eingerichtet, nicht dass Cockpit etwas übersehen hat — zum Beispiel kein WireGuard-Interface angelegt oder kein Gerät per DHCP verbunden. Details dazu stehen jeweils im Wiki-Bereich unten.":
    "An empty list usually means nothing has been set up for it on the router yet, not that Cockpit missed something — for example no WireGuard interface exists, or no device has connected via DHCP. The wiki section below explains each case.",

  // --- Wiki ---
  "Wiki — was stellt man wo ein?": "Wiki — where do I change what?",
  "WLAN": "Wi-Fi",
  "WLAN-Passwort ändern": "Change the Wi-Fi password",
  "Ändert den Netzwerkschlüssel für genau dieses Funknetz direkt am Router. Alle bereits verbundenen Geräte verlieren die Verbindung und müssen sich mit dem neuen Passwort erneut anmelden.":
    "Changes the network key for this one wireless network directly on the router. Every device already connected loses the connection and has to sign in again with the new password.",
  "Netzwerkname (SSID) ändern": "Change the network name (SSID)",
  "Ändert nur den angezeigten Namen des Funknetzes. Verbundene Geräte bleiben verbunden, neue Geräte sehen ab sofort den neuen Namen.":
    "Changes only the displayed name of the network. Connected devices stay connected; new devices see the new name from now on.",
  "Legt fest, welches vorhandene WLAN-Interface Cockpit als \"Gastnetz\" behandelt. Legt selbst kein neues Funknetz an — das WLAN muss am Router bereits existieren.":
    "Decides which existing Wi-Fi interface Cockpit treats as the \"guest network\". It does not create a new network — the Wi-Fi has to exist on the router already.",
  "Gastnetz an/aus": "Guest network on/off",
  "Schaltet nur das Funknetz selbst ein oder aus. Ob Geräte darin vom Hausnetz getrennt sind, zeigt der separate Isolations-Hinweis — das ist eine eigene Firewall-Frage, siehe FAQ.":
    "Switches only the wireless network itself on or off. Whether devices on it are separated from the home network is shown by the separate isolation note — that is a firewall question of its own, see the FAQ.",
  "Verbundene Geräte / feste IP": "Connected devices / fixed IP",
  "Zeigt Geräte, die der Router aktuell kennt (per DHCP-Zuweisung). Eine feste IP für ein Gerät zu vergeben, reserviert dessen aktuelle Adresse dauerhaft — praktisch für Drucker, NAS oder Kameras, die immer unter derselben Adresse erreichbar sein sollen.":
    "Shows the devices the router currently knows about (from DHCP). Giving a device a fixed IP reserves its current address permanently — handy for printers, NAS boxes or cameras that should always be reachable at the same address.",
  "Ändert die Adresse eines Router-Interfaces selbst. Vorsicht: änderst du die Adresse des Interfaces, über das Cockpit gerade verbunden ist, kann die Verbindung sofort abreißen.":
    "Changes the address of a router interface itself. Careful: if you change the address of the interface Cockpit is currently connected through, the connection can drop instantly.",
  "Legt fest, welche Server der Router zum Auflösen von Webadressen (z. B. example.com → IP-Adresse) benutzt. Betrifft in der Regel alle Geräte, die den Router als DNS nutzen.":
    "Sets which servers the router uses to resolve web addresses (e.g. example.com → IP address). This normally affects every device that uses the router for DNS.",
  "Lässt ein Router-Interface automatisch eine IP-Adresse von außen beziehen — typisch für den Internetanschluss an einem Kabel-/Glasfasermodem.":
    "Lets a router interface pick up an IP address automatically from outside — typical for the internet connection on a cable or fibre modem.",
  "Legt fest, welchen Adressbereich der Router automatisch an Geräte in einem Netzwerk/VLAN verteilt, inklusive Gateway und DNS für diesen Bereich.":
    "Sets which address range the router hands out automatically to devices on a network or VLAN, including the gateway and DNS for that range.",
  "Baut die Internetverbindung über Provider-Zugangsdaten auf (typisch bei DSL/Glasfaser mit Einwahl). Braucht das richtige WAN-Interface und ggf. Service-Name/VLAN-ID vom Provider.":
    "Brings up the internet connection using provider credentials (typical for DSL or fibre with a dial-in). Needs the right WAN interface and, if your provider requires them, the service name and VLAN ID.",
  "Fasst mehrere echte Router-Prüfungen (Dienste, Firewall, Gastnetz-Isolation, Firmware, Backup) zu einem Score zusammen. Ändert selbst nichts am Router, sondern liest nur.":
    "Combines several real router checks (services, firewall, guest isolation, firmware, backup) into one score. It changes nothing on the router, it only reads.",
  "Macht einen Dienst in deinem Netz vom Internet aus erreichbar (siehe FAQ zum Unterschied zur Firewall). Nur anlegen, was wirklich von außen erreichbar sein soll.":
    "Makes a service on your network reachable from the internet (see the FAQ on how this differs from the firewall). Only create what genuinely needs to be reachable from outside.",
  "Firewall — Forward": "Firewall — forward",
  "Regeln für Verkehr, der": "Rules for traffic that passes",
  "durch": "through",
  "den Router läuft (z. B. zwischen zwei Netzen oder ins Internet). Hier greift auch die Gastnetz-Isolation.":
    "the router (e.g. between two networks, or out to the internet). Guest network isolation takes effect here too.",
  "Firewall — Input": "Firewall — input",
  "Regeln für Zugriff": "Rules for access",
  "auf den Router selbst": "to the router itself",
  "(Verwaltungsoberflächen, SSH, Winbox). Eine zu strenge Regel hier kann dich aussperren.":
    "(management interfaces, SSH, WinBox). Too strict a rule here can lock you out.",
  "Firewall — NAT": "Firewall — NAT",
  "Regeln zur Adress- und Portübersetzung, unter anderem die Grundlage für Portfreigaben und die gemeinsame Internetnutzung mehrerer Geräte über eine Adresse (Masquerade).":
    "Rules for address and port translation — among other things the basis for port forwards and for several devices sharing one address to reach the internet (masquerade).",
  "Schaltet einzelne Verwaltungszugänge des Routers (SSH, WinBox, Web-Oberfläche, FTP, Telnet …) an oder aus. Was du nicht brauchst, sollte aus bleiben.":
    "Switches individual management entrances to the router (SSH, WinBox, web interface, FTP, Telnet …) on or off. Anything you do not need should stay off.",
  "Firmware-Update": "Firmware update",
  "Installiert die neueste RouterOS-Version. Der Router startet dafür kurz neu, alle Verbindungen werden dabei kurz unterbrochen.":
    "Installs the latest RouterOS version. The router restarts briefly for this, interrupting all connections for a moment.",
  "Backup erstellen/wiederherstellen": "Create/restore a backup",
  "Details in der FAQ oben — kurz: sichert bzw. ersetzt die komplette Konfiguration.":
    "Details in the FAQ above — in short: it saves, or replaces, the entire configuration.",
  "VPN-Zugang (WireGuard)": "VPN access (WireGuard)",
  "Legt einen eigenen, verschlüsselten Zugang für ein Gerät an, um von außen sicher ins Heimnetz zu kommen. Braucht eine von außen erreichbare Adresse deines Anschlusses (öffentliche IP oder DDNS-Name).":
    "Creates a separate, encrypted connection for one device so you can reach your home network safely from outside. Needs an externally reachable address for your line (public IP or DDNS name).",
  "Router-Zugang (Passwort)": "Router login (password)",
  "Ändert das Passwort des aktuell angemeldeten RouterOS-Benutzers direkt am Gerät.":
    "Changes the password of the currently signed-in RouterOS user directly on the device.",
  "Startet den Router sofort neu. Das Cockpit ist währenddessen für rund 30–60 Sekunden nicht erreichbar.":
    "Restarts the router immediately. Cockpit is unreachable for roughly 30 to 60 seconds while that happens.",

  // --- Platzhalter in Eingabefeldern ---
  "z. B. 192.168.88.1": "e.g. 192.168.88.1",
  "z. B. Kamera Einfahrt": "e.g. driveway camera",
  "z. B. Handy von Anna": "e.g. Anna's phone",
  "z. B. 10.10.10.55": "e.g. 10.10.10.55",
  "z. B. meinrouter.example.net": "e.g. myrouter.example.net",
  "Leer = WireGuard-Port des Routers": "Empty = the router's WireGuard port",
  "z. B. vlan20-buero": "e.g. vlan20-office",
  "wird aus Interface übernommen": "taken from the interface",
  "z. B. 192.168.20.1": "e.g. 192.168.20.1",
  "z. B. ether1": "e.g. ether1",
  "nur falls vom Provider verlangt": "only if your provider requires it",
  "z. B. 7": "e.g. 7",
  "z. B. 443 oder 1024-2048": "e.g. 443 or 1024-2048",
  "z. B. 192.168.20.0/24": "e.g. 192.168.20.0/24",
  "z. B. 192.168.88.50": "e.g. 192.168.88.50",
  "Warum gibt es diese Regel?": "Why does this rule exist?",
  "z. B. 8291 oder 22": "e.g. 8291 or 22",
  "z. B. 192.168.88.0/24": "e.g. 192.168.88.0/24",
  "z. B. bridge": "e.g. bridge",
  "z. B. 443": "e.g. 443",
  "z. B. 80": "e.g. 80",

  // --- Rueckmeldungen und Hinweise aus app.js / pro.js ---
  "Daten werden geladen …": "Loading data …",
  "Live aus dem Router": "Live from the router",
  "Einträge": "entries",
  "Unbekanntes Gerät": "Unknown device",
  "Löschen": "Delete",
  "Schließen": "Close",
  "Rückgängig": "Undo",
  "Wird rückgängig gemacht …": "Undoing …",
  "Bitte auswählen …": "Please choose …",
  "Bitte prüfen": "Please check",
  "Änderung bestätigen": "Confirm change",
  "Jetzt ausführen": "Do it now",
  "Jetzt prüfen": "Check now",
  "Endgültig wiederherstellen": "Restore for good",
  "Aktiv": "Active",
  "Deaktiviert": "Disabled",
  "Auswahl nötig": "Selection needed",
  "Nicht verfügbar": "Not available",

  // Zustand und Sicherheits-Check
  "Heimnetz wird geprüft": "Checking your home network",
  "Dein Heimnetz ist gut aufgestellt": "Your home network is in good shape",
  "Alles im grünen Bereich": "All clear",
  "Die geprüften Punkte sind in Ordnung. Du musst gerade nichts ändern.":
    "The checks that ran are fine. There is nothing you need to change right now.",
  "Sobald die Routerdaten vorliegen, zeigen wir dir genau eine sinnvolle nächste Aktion.":
    "As soon as the router data is in, we will show you exactly one sensible next step.",
  "Sicherheits-Check vervollständigen": "Complete the security check",
  "Sicherheits-Check öffnen": "Open the security check",
  "Internet prüfen": "Check the internet connection",
  "Verbindung oder Dienst prüfen": "Check the connection or service",
  "Deine Verbindung läuft stabil.": "Your connection is stable.",
  "Dieser Punkt konnte nicht erläutert werden.": "This item could not be explained.",
  "Keine technischen Details verfügbar.": "No technical details available.",
  "Diese Übersicht zeigt die Geräte und Netzwerke, die Cockpit gerade vom Router lesen kann. Sie ersetzt keinen vollständigen Netzplan.":
    "This overview shows the devices and networks Cockpit can currently read from the router. It is not a substitute for a full network diagram.",
  "Fähigkeiten dieses Routers": "What this router supports",

  // Fehler und Verbindungszustand
  "Backend nicht erreichbar": "Backend unreachable",
  "Etwas ist schiefgelaufen.": "Something went wrong.",
  "Die Aktion konnte nicht ausgeführt werden.": "The action could not be carried out.",
  "Benutzername oder Passwort falsch.": "Wrong username or password.",
  "Das Gerät antwortet nicht rechtzeitig.": "The device is not answering in time.",
  "Der Router ist nicht erreichbar. Prüfe Kabel, Adresse und Verbindung.":
    "The router is unreachable. Check the cable, the address and the connection.",
  "Der Router antwortet zu langsam. Bitte aktualisiere erst, bevor du die Aktion wiederholst.":
    "The router is answering too slowly. Refresh before repeating the action.",
  "Der Routerzustand ist nach der Aktion unklar. Bitte aktualisiere, bevor du etwas wiederholst.":
    "The router state is unclear after that action. Refresh before repeating anything.",
  "Die Verbindung ist abgelaufen. Bitte erneut verbinden.":
    "The session has expired. Please connect again.",
  "Die Verbindung zum Router ist abgelaufen. Bitte erneut verbinden.":
    "The connection to the router has expired. Please connect again.",
  "Die vorige Verbindung ist nicht mehr aktiv. Bitte erneut verbinden.":
    "The previous connection is no longer active. Please connect again.",
  "Die Eingabe ist unvollständig oder ungültig. Bitte prüfe die markierten Werte.":
    "The input is incomplete or invalid. Please check the highlighted values.",
  "Der Eintrag wurde nicht gefunden. Er wurde möglicherweise bereits geändert oder entfernt.":
    "The entry was not found. It may already have been changed or removed.",
  "Diese Einstellung gibt es bereits. Bitte aktualisiere die Ansicht und prüfe die vorhandenen Einträge.":
    "That setting already exists. Refresh the view and check the existing entries.",
  "Diese Änderung passt nicht mehr zum aktuellen Routerzustand. Bitte aktualisiere die Seite.":
    "This change no longer matches the current router state. Please refresh the page.",
  "Zeitüberschreitung beim Backend. Ergebnis unbekannt; vor Wiederholung aktualisieren.":
    "The backend timed out. The outcome is unknown — refresh before trying again.",
  "Vorhandene Daten können veraltet sein.": "Existing data may be out of date.",
  "Daten teilweise nicht aktuell": "Some data is out of date",
  "Der Rückgängig-Zeitraum ist abgelaufen oder bereits verbraucht.":
    "The undo window has expired or was already used.",
  "Pro-Modul ist auf diesem Rechner nicht installiert.":
    "The Pro module is not installed on this machine.",
  "Pro-Modul wurde nicht initialisiert.": "The Pro module was not initialised.",
  "Die Routing-Tabelle ist für diesen Benutzer nicht verfügbar.":
    "The routing table is not available to this user.",
  "Der Router meldet aktuell keine Route.": "The router currently reports no route.",
  "Der Router meldet keine aktive Verbindung.": "The router reports no active connection.",
  "Dieser Router meldet keinen unterstützten WLAN-Treiber.":
    "This router reports no supported wireless driver.",
  "WireGuard ist auf diesem Router oder für diesen Benutzer nicht verfügbar.":
    "WireGuard is not available on this router, or not to this user.",
  "Es ist aktuell kein WLAN-Interface eingerichtet.":
    "No wireless interface is set up at the moment.",
  "Es ist aktuell kein WireGuard-Interface eingerichtet.":
    "No WireGuard interface is set up at the moment.",
  "Auf diesem Gerät ist kein Gastnetz eingerichtet.":
    "No guest network is set up on this device.",
  "Gastnetz nicht verfügbar": "Guest network unavailable",
  "Kein Gastnetz-Interface gefunden": "No guest network interface found",
  "Isolation nicht prüfbar": "Isolation cannot be checked",
  "Isolation vom Backend bestätigt": "Isolation confirmed by the backend",
  "Keine Isolation bestätigt: Gastnetz nicht isoliert":
    "No isolation confirmed: the guest network is not isolated",
  "Der lokale Backup-Ordner ist nicht sicher eingerichtet. Es wurde kein Backup verwendet.":
    "The local backup folder is not set up securely. No backup was used.",
  "Bitte zuerst ein WAN-Interface auswählen.": "Please select a WAN interface first.",
  "Gerät unter dieser Adresse nicht erreichbar.": "No device reachable at this address.",
  "Für dieses Gerät ist keine Weboberfläche bekannt.":
    "No web interface is known for this device.",

  // Erfolgsmeldungen
  "Backup wurde erstellt.": "Backup created.",
  "DHCP-Bereich wurde angelegt.": "DHCP range created.",
  "DHCP-Bereich wurde entfernt.": "DHCP range removed.",
  "DHCP-Client wurde eingerichtet.": "DHCP client set up.",
  "DHCP-Client wurde entfernt.": "DHCP client removed.",
  "Feste IP wurde gespeichert.": "Fixed IP saved.",
  "IP-Adresse wurde gespeichert.": "IP address saved.",
  "Routername wurde gespeichert.": "Router name saved.",
  "WLAN-Name wurde geändert.": "Wi-Fi name changed.",
  "WAN-Interface wurde ausgewählt.": "WAN interface selected.",
  "WAN-Adresse in die Zwischenablage kopiert.": "WAN address copied to the clipboard.",
  "Portfreigabe mit NAT- und Firewall-Regel angelegt.":
    "Port forward created, with NAT and firewall rules.",
  "Portfreigabe wurde entfernt.": "Port forward removed.",
  "Firewall-Regel wurde angelegt.": "Firewall rule created.",
  "Firewall-Regel wurde aktiviert.": "Firewall rule enabled.",
  "Firewall-Regel wurde deaktiviert.": "Firewall rule disabled.",
  "Die neue Firewall-Regel wurde entfernt.": "The new firewall rule was removed.",
  "VPN-Zugang wurde entfernt.": "VPN access removed.",
  "PPPoE-Verbindung wurde entfernt.": "PPPoE connection removed.",
  "Das vorherige WLAN-Passwort wurde wiederhergestellt.":
    "The previous Wi-Fi password has been restored.",
  "Das vorherige WLAN-Passwort konnte nicht wiederhergestellt werden.":
    "The previous Wi-Fi password could not be restored.",
  "Das vorherige Router-Passwort wurde wiederhergestellt.":
    "The previous router password has been restored.",
  "Wiederherstellung gestartet. Der Router wird kurz nicht erreichbar sein.":
    "Restore started. The router will be unreachable for a moment.",
  "WLAN-Trennung angefordert. Das Gerät kann sich sofort wieder verbinden.":
    "Disconnect requested. The device can reconnect immediately.",

  // Undo-Hinweise
  "WLAN-Passwort geändert": "Wi-Fi password changed",
  "Router-Passwort geändert": "Router password changed",
  "Firewall-Regel angelegt": "Firewall rule created",
  "Du kannst diese letzte Änderung noch fünf Minuten rückgängig machen.":
    "You can undo this last change for the next five minutes.",
  "Du kannst genau diese neue Regel noch fünf Minuten rückgängig machen.":
    "You can undo this one new rule for the next five minutes.",

  // Bestaetigungsdialoge
  "Diese Aktion kann nicht rückgängig gemacht werden.": "This action cannot be undone.",
  "Die Verbindung zum Router kann sofort abbrechen. Fahre nur fort, wenn du die neue Adresse sicher kennst.":
    "The connection to the router may drop instantly. Only continue if you are sure of the new address.",
  "IP-Adresse ändern": "Change IP address",
  "WLAN-Gerät kurz trennen": "Briefly disconnect a Wi-Fi device",
  "Das WLAN-Gerät kann sich sofort wieder verbinden. Kabelgeräte werden nicht getrennt. Falls dies dein eigenes Gerät ist, kann auch die Cockpit-Verbindung abbrechen.":
    "The wireless device can reconnect straight away. Wired devices are not affected. If this is your own device, the Cockpit connection may drop as well.",
  "Pool und DHCP-Server dieses Bereichs werden entfernt. Geräte erhalten dort keine neuen Adressen mehr.":
    "The pool and DHCP server for this range will be removed. Devices there will no longer get new addresses.",
  "Router-Fingerprint prüfen": "Check the router fingerprint",
  "Nur fortfahren, wenn dieser Fingerprint mit dem am Router selbst angezeigten übereinstimmt":
    "Only continue if this fingerprint matches the one shown on the router itself",
  "(z. B. in WinBox oder WebFig). Jetzt vertrauen und verbinden?":
    "(e.g. in WinBox or WebFig). Trust it and connect now?",

  // VPN-Konfiguration
  "WireGuard-Konfiguration": "WireGuard configuration",
  "Enthält einen privaten Schlüssel. Sicher aufbewahren und nicht weitergeben. Nur bis zum Neuladen oder Abmelden verfügbar. Die vollständige VPN-Verbindung ist damit noch nicht geprüft.":
    "Contains a private key. Keep it safe and do not pass it on. Available only until you reload or sign out. This does not yet prove the whole VPN connection works.",
  "Die Konfiguration ist nur nach dem Anlegen in dieser Sitzung verfügbar. Bereits heruntergeladene Datei verwenden; private Schlüssel können nicht nachträglich abgerufen werden.":
    "The configuration is only available in the session that created it. Use the file you already downloaded — private keys cannot be retrieved later.",
  "Mehrere WireGuard-Interfaces gefunden. Bitte eines auswählen.":
    "Several WireGuard interfaces found. Please choose one.",
  "Weboberfläche öffnen": "Open web interface",
  "Weboberfläche →": "Web interface →",

  // Formularerklaerungen
  "Der Zielport auf diesem Gerät. Nur nötig, wenn sich der Port ändern soll.":
    "The target port on that device. Only needed if the port should change.",
  "Legt fest, welche Art von Verbindung die Regel betrifft. „Alle“ ist bewusst weit gefasst.":
    "Sets which kind of traffic the rule applies to. \"All\" is deliberately broad.",
  "Von hier kommt der Verkehr. Leer bedeutet: aus jedem Netzwerk.":
    "Where the traffic comes from. Empty means: from any network.",
  "Dieses Gerät oder Netzwerk ist das Ziel. Leer bedeutet: jedes Ziel.":
    "The device or network being addressed. Empty means: any destination.",
  "Dorthin wird die Verbindung nach der Übersetzung geleitet, zum Beispiel auf einen Server im Heimnetz.":
    "Where the connection is sent after translation, for example to a server on your home network.",

  // Firewall-Aktionen und Regelzusammenfassung
  "Springen (jump)": "Jump",
  "Zurückkehren (return)": "Return",
  "Verzögern (tarpit)": "Tarpit",
  "Umleiten (redirect)": "Redirect",
  "Quelle zur Adressliste hinzufügen": "Add source to address list",
  "Ziel zur Adressliste hinzufügen": "Add destination to address list",
  "unbekannt": "unknown",
  "Bedingungen vollständig gemeldet": "All conditions reported",
  "Teilansicht: API meldet nicht garantiert alle Bedingungen; vor Änderungen vollständige Regel in RouterOS prüfen.":
    "Partial view: the API does not guarantee every condition is listed — check the full rule in RouterOS before changing it.",
  "Firewall-Regel umschalten": "Toggle firewall rule",
  "Firewall-Regel löschen": "Delete firewall rule",
  "Endgültig löschen": "Delete permanently",
  "Das kann den Zugang sperren oder Schutzregeln außer Kraft setzen.":
    "This can lock out access or disable protective rules.",
  "Diese Firewall-Regel wirklich endgültig löschen?":
    "Really delete this firewall rule for good?",
  "Das ist eine RouterOS-Systemregel, kein eigenes Cockpit-Element. Das Löschen kann die Verbindung zum Router kappen oder das Netzwerk öffnen. Wirklich endgültig löschen?":
    "This is a RouterOS system rule, not something Cockpit created. Deleting it can cut the connection to the router or open up the network. Really delete it for good?",

  // IP-Dienste, VPN, PPPoE
  "SSH deaktivieren": "Disable SSH",
  "Cockpit spricht nur SSH mit dem Router. Die Verbindung bricht ab; danach geht es hier nicht weiter. Du brauchst WinBox, eine serielle Verbindung oder direkten Zugang.":
    "Cockpit talks to the router over SSH only. The connection will drop and you cannot continue here. You will need WinBox, a serial connection or direct access.",
  "VPN-Zugang entfernen": "Remove VPN access",
  "Zugang entfernen": "Remove access",
  "Das WireGuard-Gerät kann sich danach nicht mehr verbinden.":
    "The WireGuard device will no longer be able to connect.",
  "PPPoE-Verbindung entfernen": "Remove PPPoE connection",
  "Verbindung entfernen": "Remove connection",
  "Die Verbindung zum Internet kann dadurch ausfallen.":
    "This can take down the internet connection.",

  // --- Meldungen des Backends ---
  // Sie erreichen den Nutzer ueber Toasts und Fehlerbanner, laufen also durch dieselbe Schicht.
  // Das Backend selbst antwortet weiterhin auf Deutsch; wer die API direkt anspricht, bekommt
  // deutschen Text. Fuer die Oberflaeche ist das unsichtbar.
  "'host' und 'password' sind Pflicht": "'host' and 'password' are required",
  "'host', 'user' und 'password' müssen Text sein": "'host', 'user' and 'password' must be text",
  "'ssh_port' muss eine Zahl sein": "'ssh_port' must be a number",
  "'ssh_port' muss zwischen 1 und 65535 liegen": "'ssh_port' must be between 1 and 65535",
  "Der Request-Body muss ein JSON-Objekt sein": "The request body must be a JSON object",
  "'enabled' fehlt oder ist kein Wahrheitswert": "'enabled' is missing or is not a boolean",
  "'external_port'/'internal_port' muessen 1-65535 sein, 'internal_ip' eine gueltige IPv4-Adresse":
    "'external_port'/'internal_port' must be 1-65535, and 'internal_ip' a valid IPv4 address",
  "'network' (CIDR), 'range_start' und 'range_end' muessen gueltig sein":
    "'network' (CIDR), 'range_start' and 'range_end' must be valid",
  "Adresse muss im Format 192.168.1.1/24 angegeben werden":
    "The address must be given as 192.168.1.1/24",
  "Der Routername muss 1 bis 64 Zeichen enthalten und darf keine Steuerzeichen, Anführungszeichen oder Semikolons enthalten":
    "The router name must be 1 to 64 characters and must not contain control characters, quotation marks or semicolons",
  "Die SSID muss 1 bis 32 Zeichen enthalten und darf keine Anführungszeichen oder Zeilenumbrüche enthalten":
    "The SSID must be 1 to 32 characters and must not contain quotation marks or line breaks",
  "Das Passwort darf keine Anführungszeichen oder Zeilenumbrüche enthalten":
    "The password must not contain quotation marks or line breaks",
  "Das Passwort darf keine Anführungszeichen oder Zeilenumbrüche enthalten (max. 63 Zeichen)":
    "The password must not contain quotation marks or line breaks (63 characters maximum)",
  "Ungültiger Interface-Name": "Invalid interface name",
  "Ungültige MAC-Adresse.": "Invalid MAC address.",
  "Dieses Interface existiert nicht auf dem Router": "This interface does not exist on the router",
  "Dieses Interface hat mehrere IP-Adressen -- das kann hier nicht sicher geändert werden":
    "This interface has several IP addresses — that cannot be changed safely here",
  "Das Interface braucht zuerst eine eigene IP-Adresse (siehe Netzwerk-Bereich)":
    "The interface needs its own IP address first (see the network section)",
  "Der DHCP-Bereich muss vollständig innerhalb des angegebenen Netzes liegen":
    "The DHCP range has to lie entirely inside the given network",
  "Netz- und Broadcastadresse dürfen nicht im DHCP-Bereich liegen":
    "The network and broadcast addresses must not fall inside the DHCP range",
  "Bitte ein WAN-Interface auswählen.": "Please select a WAN interface.",
  "Mehrere aktive WAN-Interfaces gefunden. Bitte eines auswählen.":
    "Several active WAN interfaces found. Please choose one.",
  "WAN-Interface nicht gefunden.": "WAN interface not found.",
  "Die Interface-Liste WAN fehlt. PPPoE wurde nicht angelegt.":
    "The WAN interface list is missing. The PPPoE connection was not created.",
  "Bitte Interface, Benutzername und Passwort sowie gültige optionale Werte angeben":
    "Please provide the interface, username and password, plus valid optional values",
  "Eine PPPoE-Verbindung mit diesem Namen existiert bereits":
    "A PPPoE connection with that name already exists",

  // Gastnetz
  "Gastnetz-Interface nicht gefunden": "Guest network interface not found",
  "Kein Gastnetz-Interface für diese Sitzung ausgewählt.":
    "No guest network interface selected for this session.",
  "Noch kein Gastnetz-Interface ausgewaehlt": "No guest network interface selected yet",

  // WLAN-Trennung
  "Die WLAN-Trennung konnte nicht bestätigt werden. Bitte den Gerätestatus prüfen.":
    "The disconnect could not be confirmed. Please check the device status.",
  "Dieses Gerät ist hier nicht direkt als WLAN-Client verbunden. Kabelgeräte und Clients anderer Access Points können so nicht getrennt werden. Es wurde nichts geändert.":
    "This device is not connected here as a wireless client. Wired devices and clients of other access points cannot be disconnected this way. Nothing was changed.",
  "Mehrere WLAN-Registrierungen gefunden. Aus Sicherheitsgründen wurde nichts getrennt.":
    "Several wireless registrations found. Nothing was disconnected, as a safety measure.",
  "WLAN-Registrierung konnte nicht eindeutig zugeordnet werden.":
    "The wireless registration could not be matched unambiguously.",
  "WLAN-Registrierungen konnten nicht sicher gelesen werden.":
    "The wireless registrations could not be read reliably.",
  "WLAN-Interface konnte nicht sicher zugeordnet werden.":
    "The wireless interface could not be matched reliably.",

  // Undo
  "Für dieses WLAN-Passwort steht aktuell kein Rückgängig zur Verfügung.":
    "There is no undo available for this Wi-Fi password right now.",
  "Für das Router-Passwort steht aktuell kein Rückgängig zur Verfügung.":
    "There is no undo available for the router password right now.",
  "Der ursprüngliche Wert kann nicht sicher wiederhergestellt werden.":
    "The original value cannot be restored reliably.",
  "Regel unbekannt": "Rule unknown",

  // VPN
  "Bitte ein WireGuard-Interface auswählen.": "Please select a WireGuard interface.",
  "WireGuard-Interface nicht gefunden": "WireGuard interface not found",
  "WireGuard-Interface nicht gefunden.": "WireGuard interface not found.",
  "Am WireGuard-Interface ist kein aktives IPv4-Netz eingerichtet. Bitte zuerst das VPN-Netz einrichten.":
    "The WireGuard interface has no active IPv4 network. Please set up the VPN network first.",
  "Das IPv4-Netz des WireGuard-Interfaces konnte nicht sicher geprüft werden. Kein VPN-Zugang angelegt.":
    "The WireGuard interface's IPv4 network could not be checked reliably. No VPN access was created.",
  "Der WireGuard-Port konnte nicht sicher ermittelt werden. Kein VPN-Zugang angelegt.":
    "The WireGuard port could not be determined reliably. No VPN access was created.",
  "Die Firewall-Freigabe für den WireGuard-Port konnte nicht sichergestellt werden. Kein VPN-Zugang angelegt.":
    "The firewall opening for the WireGuard port could not be ensured. No VPN access was created.",
  "Vorhandene Router-/Peer-Adressen konnten nicht sicher geprüft werden. Kein VPN-Zugang angelegt.":
    "Existing router and peer addresses could not be checked reliably. No VPN access was created.",
  "Die Client-IP muss eine nutzbare Hostadresse im eingerichteten WireGuard-Netz sein, keine Netz- oder Broadcastadresse.":
    "The client IP has to be a usable host address inside the configured WireGuard network, not a network or broadcast address.",
  "Diese Client-IP wird bereits vom Router verwendet.":
    "That client IP is already in use by the router.",
  "Bitte eine öffentliche VPN-IP oder einen DNS/DDNS-Namen ohne URL und Port angeben. Optionaler externer Port: 1–65535.":
    "Please give a public VPN IP or a DNS/DDNS name, without a URL or port. Optional external port: 1–65535.",
  "Bitte einen gültigen Namen (maximal 64 UTF-8-Bytes, ohne Steuerzeichen, Anführungszeichen oder Semikolon) und eine IPv4-Clientadresse ohne Netzmaske angeben.":
    "Please give a valid name (64 UTF-8 bytes maximum, no control characters, quotation marks or semicolons) and an IPv4 client address without a netmask.",

  // Backup und Firmware
  "Backup-Ordner konnte nicht gelesen werden.": "The backup folder could not be read.",
  "Noch kein gültiges Backup über das Cockpit erstellt.":
    "No valid backup has been created through Cockpit yet.",
  "Update-Status konnte nicht geprüft werden.": "The update status could not be checked.",
  "Versionsdaten konnten nicht ermittelt werden.": "Version data could not be determined.",

  // Sicherheits-Check
  "Zugriffsschutz auf den Router": "Protection against access to the router",
  "Unsichere Klartext-Dienste": "Insecure plain-text services",
  "Gastnetz-Isolation": "Guest network isolation",
  "Firmware aktuell": "Firmware up to date",
  "Aktuelles Backup vorhanden": "Recent backup available",
  "Telnet und FTP sind deaktiviert.": "Telnet and FTP are disabled.",
  "Dienste konnten nicht gelesen werden.": "The services could not be read.",
  "Firewall-Regeln konnten nicht gelesen werden.": "The firewall rules could not be read.",
  "Status von Telnet und FTP konnte nicht vollständig gelesen werden.":
    "The status of Telnet and FTP could not be read in full.",

  // Von der statischen Pruefung (test-language-static.py) nachgetragen: Meldungen, die nur bei
  // bestimmten Fehleingaben entstehen und deshalb weder im Browsertest noch am Testgeraet auftauchen.
  "'confirm_fingerprint' muss Text sein": "'confirm_fingerprint' must be text",
  "'enabled' fehlt": "'enabled' is missing",
  "'gateway'/'dns_servers' ungueltig": "'gateway'/'dns_servers' invalid",
  "'interface' fehlt oder ungueltig": "'interface' is missing or invalid",
  "'ip' fehlt oder ungueltig": "'ip' is missing or invalid",
  "'mac' ungueltig": "'mac' is invalid",
  "'name' fehlt oder ungueltig": "'name' is missing or invalid",
  "'range_start' muss kleiner oder gleich 'range_end' sein":
    "'range_start' must be less than or equal to 'range_end'",
  "'webui_port' muss 1-65535 sein": "'webui_port' must be 1-65535",
  "'webui_scheme' muss http oder https sein": "'webui_scheme' must be http or https",
  "1 bis 3 gueltige IPv4-Adressen erwartet": "Expected 1 to 3 valid IPv4 addresses",
  "Mindestens 8 Zeichen": "At least 8 characters",
  "Backup unbekannt": "Unknown backup",
  "DHCP-Bereich unbekannt": "Unknown DHCP range",
  "Dienst unbekannt": "Unknown service",
  "Dienstname ungueltig": "Invalid service name",
  "Interface unbekannt": "Unknown interface",
  "PPPoE-Verbindung unbekannt": "Unknown PPPoE connection",
  "Portweiterleitung unbekannt": "Unknown port forward",
  "VPN-Peer unbekannt": "Unknown VPN peer",
  "WLAN-Interface unbekannt": "Unknown wireless interface",
  "IP bereits vergeben": "IP already taken",
  "Port bereits belegt": "Port already in use",
  "Diese Client-IP liegt bereits im Adressbereich eines WireGuard-Peers.":
    "That client IP already falls inside another WireGuard peer's address range.",
  "Fuer dieses Interface existiert bereits ein DHCP-Bereich":
    "A DHCP range already exists for this interface",
  "Fuer dieses Interface laeuft bereits ein DHCP-Client":
    "A DHCP client is already running on this interface",
  "Kein DHCP-Client fuer dieses Interface": "No DHCP client on this interface",
  "Kein bekannter DHCP-Lease fuer diese MAC -- Geraet muss vorher online gewesen sein":
    "No known DHCP lease for that MAC — the device has to have been online first",
  "Konnte nicht geprüft werden, ob unsichere Altdienste wie Telnet oder FTP an sind. Bitte später erneut prüfen.":
    "Could not check whether insecure legacy services such as Telnet or FTP are switched on. Please try again later.",
  "Der Status von Telnet und FTP konnte nicht vollständig gelesen werden - keine verlässliche Aussage möglich.":
    "The status of Telnet and FTP could not be read in full — no reliable statement is possible.",
  "Telnet und FTP sind aus. Diese unsicheren Altdienste stellen kein Risiko dar.":
    "Telnet and FTP are off. Those insecure legacy services pose no risk here.",
  "Für diese Sitzung ist kein Gastnetz ausgewählt - die Trennung zum Hausnetz wurde nicht geprüft.":
    "No guest network is selected for this session — separation from the home network has not been checked.",
  "Das Gastnetz ist vom Hausnetz getrennt. Auch wenn beide technisch auf demselben Netzwerksegment liegen, verhindert eine zusätzliche Regel den Zugriff aufs Hausnetz - kein Handlungsbedarf.":
    "The guest network is separated from the home network. Even though both technically sit on the same segment, an additional rule blocks access to the home network — nothing to do.",
  "Gastnetz und Hausnetz sind aktuell NICHT sauber getrennt - Geräte im Gastnetz können möglicherweise auf dein Hausnetz zugreifen. Richte eine Bridge-Firewall-Regel oder eine VLAN-Trennung für das Gastnetz-Interface ein, oder trenne Gast- und Hausnetz auf getrennte Netzwerkkarten/Bridges.":
    "The guest and home networks are NOT cleanly separated at the moment — devices on the guest network may be able to reach your home network. Set up a bridge firewall rule or VLAN separation for the guest interface, or move guest and home networks onto separate interfaces or bridges.",
  "Die Gastnetz-Isolation konnte nicht geprüft werden, weil die Firewall-Regeln nicht gelesen werden konnten.":
    "Guest network isolation could not be checked because the firewall rules could not be read.",
  "Es konnte nicht geprüft werden, ob eine neue RouterOS-Version verfügbar ist.":
    "It could not be checked whether a newer RouterOS version is available.",
  "Es liegen keine vollständigen Versionsdaten vor - vermutlich hat der Router noch nie erfolgreich nach Updates gesucht. Stoße unter System eine Update-Prüfung an.":
    "There is no complete version data — the router has probably never successfully checked for updates. Start an update check under System.",
  "Der Backup-Ordner konnte nicht gelesen werden - es lässt sich nicht sagen, ob ein aktuelles Backup vorliegt.":
    "The backup folder could not be read — there is no way to tell whether a recent backup exists.",
  "Es liegt noch kein Backup über das Cockpit vor. Erstelle jetzt eines, damit du die Router-Konfiguration im Notfall wiederherstellen kannst.":
    "There is no Cockpit backup yet. Create one now so you can restore the router configuration if the worst happens.",

  // --- Von der Sprachpruefung (test-language.py) nachgetragen ---
  "Jetzt prüfen →": "Check now →",
  "SSID speichern": "Save SSID",
  "Raum speichern": "Save room",
  "IP speichern": "Save IP",
  "Noch keine PPPoE-Verbindung eingerichtet.": "No PPPoE connection set up yet.",
  "Keine Regeln in dieser Kette vorhanden.": "No rules in this chain.",
  "Bitte auswählen": "Please choose",
  "Noch keine Backups vorhanden.": "No backups yet.",
  "Neues Passwort (mind. 8 Zeichen)": "New password (8 characters minimum)",

  // --- Am echten Router gefunden: Zustaende, die die Mock-Daten nicht abdecken ---
  "Backend verbunden": "Backend connected",
  "Heute wichtig": "Important today",
  "Nicht verbunden": "Not connected",
  "Keine DHCP-Leases vorhanden.": "No DHCP leases.",
  "Keine DHCP-Geräte gefunden.": "No DHCP devices found.",
  "Keine Cockpit-Portfreigaben vorhanden.": "No Cockpit port forwards.",
  "Die Trennung vom privaten Netzwerk ist nicht nachgewiesen. Ein aktiviertes Gastnetz allein schützt deine Geräte nicht. Vor der Nutzung die Netztrennung prüfen lassen.":
    "Separation from your private network is not proven. An enabled guest network alone does not protect your devices. Have the separation checked before relying on it.",
  "Ob der Router gegen unbekannte Zugriffsversuche von außen geschützt ist, konnte nicht abschließend geklärt werden. Das ist keine Bestätigung, dass er sicher ist - bitte die Firewall-Regeln manuell prüfen.":
    "Whether the router is protected against unknown access attempts from outside could not be established conclusively. This is not a confirmation that it is safe — please check the firewall rules by hand.",
  "Es konnte nicht eindeutig geklärt werden, ob das Gastnetz vom Hausnetz getrennt ist. Das ist keine Bestätigung der Sicherheit - bitte die Firewall-Regeln manuell prüfen.":
    "It could not be established clearly whether the guest network is separated from the home network. This is not a confirmation of safety — please check the firewall rules by hand.",
  "IPv4: Vorgelagerte Freigaben oder Sprungketten benötigen eine vollständige Firewall-Prüfung. IPv6: Vorgelagerte Freigaben oder Sprungketten benötigen eine vollständige Firewall-Prüfung.":
    "IPv4: earlier accept rules or jump chains require a full firewall review. IPv6: earlier accept rules or jump chains require a full firewall review.",
  "IPv4: keine eindeutige Regel gefunden. IPv6: aktiv, aber keine eindeutige Regel gefunden.":
    "IPv4: no clear rule found. IPv6: active, but no clear rule found.",
  "Internetverbindung prüfen": "Check the internet connection",
  "Netzwerkname (SSID)": "Network name (SSID)",
  "Wird aktualisiert …": "Refreshing …",
  "Technische Details": "Technical details",
  "Verbunden": "Connected",
  "DHCP-Leases": "DHCP leases",
  "Raum": "Room",
  "Details verwalten →": "Manage details →",
  "Keine DHCP-Clients eingerichtet.": "No DHCP clients configured.",
  "Eingangsinterface (optional)": "Inbound interface (optional)",
  "Ausgangsinterface (optional)": "Outbound interface (optional)",
  "Zieladresse (optional)": "Destination address (optional)",
  "Quelladresse (optional)": "Source address (optional)",
  "Deaktivieren": "Disable",
  "Aktivieren": "Enable",
  "Config anzeigen": "Show config",
  "Entfernen": "Remove",
  "Kein Raum zugewiesen": "No room assigned",
  "Status ansehen": "View status",
  "Details ansehen": "View details",
  "Sicherheits-Check ansehen": "View the security check",
  "Keine DHCP-Bereiche eingerichtet.": "No DHCP ranges configured.",
  "RouterOS-Systemregel": "RouterOS system rule",
  "Der Router meldet derzeit keine aktive Verbindung zum Internet.":
    "The router currently reports no active connection to the internet.",
  // --- Benutzerverwaltung (Pro, 18.09.2026) und Sicherheits-Check "Standardbenutzer admin" ---
  "Benutzer": "Users",
  "Standardbenutzer admin": "Default user admin",
  "MikroTik empfiehlt als ersten Schritt einen eigenen Benutzer.": "MikroTik recommends creating your own user as the first step.",
  "Lege einen Benutzer mit vollen Rechten an, melde dich einmal damit an und schalte danach": "Create a user with full rights, log in with it once, then switch off",
  "ab. Cockpit verhindert, dass du dich selbst aussperrst: Der angemeldete Benutzer und der letzte Vollzugang lassen sich weder deaktivieren noch löschen oder herabstufen.":
    ". Cockpit stops you locking yourself out: the logged-in user and the last full-access user cannot be disabled, deleted or downgraded.",
  "Benutzer anlegen": "Create user",
  "Vollzugriff, Ändern oder nur Lesen": "Full access, change or read only",
  "Benutzername": "Username",
  "z. B. marco": "e.g. marco",
  "Rechte": "Rights",
  "Vollzugriff (full)": "Full access (full)",
  "Ändern ohne Benutzerverwaltung (write)": "Change settings, no user management (write)",
  "Nur lesen (read)": "Read only (read)",
  "Nur Buchstaben, Ziffern und Sonderzeichen ohne Umlaute, keine Anführungszeichen. RouterOS verwirft Umlaute per SSH stillschweigend.":
    "Letters, digits and ASCII symbols only, no quotation marks. RouterOS silently drops non-ASCII characters over SSH.",
  "Keine Benutzer gefunden.": "No users found.",
  "Ändern": "Change",
  "Nur lesen": "Read only",
  "Noch nie angemeldet": "Never logged in",
  "Du": "You",
  "Letzter Vollzugang": "Last full access",
  "Standardname": "Default name",
  "Passwort setzen": "Set password",
  "Abbrechen": "Cancel",
  "Rechte ändern": "Change rights",
  "Benutzer deaktivieren": "Disable user",
  "Benutzer löschen": "Delete user",
  "Die Passwörter stimmen nicht überein.": "The passwords do not match.",
  "Verwaltet die Anmeldekonten des Routers.": "Manages the router's login accounts.",
  "darf alles,": "may do anything,",
  "darf Einstellungen ändern, aber keine Benutzer,": "may change settings but not users,",
  "nur ansehen. Der Standardbenutzer": "may only view. The default user",
  "sollte abgeschaltet werden, sobald ein eigener Vollzugang funktioniert.": "should be switched off as soon as your own full-access user works.",
  // Backend-Meldungen
  "'group' muss full, write oder read sein": "'group' must be full, write or read",
  "Benutzer unbekannt": "Unknown user",
  "Benutzername: 1 bis 64 Zeichen, Buchstaben, Ziffern und _ . # @ -, am Anfang und Ende Buchstabe oder Ziffer":
    "Username: 1 to 64 characters, letters, digits and _ . # @ -, starting and ending with a letter or digit",
  "Das Passwort darf nur Buchstaben, Ziffern und Sonderzeichen ohne Umlaute enthalten, keine Anführungszeichen. RouterOS verwirft Umlaute per SSH stillschweigend.":
    "The password may only contain letters, digits and ASCII symbols, no quotation marks. RouterOS silently drops non-ASCII characters over SSH.",
  "Das Passwort darf nur Buchstaben, Ziffern und Sonderzeichen ohne Umlaute enthalten, keine Anführungszeichen (max. 63 Zeichen). RouterOS verwirft Umlaute per SSH stillschweigend.":
    "The password may only contain letters, digits and ASCII symbols, no quotation marks (max. 63 characters). RouterOS silently drops non-ASCII characters over SSH.",
  "Das eigene Passwort wird über 'Router-Passwort ändern' gesetzt.": "Your own password is set via 'Change router password'.",
  "Benutzer angelegt, aber danach nicht wiedergefunden -- bitte Liste prüfen": "User created but not found afterwards -- please check the list",
  "Der Router hat die Änderung nicht übernommen -- bitte Liste prüfen": "The router did not apply the change -- please check the list",
  "Der Router hat die Gruppe nicht übernommen -- bitte Liste prüfen": "The router did not apply the group -- please check the list",
  "Der Router hat den Benutzer nicht gelöscht -- bitte Liste prüfen": "The router did not delete the user -- please check the list",
  "Der andere Benutzer mit vollen Rechten war noch nie angemeldet. Melde dich erst einmal mit ihm an, damit das Passwort nachweislich stimmt, dann lässt sich":
    "The other full-access user has never logged in. Log in with it once first, so the password is proven to work, then",
  "Benutzerliste konnte nicht gelesen werden.": "The user list could not be read.",
  "Benutzerliste ist leer oder unlesbar.": "The user list is empty or unreadable.",
  "Konnte nicht geprüft werden, ob der Standardbenutzer admin noch aktiv ist. Bitte später erneut prüfen.":
    "Could not check whether the default user admin is still active. Please check again later.",
  "Die Benutzerliste des Routers war leer oder unlesbar - keine verlässliche Aussage möglich.":
    "The router's user list was empty or unreadable - no reliable statement possible.",
  "admin ist deaktiviert oder entfernt.": "admin is disabled or removed.",
  "Der Standardbenutzer admin ist abgeschaltet. Angreifer müssen damit auch den Benutzernamen raten, nicht nur das Passwort.":
    "The default user admin is switched off. Attackers now have to guess the username as well, not just the password.",
  "admin ist aktiv und der einzige Vollzugang.": "admin is active and the only full-access user.",
  "Der Standardbenutzer admin ist aktiv und der einzige Vollzugang. Jeder Angriff auf MikroTik-Router probiert diesen Namen zuerst. Lege einen eigenen Vollzugang an (in Cockpit Pro unter Benutzer, sonst in WinBox unter System > Users), melde dich einmal damit an und schalte admin danach ab.":
    "The default user admin is active and the only full-access user. Every attack on MikroTik routers tries this name first. Create your own full-access user (in Cockpit Pro under Users, otherwise in WinBox under System > Users), log in with it once, then switch admin off.",
  "admin ist noch aktiv, obwohl ein eigener Vollzugang existiert.": "admin is still active although your own full-access user exists.",
  "Ein eigener Vollzugang existiert bereits, admin ist aber noch aktiv. Schalte admin ab (in Cockpit Pro unter Benutzer, sonst in WinBox unter System > Users), sobald du dich mit dem eigenen Zugang einmal angemeldet hast.":
    "Your own full-access user already exists, but admin is still active. Switch admin off (in Cockpit Pro under Users, otherwise in WinBox under System > Users) once you have logged in with your own account.",
  "Cockpit wurde aktualisiert, die Seite wird neu geladen.": "Cockpit was updated, reloading the page.",
};
