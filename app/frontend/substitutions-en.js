// Teilersetzungen fuer zusammengesetzte Zeichenketten (siehe i18n.js, dritte Stufe).
//
// Die Firewall-Zusammenfassung baut sich aus Bausteinen zusammen ("Kette: input · Zielport 22 ·
// ..."), landet aber als ein Textknoten. Weder ein exakter Woerterbuch-Treffer noch ein Muster
// koennen das abdecken, weil jede Regel eine andere Kombination ergibt.
//
// Reihenfolge zaehlt: laengere Zeichenketten zuerst, sonst zerlegt eine kurze die laengere.

window.COCKPIT_SUBSTITUTIONS_EN = [
  ["Teilansicht: API meldet nicht garantiert alle Bedingungen; vor Änderungen vollständige Regel in RouterOS prüfen.",
    "Partial view: the API does not guarantee every condition is listed — check the full rule in RouterOS before changing it."],

  // Sicherheitscheck: "detail" entsteht aus Saetzen mit " ".join(). Welche zusammenkommen, haengt vom
  // Router ab, deshalb steht hier jeder Satz einzeln (test-language-static.py prueft das).
  ["Gastnetz und Hausnetz liegen auf derselben Bridge, 'use-ip-firewall' ist nicht aktiv -- die IP-Firewall greift für diesen Verkehr gar nicht, unabhängig von vorhandenen Regeln. Weder ein Bridge-Firewall-Filter noch eine VLAN-Trennung konnten die Isolation nachweisen.",
    "Guest and home networks share one bridge and 'use-ip-firewall' is off, so the IP firewall does not see this traffic, whatever rules exist. Neither a bridge firewall filter nor VLAN separation could prove the isolation."],
  ["Layer 2: Ein Hausnetz-Port liegt im selben VLAN wie das Gastnetz, oder der Gast-Port lässt selbst getaggte Pakete in andere VLANs.",
    "Layer 2: a home network port sits in the guest VLAN, or the guest port lets self-tagged frames into other VLANs."],
  ["Layer 2: Die VLAN-Trennung konnte nicht nachgewiesen werden.", "Layer 2: VLAN separation could not be proven."],
  ["Layer 2: Das Gastnetz liegt in einem eigenen VLAN.", "Layer 2: the guest network has its own VLAN."],
  ["Layer 2: Eine aktive Bridge-Firewall-Filter-Regel sperrt den Verkehr zum Hausnetz.",
    "Layer 2: an active bridge firewall filter rule blocks traffic to the home network."],
  ["Bridge-Zugehörigkeit konnte nicht geprüft werden.", "Bridge membership could not be checked."],
  ["Layer 2: Das Gast-Interface ist unter diesem Namen am Router nicht zu finden, etwa wegen eines Sonderzeichens im Namen. Ein Name ohne Sonderzeichen behebt das.",
    "Layer 2: the guest interface cannot be found under this name on the router, perhaps because of a special character. A name without special characters fixes this."],
  ["IPv4: aktive Drop-Regel vom Gastnetz ins Hausnetz nachgewiesen.", "IPv4: active drop rule from guest to home network confirmed."],
  ["IPv6: aktive Drop-Regel vom Gastnetz ins Hausnetz nachgewiesen.", "IPv6: active drop rule from guest to home network confirmed."],
  ["IPv4: eine Accept-Regel erlaubt Zugriff vom Gastnetz ins Hausnetz.", "IPv4: an accept rule allows access from guest to home network."],
  ["IPv6: eine Accept-Regel erlaubt Zugriff vom Gastnetz ins Hausnetz.", "IPv6: an accept rule allows access from guest to home network."],
  ["IPv4: keine eindeutige Regel gefunden.", "IPv4: no clear rule found."],
  ["IPv6: aktiv, aber keine eindeutige Regel gefunden.", "IPv6: active, but no clear rule found."],
  ["IPv4: Auf diesem Gerät gibt es für das Gastnetz keinen Router und keinen Weg nach außen.",
    "IPv4: on this device the guest network has no router and no way out."],
  ["IPv6: Auf diesem Gerät gibt es für das Gastnetz keinen Router und keinen Weg nach außen.",
    "IPv6: on this device the guest network has no router and no way out."],
  ["IPv6: An diesem Gerät gibt es kein anderes IPv6-Netz, in das das Gastnetz geroutet werden könnte.",
    "IPv6: this device has no other IPv6 network the guest network could be routed into."],
  ["IPv6-Status konnte nicht ermittelt werden.", "IPv6 status could not be determined."],
  ["Der Internetausgang hat eine private Adresse, dieser Router hängt also vermutlich hinter einem anderen Router. Eine Sperre muss auch das Netz davor abdecken.",
    "The internet uplink has a private address, so this router probably sits behind another router. A block must also cover the network in front of it."],
  ["Geroutet wird auf einem anderen Gerät, dort muss die Sperre liegen.",
    "Routing happens on another device, the block must be there."],
  ["Firewall-Regeln konnten nicht gelesen werden.", "Firewall rules could not be read."],
  ["Eine allgemeine Freigabe steht vor einer wirksamen Zugriffssperre.", "A general accept rule comes before an effective block."],
  ["Vorgelagerte Freigaben oder Sprungketten benötigen eine vollständige Firewall-Prüfung.",
    "earlier accept rules or jump chains require a full firewall review."],
  ["Eine aktive Sperrregel für unbekannten Zugriff ist vorhanden.", "An active rule blocking unknown access is in place."],
  ["Keine aktive, generell wirkende Drop/Reject-Regel in der Input-Kette gefunden.",
    "No active, generally effective drop or reject rule found in the input chain."],
  ["Der Router hat keine wirksame Sperre gegen unbekannte Zugriffsversuche von außen.", "The router has no effective block against unknown access attempts from outside."],
  ["Prüfe zuerst, dass dein Verwaltungszugang in der Liste LAN steht und dein Internetanschluss nicht.", "First check that your management access is in the list LAN and your internet connection is not."],
  ["Lege dann im Safe Mode am Ende der Input-Kette diese Regeln an: ", "Then, in Safe Mode, add these rules at the end of the input chain: "],
  [" und danach /ip firewall filter", " and then /ip firewall filter"],
  ["Für IPv6 nimm die Regeln aus der Standardkonfiguration von RouterOS als Vorlage, sie lassen ICMPv6 und DHCPv6 durch.", "For IPv6, use the rules from the RouterOS default configuration as a template, they let ICMPv6 and DHCPv6 through."],
  ["Läuft dieses Gerät nur als Access Point oder Switch hinter einem Router, ist das normal, dann muss der Router davor schützen.", "If this device only runs as an access point or switch behind a router, this is normal, and the router in front has to protect it."],
  ["Eine Freigabe öffnet einen Verwaltungsdienst des Routers zum Internet.", "An accept rule opens a management service of the router to the internet."],
  ["IPv6: Ohne globale Adresse und Standardroute führt kein Weg aus dem Internet zum Router.", "IPv6: Without a global address and a default route, no path leads from the internet to the router."],
  ["Eine Regel lässt sich nicht sicher lesen, weil sie freien Text enthält, der wie Regelfelder aussehen kann.",
    "A rule cannot be read reliably, because it contains free text that may look like rule fields."],
  ["Eine Sperrregel ist vorhanden, ob sie den Zugriff aus dem Internet trifft, lässt sich nicht belegen.",
    "A blocking rule exists, but it cannot be shown that it covers access from the internet."],

  ["Bedingungen vollständig gemeldet", "All conditions reported"],
  ["Verbindungsstatus: ", "Connection state: "],
  ["Eingangsliste: ", "Inbound list: "],
  ["Ausgangsliste: ", "Outbound list: "],
  ["Eingang: ", "In: "],
  ["Ausgang: ", "Out: "],
  ["Quellport ", "Source port "],
  ["Zielport ", "Destination port "],
  ["Kette: ", "Chain: "],
  ["von ", "from "],
  ["zu ", "to "],

  // WLAN-Karte: diese Angaben stehen hinter einem Symbol ("◉ Band unbekannt"), deshalb greift
  // weder ein exakter Treffer noch ein verankertes Muster.
  ["Band unbekannt", "Band unknown"],
  ["Sichtbar", "Visible"],
  ["Verborgen", "Hidden"],
  ["Keine Adresse", "No address"],

  // Handlungsknoepfe der "Heute wichtig"-Karte tragen einen Pfeil hinter dem Text.
  ["Status ansehen", "View status"],
  ["Details ansehen", "View details"],
  ["Sicherheits-Check ansehen", "View the security check"],
  ["Sicherheits-Check öffnen", "Open the security check"],
  ["Sicherheits-Check vervollständigen", "Complete the security check"],
  ["Internetverbindung prüfen", "Check the internet connection"],
  ["Internet prüfen", "Check the internet connection"],
  ["Jetzt prüfen", "Check now"],

  // Zustandszeilen und Regelzusammenfassungen tragen Symbole oder Werte vor dem Text.
  ["alle Quelladressen", "all source addresses"],
  ["alle Zieladressen", "all destination addresses"],
  ["Verbunden", "Connected"],
  ["Nicht verbunden", "Not connected"],
];
