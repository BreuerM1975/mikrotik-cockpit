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
