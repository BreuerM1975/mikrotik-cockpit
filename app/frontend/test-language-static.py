"""Statische Sprachpruefung: nimmt jeden deutschen Text, den das Backend senden kann, und prueft,
ob die Sprachschicht ihn abdeckt. Braucht weder Chrome noch Router.

    python3 app/frontend/test-language-static.py

Warum zusaetzlich zu test-language.py: Der Browsertest sieht nur, was die Mock-Daten liefern.
Meldungen wie "Noch aktiv: ftp, telnet." entstehen erst an echter Hardware und blieben deshalb
ungeprueft, bis sie live auffielen. Diese Pruefung liest stattdessen den Quelltext.
"""

import ast, json, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent
BACKEND = ROOT.parent / "backend" / "src"

# Platzhalter aus f-Strings werden zu einem Marker, den die Musterpruefung unten fuellt.
PLACEHOLDER = re.compile(r"\{[^}]*\}")

# Schluessel, unter denen ein Text in der JSON-Antwort beim Nutzer landet.
TEXT_SCHLUESSEL = ("message", "plain", "detail", "label")

# Erstes Element eines (code, text)-Tupels: ein Fehlercode wie "bad_request".
FEHLERCODE = re.compile(r"^[a-z][a-z0-9_]*$")


def _literal(node) -> str | None:
    """Der Text eines String-Literals, auch ueber mehrere Zeilen und als f-String.

    Implizite Verkettung ("a" "b") loest Python schon beim Parsen auf, ein f-String wird
    zu ast.JoinedStr -- dessen Ausdruecke werden zu "{X}", damit die Musterpruefung unten
    dieselben Platzhalter sieht wie bei einem echten f-String im Quelltext.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return "".join(
            teil.value if isinstance(teil, ast.Constant) and isinstance(teil.value, str) else "{X}"
            for teil in node.values
        )
    return None


def backend_texts():
    """Alle Texte, die beim Nutzer landen koennen.

    Zwei Wege, und der zweite kam erst am 2026-10-20 dazu: bis dahin suchte diese Funktion per
    Regex nur nach `"message": "..."`. Damit war sie blind fuer jeden Text, den eine Route als
    `(code, text)`-Tupel zurueckgibt -- dreizehn Stellen allein in `routes_pro.py`. Drei
    Meldungen vom 19.10. standen deshalb ohne englische Fassung im Code, ohne dass diese
    Pruefung etwas gemeldet haette. Beide Wege laufen jetzt ueber den Syntaxbaum statt ueber
    einen Regex, der an einer mehrzeiligen Verkettung abreisst.
    """
    found = set()
    for name in ("routes_basis.py", "routes_pro.py", "core.py"):
        path = BACKEND / name
        if not path.exists():
            continue
        baum = ast.parse(path.read_text(encoding="utf-8"))
        for knoten in ast.walk(baum):
            # Weg 1: {"message": "..."} und die drei verwandten Schluessel.
            if isinstance(knoten, ast.Dict):
                for schluessel, wert in zip(knoten.keys, knoten.values):
                    if isinstance(schluessel, ast.Constant) and schluessel.value in TEXT_SCHLUESSEL:
                        text = (_literal(wert) or "").strip()
                        if text:
                            found.add(text)
            # Weg 2: return None, ("bad_request", "...") -- der Aufrufer setzt daraus die
            # Antwort zusammen, der Text landet genauso beim Nutzer.
            if isinstance(knoten, ast.Tuple) and len(knoten.elts) == 2:
                code, wert = (_literal(teil) for teil in knoten.elts)
                if not code or not wert or not FEHLERCODE.match(code):
                    continue
                text = wert.strip()
                # Ein Tupel aus Name und RouterOS-Befehl sieht genauso aus, ist aber kein
                # Nutzertext (core.py:426, Treiberwahl). Befehle beginnen mit "/".
                if text.startswith("/") or " " not in text:
                    continue
                found.add(text)
    return found


def _baustein_literale(wert):
    if isinstance(wert, ast.Subscript):
        return _baustein_literale(wert.value)
    if isinstance(wert, ast.Dict):
        return [text for teil in wert.values for text in _baustein_literale(teil)]
    text = (_literal(wert) or "").strip()
    return [text] if text else []


def bausteine():
    """Weg 3, seit 2026-11-05: Texte, die erst zusammengesetzt beim Nutzer landen.

    Der Gastnetz-Check baut sein "detail" aus Saetzen mit " ".join(detail_parts). Jede Kombination
    ist ein anderer Gesamttext, ein Woerterbuchtreffer greift deshalb nicht. Jeder Satz muss als
    Teilersetzung stehen. Die anderen beiden Wege sahen diese Saetze gar nicht.
    Rueckgabe: (Saetze, die zusammengesetzt werden; Texte, die einzeln ausgegeben werden).
    """
    teile, einzeln = set(), set()
    for name in ("routes_basis.py", "routes_pro.py", "core.py"):
        path = BACKEND / name
        if not path.exists():
            continue
        for knoten in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Attribute) and knoten.func.attr == "append" \
                    and isinstance(knoten.func.value, ast.Name) and knoten.func.value.id == "detail_parts" and knoten.args:
                teile.update(_baustein_literale(knoten.args[0]))
            if isinstance(knoten, ast.Assign) and len(knoten.targets) == 1 and isinstance(knoten.targets[0], ast.Name):
                if knoten.targets[0].id == "texte":
                    teile.update(_baustein_literale(knoten.value))
                elif knoten.targets[0].id == "plain":
                    einzeln.update(_baustein_literale(knoten.value))
            # return False, "Ein Satz." -- der Aufrufer setzt ihn hinter "IPv4: " in detail_parts.
            if isinstance(knoten, ast.Return) and isinstance(knoten.value, ast.Tuple) and len(knoten.value.elts) == 2:
                ergebnis, satz = knoten.value.elts
                if isinstance(ergebnis, ast.Constant) and (ergebnis.value is None or isinstance(ergebnis.value, bool)):
                    text = (_literal(satz) or "").strip()
                    if " " in text:
                        teile.add(text)
    # Ein f-String wie "IPv6: {detail}" ist kein Satz, seine Saetze stehen oben einzeln in der Menge.
    return {t for t in teile if "{X}" not in t}, einzeln


def load_language_files():
    """dict-en.js, patterns-en.js und substitutions-en.js ueber node auslesen."""
    script = f"""
      global.window = {{}};
      require({json.dumps(str(ROOT / 'dict-en.js'))});
      require({json.dumps(str(ROOT / 'patterns-en.js'))});
      require({json.dumps(str(ROOT / 'substitutions-en.js'))});
      console.log(JSON.stringify({{
        dict: Object.keys(window.COCKPIT_DICT_EN || {{}}),
        patterns: (window.COCKPIT_PATTERNS_EN || []).map(p => p[0].source),
        subs: (window.COCKPIT_SUBSTITUTIONS_EN || []).map(s => s[0]),
      }}));
    """
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def covered(text, data):
    if text in data["dict"]:
        return True
    if any(sub in text for sub in data["subs"]):
        return True
    # f-String-Platzhalter durch Beispielwerte ersetzen und gegen die Muster halten. Zwei Proben,
    # weil manche Muster eine Zahl erwarten (\d+) und andere beliebigen Text.
    probes = [PLACEHOLDER.sub("X", text), PLACEHOLDER.sub("42", text)]
    for source in data["patterns"]:
        for probe in probes:
            try:
                if re.search(source, probe):
                    return True
            except re.error:
                continue
    return False


def main():
    data = load_language_files()
    teile, einzeln = bausteine()
    gesamt = backend_texts()
    texts = gesamt | teile | einzeln
    missing = sorted(
        {t for t in gesamt - teile - einzeln if not covered(t, data)}
        | {t for t in einzeln - teile if t not in data["dict"] and t not in data["subs"]}
        | {t for t in teile if t not in data["subs"]}
    )
    print(f"Backend-Texte geprüft: {len(texts)} · abgedeckt: {len(texts) - len(missing)}")
    if missing:
        print(f"\n{len(missing)} Text(e) ohne Übersetzung:\n")
        for text in missing:
            print("  " + text[:150])
        return 1
    print("Jeder Backend-Text ist von Wörterbuch, Muster oder Teilersetzung abgedeckt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
