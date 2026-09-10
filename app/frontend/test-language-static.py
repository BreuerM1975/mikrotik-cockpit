"""Statische Sprachpruefung: nimmt jeden deutschen Text, den das Backend senden kann, und prueft,
ob die Sprachschicht ihn abdeckt. Braucht weder Chrome noch Router.

    python3 app/frontend/test-language-static.py

Warum zusaetzlich zu test-language.py: Der Browsertest sieht nur, was die Mock-Daten liefern.
Meldungen wie "Noch aktiv: ftp, telnet." entstehen erst an echter Hardware und blieben deshalb
ungeprueft, bis sie live auffielen. Diese Pruefung liest stattdessen den Quelltext.
"""

import json, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent
BACKEND = ROOT.parent / "backend" / "src"

# Platzhalter aus f-Strings werden zu einem Marker, den die Musterpruefung unten fuellt.
PLACEHOLDER = re.compile(r"\{[^}]*\}")


def backend_texts():
    """Alle Texte, die als message/plain/detail/label beim Nutzer landen koennen."""
    found = set()
    for name in ("routes_basis.py", "routes_pro.py", "core.py"):
        path = BACKEND / name
        if not path.exists():
            continue
        source = path.read_text(encoding="utf-8")
        # Einfache und ueber mehrere Zeilen zusammengesetzte Literale
        for match in re.finditer(r'"(?:message|plain|detail|label)":\s*((?:f?"[^"]*"\s*)+)', source):
            parts = re.findall(r'f?"([^"]*)"', match.group(1))
            text = "".join(parts).strip()
            if text:
                found.add(text)
    return found


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
    texts = backend_texts()
    missing = sorted(t for t in texts if not covered(t, data))
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
