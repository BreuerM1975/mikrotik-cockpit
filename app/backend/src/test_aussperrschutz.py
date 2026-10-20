"""Tests gegen die drei Wege, auf denen sich ein Kunde endgueltig aussperren kann.

Angelegt am 2026-10-19 nach einer Lueckenanalyse der damals 413 Tests. Der Befund war
nicht, dass diese Pfade falsch programmiert sind, sondern dass sie **unbeobachtet**
laufen: eine Aenderung an ihnen laesst die gesamte Suite gruen.

Zwei Tests hier standen zuerst als `unittest.expectedFailure`: sie beschrieben das
gewuenschte Verhalten, das der Code noch nicht hatte, und haben sich von allein gemeldet,
als die Luecke am 2026-10-20 geschlossen wurde. Seitdem laufen sie normal mit. Der Weg hat
sich bewaehrt -- die offene Stelle steht im Code und nicht in einer Notizdatei, die niemand
oeffnet.

Kein Test hier fasst einen Router an. Alle Routerantworten sind Attrappen.
"""

import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import app as app_module
import core as core_module
from test_app import zaehlende_sperre

try:
    import routes_pro as routes_pro_module
    HAS_PRO = True
except ImportError:
    routes_pro_module = None
    HAS_PRO = False


# Dienstezeilen, wie `/ip service print terse` sie liefert. RouterOS schreibt "disabled"
# nicht als Feld, sondern als Flag-Buchstaben "X" vor dem ersten key=value -- parse_terse()
# wertet genau das aus.
DIENST_SSH = '2  name=ssh port=22 proto=tcp\n'
DIENST_SSH_AUS = '2 X name=ssh port=22 proto=tcp\n'
DIENST_TELNET = '0  name=telnet port=23 proto=tcp\n'
DIENST_TELNET_AUS = '0 X name=telnet port=23 proto=tcp\n'


# Verteilende Attrappen statt Listen fester Laenge (2026-10-20).
#
# Vorher stand in jedem Test `mock_router.side_effect = [antwort1, antwort2, antwort3]`. Das
# bindet den Test an die genaue ANZAHL der Routerzugriffe: wer dem Pfad einen harmlosen
# zusaetzlichen Lesebefehl hinzufuegt, bekommt StopIteration und einen roten Test, der nichts
# ueber die geprueft Sache sagt. Die Attrappen unten schauen stattdessen auf den Befehl und
# ueberleben jede Reihenfolge und jede Anzahl. Gleiches Muster wie
# test_app_pro.py:test_firewall_enabled_toggle_success.
#
# Ein Befehl, den sie nicht kennen, bekommt eine leere Antwort -- derselbe Kompromiss wie im
# Vorbild. Das ist bewusst: diese Tests pruefen einen engen Pfad, und eine leere Antwort ist
# das, was die alte Liste an derselben Stelle auch geliefert haette.


def _dienst_fake(vorher: str, nachher: str | None = None):
    """`/ip service print` liefert `vorher`, nach einem disable/enable dann `nachher`.

    Ohne `nachher` bleibt es bei `vorher` -- das ist der Fall "der Befehl lief, hat aber
    nichts bewirkt", den RouterOS auch mit Exitcode 0 liefert.
    """
    zustand = {"geschaltet": False}

    def router(command):
        if command.startswith("/ip service print"):
            return nachher if zustand["geschaltet"] and nachher is not None else vorher
        if command.startswith(("/ip service disable", "/ip service enable")):
            zustand["geschaltet"] = True
            return ""
        return ""

    return router


def _firewall_fake(vorher: str, nachher: str | None = None):
    """`print as-value` liefert `vorher`, nach einem `add` dann `nachher`."""
    zustand = {"angelegt": False}

    def router(command):
        if "print as-value" in command:
            return nachher if zustand["angelegt"] and nachher is not None else vorher
        if " add " in command:
            zustand["angelegt"] = True
            return ""
        return ""

    return router


class _MitSitzung(unittest.TestCase):
    def setUp(self):
        app_module.app.testing = True
        self.client = app_module.app.test_client()
        self.session_id = "aussperrschutz-test"
        core_module.SESSIONS[self.session_id] = {
            "host": "test-host", "user": "admin", "password": "test-pass", "ssh_port": 22,
        }
        self.headers = {"X-Cockpit-Session": self.session_id}

    def tearDown(self):
        core_module.SESSIONS.pop(self.session_id, None)


@unittest.skipUnless(HAS_PRO, "routes_pro.py nicht vorhanden (Basis-Checkout)")
class DiensteAussperrungTests(_MitSitzung):
    """Weg 1: Cockpit schaltet den SSH-Dienst ab, ueber den es selbst spricht.

    Der Endpunkt PUT /api/v1/services/<name>/enabled prueft heute nur Namensgueltigkeit,
    Wahrheitswert und Existenz (routes_pro.py:1289). Der einzige Schutz gegen das
    Abschalten des eigenen Zugangswegs steht im Frontend (pro.js, `confirmAction`) --
    und genau diese Bedingung war am 08.09. schon einmal invertiert (Projektnotizen).
    """

    @patch("core.router")
    def test_eigener_zugangsweg_braucht_eine_ausdrueckliche_bestaetigung(self, mock_router):
        """Behoben am 2026-10-19: ohne 'confirm' wird das Abschalten mit 409 abgelehnt.

        Beim Kunden hiesse es sonst WinBox ueber MAC, seriell oder Reset-Knopf.
        """
        mock_router.side_effect = _dienst_fake(DIENST_SSH)

        antwort = self.client.put(
            "/api/v1/services/ssh/enabled", json={"enabled": False}, headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 409)
        self.assertEqual(antwort.get_json()["error"], "confirmation_required")
        self.assertNotIn(
            "/ip service disable",
            " ".join(aufruf.args[0] for aufruf in mock_router.call_args_list),
            "Der Abschaltbefehl darf nicht einmal abgesetzt werden",
        )

    @patch("core.router")
    def test_mit_bestaetigung_laesst_sich_ssh_abschalten(self, mock_router):
        """Verboten ist es nicht. Wer einen zweiten Zugang eingerichtet hat, muss den
        Klartext- oder Fernzugang abschalten koennen."""
        mock_router.side_effect = _dienst_fake(DIENST_SSH, DIENST_SSH_AUS)

        antwort = self.client.put(
            "/api/v1/services/ssh/enabled",
            json={"enabled": False, "confirm": True},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 200)
        mock_router.assert_any_call('/ip service disable [find where name="ssh" and dynamic=no]')

    @patch("core.router")
    def test_fremde_dienste_bleiben_ohne_huerde_abschaltbar(self, mock_router):
        """Die Huerde fuer ssh darf telnet nicht mitsperren. Telnet abzuschalten ist der
        Normalfall und soll in einem Schritt gehen."""
        mock_router.side_effect = _dienst_fake(DIENST_TELNET, DIENST_TELNET_AUS)

        antwort = self.client.put(
            "/api/v1/services/telnet/enabled", json={"enabled": False}, headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 200)
        mock_router.assert_any_call('/ip service disable [find where name="telnet" and dynamic=no]')

    @patch("core.router")
    def test_ssh_einschalten_bleibt_erlaubt(self, mock_router):
        """Nur das Abschalten ist gefaehrlich. Einschalten muss ohne Huerde gehen."""
        mock_router.side_effect = _dienst_fake(DIENST_SSH_AUS, DIENST_SSH)

        antwort = self.client.put(
            "/api/v1/services/ssh/enabled", json={"enabled": True}, headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 200)

    @patch("core.router")
    def test_wirkungsloser_befehl_wird_nicht_als_erfolg_gemeldet(self, mock_router):
        """RouterOS lehnt inhaltlich auch mit Exitcode 0 ab. Ohne Nachpruefung meldete
        Cockpit "telnet ist aus", waehrend der Klartextdienst weiterlief, und der Kunde
        hielt einen offenen Dienst fuer geschlossen."""
        mock_router.side_effect = _dienst_fake(DIENST_TELNET)

        antwort = self.client.put(
            "/api/v1/services/telnet/enabled", json={"enabled": False}, headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 502)
        self.assertEqual(antwort.get_json()["error"], "router_state_mismatch")


@unittest.skipUnless(HAS_PRO, "routes_pro.py nicht vorhanden (Basis-Checkout)")
class FirewallEinfuegepositionTests(_MitSitzung):
    """Weg 2: Eine neue Sperrregel landet vor der Regel, die die eigene Sitzung traegt.

    `_fw_create_and_locate()` setzt pauschal `place-before=<letzte ID der Kette>`
    (routes_pro.py:1083). Das ist richtig, solange die Kette auf eine Catch-all-Drop-Regel
    endet. Endet sie auf ein `accept`, wird die neue Drop-Regel davor einsortiert.

    Fuer genau dieses Problem gibt es im selben Modul schon die Loesung:
    `_wg_place_before_id()` (routes_pro.py:639) sucht die erste aktive, uneingeschraenkte
    Drop-Regel. Der allgemeine Firewallpfad benutzt sie nicht.
    """

    @patch("core.router")
    @patch("uuid.uuid4", return_value=uuid.UUID("dddd4444-0000-0000-0000-000000000000"))
    def test_neue_sperre_landet_nicht_vor_der_tragenden_accept_regel(self, _uuid, mock_router):
        """Behoben am 2026-10-19. Kette im Aufbau: nur Accept-Regeln, keine Catch-all-Sperre.

        Eine neue Sperre gehoert dann ans Ende. Vorher setzte der Rueckfall sie vor die
        letzte Regel der Kette, also vor "accept established" -- und riss die laufende
        SSH-Sitzung im selben Moment ab.
        """
        kette = (
            '.id=*A;chain=input;action=accept;protocol=icmp;comment=defconf: accept icmp;disabled=false;'
            '.id=*B;chain=input;action=accept;connection-state=established,related;'
            'comment=defconf: accept established,related;disabled=false'
        )
        mock_router.side_effect = _firewall_fake(
            kette,
            kette + ';.id=*9;chain=input;action=drop;protocol=udp;'
                    'comment=cockpit-fw:dddd4444: Test;disabled=false',
        )

        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "protocol": "udp", "comment": "Test"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 201)
        gesendet = [a.args[0] for a in mock_router.call_args_list if " add " in a.args[0]]
        self.assertEqual(len(gesendet), 1)
        self.assertNotIn(
            "place-before=", gesendet[0],
            "Die Sperre wurde vor die Regel gesetzt, die die eigene Sitzung traegt",
        )

    @patch("core.router")
    @patch("uuid.uuid4", return_value=uuid.UUID("ffff6666-0000-0000-0000-000000000000"))
    def test_neue_sperre_bleibt_vor_einer_catch_all_sperre(self, _uuid, mock_router):
        """Gegenprobe: endet die Kette auf eine echte Catch-all-Sperre, muss die neue Sperre
        davor stehen, sonst ist sie wirkungslos -- dort ist ohnehin schon alles verworfen."""
        kette = (
            '.id=*A;chain=input;action=accept;connection-state=established,related;disabled=false;'
            '.id=*B;chain=input;action=drop;comment=defconf: drop all;disabled=false'
        )
        mock_router.side_effect = _firewall_fake(
            kette,
            kette + ';.id=*9;chain=input;action=drop;protocol=udp;'
                    'comment=cockpit-fw:ffff6666: Test;disabled=false',
        )

        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "protocol": "udp", "comment": "Test"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 201)
        gesendet = [a.args[0] for a in mock_router.call_args_list if " add " in a.args[0]]
        self.assertIn("place-before=*B", gesendet[0])

    @patch("core.router")
    @patch("uuid.uuid4", return_value=uuid.UUID("eeee5555-0000-0000-0000-000000000000"))
    def test_freigabe_bleibt_vor_der_abschliessenden_sperre(self, _uuid, mock_router):
        """Der Normalfall nach defconf, und er muss so bleiben: eine Freigabe gehoert vor die
        Sperre, sonst wirkt sie nie."""
        kette = (
            '.id=*A;chain=input;action=accept;connection-state=established,related;disabled=false;'
            '.id=*B;chain=input;action=drop;in-interface-list=!LAN;'
            'comment=defconf: drop all not coming from LAN;disabled=false'
        )
        mock_router.side_effect = _firewall_fake(
            kette,
            '.id=*A;chain=input;action=accept;connection-state=established,related;disabled=false;'
            '.id=*7;chain=input;action=accept;protocol=tcp;dst-port=8291;'
            'comment=cockpit-fw:eeee5555: WinBox;disabled=false;'
            '.id=*B;chain=input;action=drop;in-interface-list=!LAN;'
            'comment=defconf: drop all not coming from LAN;disabled=false',
        )

        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "accept", "protocol": "tcp", "dst_port": "8291", "comment": "WinBox"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 201)
        gesendet = [a.args[0] for a in mock_router.call_args_list if " add " in a.args[0]]
        self.assertIn("place-before=*B", gesendet[0])

    @patch("core.router")
    def test_invalid_regel_gilt_nicht_als_catch_all(self, mock_router):
        """Die defconf-Regel "drop invalid" ist keine uneingeschraenkte Sperre. Wurde sie als
        solche gelesen, landete jede neue Freigabe ganz oben in der Kette, vor der
        Invalid-Sperre. Betraf bis zum 2026-10-19 den WireGuard-Pfad."""
        kette = (
            '.id=*A;chain=forward;action=drop;connection-state=invalid;'
            'comment=defconf: drop invalid;disabled=false;'
            '.id=*B;chain=forward;action=drop;comment=defconf: drop all from WAN;disabled=false'
        )
        mock_router.side_effect = _firewall_fake(kette)

        self.assertEqual(
            routes_pro_module._wg_place_before_id("/ip firewall filter", "forward"), "*B",
        )

    # Kette nach MikroTiks eigenem Filter-Beispiel: eine Sperrliste steht vor dem
    # abschliessenden Catch-all. Genau daran ist die Positivliste vom 2026-10-19
    # gescheitert -- "src-address-list" stand nicht darin, also galt *3 als Catch-all.
    KETTE_MIT_SPERRLISTE = (
        '.id=*1;chain=input;action=accept;connection-state=established,related;'
        'dynamic=false;invalid=false;'
        '.id=*2;chain=input;action=drop;connection-state=invalid;dynamic=false;invalid=false;'
        '.id=*3;chain=input;action=drop;src-address-list=gesperrt;dynamic=false;invalid=false;'
        '.id=*4;chain=input;action=accept;src-address-list=erlaubt;dynamic=false;invalid=false;'
        '.id=*5;chain=input;action=accept;protocol=icmp;dynamic=false;invalid=false;'
        '{letzte}'
    )

    @patch("core.router")
    def test_sperrliste_des_kunden_gilt_nicht_als_catch_all(self, mock_router):
        """Behoben am 2026-10-20. Eine Freigabe darf nicht vor die Sperrliste des Kunden.

        Landet sie dort, erreicht eine gesperrte Quelle den neu geoeffneten Port -- die
        Sperrliste ist ausgesetzt, ohne dass sich an ihr etwas geaendert haette. Der Fehler
        stammt aus der Positivliste der Matcher, in der "src-address-list" fehlte, und traf
        seit dem 2026-10-19 jede ueber die Firewall-Flaeche angelegte Regel.
        """
        mock_router.side_effect = _firewall_fake(self.KETTE_MIT_SPERRLISTE.format(
            letzte='.id=*6;chain=input;action=drop;comment=drop all;dynamic=false;invalid=false',
        ))

        self.assertEqual(
            routes_pro_module._wg_place_before_id("/ip firewall filter", "input"), "*6",
        )

    @patch("core.router")
    def test_ohne_echten_catch_all_faellt_die_freigabe_auf_die_letzte_regel(self, mock_router):
        """Gegenprobe mit der defconf-Sperre als Kettenende. "in-interface-list=!LAN" ist eine
        Einschraenkung, also gibt es keinen uneingeschraenkten Catch-all -- der Rueckfall vor
        die letzte Regel ist dann die richtige Position fuer eine Freigabe."""
        mock_router.side_effect = _firewall_fake(self.KETTE_MIT_SPERRLISTE.format(
            letzte='.id=*6;chain=input;action=drop;in-interface-list=!LAN;'
                   'comment=defconf: drop all not coming from LAN;dynamic=false;invalid=false',
        ))

        self.assertEqual(
            routes_pro_module._wg_place_before_id("/ip firewall filter", "input"), "*6",
        )

    @patch("core.router")
    def test_as_value_nebenfelder_machen_aus_einem_catch_all_keine_sperrregel(self, mock_router):
        """Die Kehrseite der Negativliste, und der Grund fuer _FW_AS_VALUE_METADATEN.

        Am Test-hAP gemessen (2026-10-20): "print as-value" haengt an JEDE Regel
        "dynamic=false;invalid=false" an, "print terse" nicht. Zaehlen diese Felder als
        Einschraenkung, gilt keine Regel mehr als Catch-all und jede Freigabe landet am
        Kettenende, wo sie nichts mehr bewirkt. Dieser Test faellt, sobald jemand die
        Nebenfelder aus der Liste nimmt.
        """
        mock_router.side_effect = _firewall_fake(
            '.id=*A;chain=input;action=accept;connection-state=established,related;'
            'dynamic=false;invalid=false;'
            '.id=*B;chain=input;action=drop;comment=drop all;disabled=false;'
            'dynamic=false;invalid=false'
        )

        self.assertEqual(
            routes_pro_module._wg_place_before_id("/ip firewall filter", "input"), "*B",
        )


class PortweiterleitungPositionTests(_MitSitzung):
    """Weg 3 ist kein Aussperren, sondern eine stille Fehlfunktion.

    `_port_forwards_create()` setzt die Filter-Regel mit
    `place-before=<letzte ID>` (routes_basis.py:830). Keiner der 413 Tests prueft das:
    `grep -c "place-before" test_app.py` ergibt 0. Faellt die Zeile weg, meldet Cockpit
    eine eingerichtete Portweiterleitung, die hinter defconfs Drop-Regel haengt und nie
    funktioniert. Der Kunde sucht den Fehler bei seiner Kamera.
    """

    @patch("core.router")
    def test_filterregel_wird_vor_die_letzte_regel_gesetzt(self, mock_router):
        def antworten(befehl):
            if befehl == '/interface print terse where name="ether1"':
                return "0 name=ether1 running=true\n"
            if befehl.startswith("/ip firewall nat print terse"):
                return ""
            if befehl.startswith(":foreach"):
                return "*A\n*SPERRE\n"
            return ""

        mock_router.side_effect = antworten

        antwort = self.client.post(
            "/api/v1/port-forwards",
            json={"name": "Kamera", "protocol": "tcp", "external_port": 8554,
                  "internal_ip": "192.168.178.70", "internal_port": 554},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 201)
        filterbefehle = [a.args[0] for a in mock_router.call_args_list
                         if a.args[0].startswith("/ip firewall filter add")]
        self.assertEqual(len(filterbefehle), 1)
        self.assertIn(
            "place-before=*SPERRE", filterbefehle[0],
            "Ohne place-before haengt die Freigabe hinter der Drop-Regel und wirkt nie",
        )


@unittest.skipUnless(HAS_PRO, "routes_pro.py nicht vorhanden (Basis-Checkout)")
class TierMeldungTests(_MitSitzung):
    """Die Tier-Meldung muss gegen einen festen Wert geprueft werden.

    `test_app.py:655` und `:671` vergleichen die Antwort mit
    `app.config["COCKPIT_TIER"]`, also mit der Quelle der Antwort selbst. Diese
    Zusicherung kann nicht fehlschlagen. Hier steht der feste Wert.
    """

    @patch("core.router")
    def test_mit_geladenem_pro_modul_meldet_capabilities_pro(self, mock_router):
        mock_router.return_value = ""

        antwort = self.client.get("/api/v1/capabilities", headers=self.headers)

        self.assertEqual(antwort.status_code, 200)
        self.assertEqual(antwort.get_json()["tier"], "pro")



@unittest.skipUnless(HAS_PRO, "routes_pro.py nicht vorhanden (Basis-Checkout)")
class UneingeschraenkteSperreTests(_MitSitzung):
    """Eine Sperre ohne jede Einschraenkung in der input-Kette schliesst den Router zu.

    Laut dem API-Vertrag ist nur "action" Pflicht. {"action": "drop"} war damit ein
    vollstaendiger Request, der jede neue Verbindung zum Router verwirft, auch die der
    eigenen Verwaltung. Bestehende Sitzungen leben weiter, solange eine Accept-Regel fuer
    established davor steht -- der Kunde merkt es erst beim naechsten Anmelden.
    """

    @patch("core.router")
    def test_sperre_ohne_einschraenkung_braucht_eine_bestaetigung(self, mock_router):
        antwort = self.client.post(
            "/api/v1/firewall/input", json={"action": "drop"}, headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 409)
        self.assertEqual(antwort.get_json()["error"], "confirmation_required")
        mock_router.assert_not_called()

    @patch("core.router")
    @patch("uuid.uuid4", return_value=uuid.UUID("aaaa0001-0000-0000-0000-000000000000"))
    def test_mit_bestaetigung_geht_die_sperre_durch(self, _uuid, mock_router):
        """Verboten ist es nicht. Wer seinen Router bewusst zumacht, darf das."""
        kette = '.id=*A;chain=input;action=accept;connection-state=established,related;disabled=false'
        mock_router.side_effect = _firewall_fake(
            kette,
            kette + ';.id=*9;chain=input;action=drop;'
                    'comment=cockpit-fw:aaaa0001: Zu;disabled=false',
        )

        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "comment": "Zu", "confirm": True},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 201)

    @patch("core.router")
    @patch("uuid.uuid4", return_value=uuid.UUID("aaaa0002-0000-0000-0000-000000000000"))
    def test_sperre_mit_einschraenkung_braucht_keine_bestaetigung(self, _uuid, mock_router):
        """Gegenprobe: eine Sperre fuer einen einzelnen Port ist der Normalfall und soll
        ohne zusaetzlichen Schritt durchgehen."""
        kette = '.id=*A;chain=input;action=accept;connection-state=established,related;disabled=false'
        mock_router.side_effect = _firewall_fake(
            kette,
            kette + ';.id=*9;chain=input;action=drop;protocol=tcp;dst-port=23;'
                    'comment=cockpit-fw:aaaa0002: Telnet zu;disabled=false',
        )

        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "protocol": "tcp", "dst_port": "23", "comment": "Telnet zu"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 201)

    @patch("core.router")
    def test_in_der_forward_kette_gilt_die_huerde_nicht(self, mock_router):
        """Die forward-Kette traegt nicht die eigene Verwaltungsverbindung. Dort ist eine
        pauschale Sperre eine normale Entscheidung."""
        kette = '.id=*A;chain=forward;action=accept;connection-state=established,related;disabled=false'
        mock_router.side_effect = _firewall_fake(
            kette,
            kette + ';.id=*9;chain=forward;action=drop;comment=cockpit-fw:bbbb0001: Zu;disabled=false',
        )
        with patch("uuid.uuid4", return_value=uuid.UUID("bbbb0001-0000-0000-0000-000000000000")):
            antwort = self.client.post(
                "/api/v1/firewall/forward", json={"action": "drop", "comment": "Zu"},
                headers=self.headers,
            )

        self.assertEqual(antwort.status_code, 201)

    @patch("core.router")
    def test_interface_bridge_schuetzt_nicht_vor_der_huerde(self, mock_router):
        """Behoben am 2026-10-20, und das war der erzeugbare Fall.

        Die alte Huerde zaehlte jedes gesetzte Feld als Einschraenkung. "Verwerfen" plus
        Interface "bridge" -- genau was der Platzhalter der Eingabemaske vorschlaegt
        (index.html:68, "z. B. bridge") -- ging damit ohne Rueckfrage durch und verwirft
        jeden neuen Zugriff aus dem LAN. Ein Interface ist keine Entschaerfung, denn der
        Router wird ueber die Bridge verwaltet.
        """
        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "in_interface": "bridge"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 409)
        self.assertEqual(antwort.get_json()["error"], "confirmation_required")
        mock_router.assert_not_called()

    @patch("core.router")
    def test_quelladresse_schuetzt_nicht_vor_der_huerde(self, mock_router):
        """Dasselbe fuer eine Quelladresse. "0.0.0.0/0" ist die ganze Welt, inklusive des
        Rechners, auf dem Cockpit laeuft."""
        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "src_address": "0.0.0.0/0"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 409)
        mock_router.assert_not_called()

    @patch("core.router")
    def test_protokoll_tcp_allein_schuetzt_nicht_vor_der_huerde(self, mock_router):
        """SSH, WinBox und WebFig sind alle TCP. "protocol=tcp" ohne Port trifft sie alle."""
        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "protocol": "tcp"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 409)
        mock_router.assert_not_called()

    @patch("core.router")
    @patch("uuid.uuid4", return_value=uuid.UUID("aaaa0003-0000-0000-0000-000000000000"))
    def test_icmp_sperre_geht_weiter_ohne_bestaetigung(self, _uuid, mock_router):
        """Gegenprobe Protokoll: icmp traegt keinen Verwaltungszugang. Eine solche Sperre
        ist die haeufigste harmlose Regel ueberhaupt und darf keinen Dialog ausloesen."""
        kette = '.id=*A;chain=input;action=accept;connection-state=established,related;disabled=false'
        mock_router.side_effect = _firewall_fake(
            kette,
            kette + ';.id=*9;chain=input;action=drop;protocol=icmp;'
                    'comment=cockpit-fw:aaaa0003: Ping zu;disabled=false',
        )

        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "protocol": "icmp", "comment": "Ping zu"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 201)

    @patch("core.router")
    def test_ein_portbereich_ueber_den_winbox_port_loest_die_huerde_aus(self, mock_router):
        """Die Huerde haengt am Port, nicht an der Anzahl der Felder: ein Bereich, der 8291
        einschliesst, sperrt WinBox aus -- auch wenn er sonst eng aussieht."""
        antwort = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "protocol": "tcp", "dst_port": "8200-8300"},
            headers=self.headers,
        )

        self.assertEqual(antwort.status_code, 409)
        mock_router.assert_not_called()

    @patch("core.router")
    @patch("uuid.uuid4", return_value=uuid.UUID("aaaa0004-0000-0000-0000-000000000000"))
    def test_abweichender_ssh_port_der_sitzung_wird_mitgeprueft(self, _uuid, mock_router):
        """Der SSH-Port kommt aus der Sitzung, nicht aus einer festen Liste. Laeuft SSH auf
        2222, muss eine Sperre fuer 2222 die Huerde ausloesen -- und eine fuer 22 nicht
        mehr, weil dort nichts mehr horcht."""
        core_module.SESSIONS[self.session_id]["ssh_port"] = 2222

        gesperrt = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "protocol": "tcp", "dst_port": "2222"},
            headers=self.headers,
        )
        self.assertEqual(gesperrt.status_code, 409)
        mock_router.assert_not_called()

        kette = '.id=*A;chain=input;action=accept;connection-state=established,related;disabled=false'
        mock_router.side_effect = _firewall_fake(
            kette,
            kette + ';.id=*9;chain=input;action=drop;protocol=tcp;dst-port=22;'
                    'comment=cockpit-fw:aaaa0004: Alter SSH-Port;disabled=false',
        )
        frei = self.client.post(
            "/api/v1/firewall/input",
            json={"action": "drop", "protocol": "tcp", "dst_port": "22",
                  "comment": "Alter SSH-Port"},
            headers=self.headers,
        )
        self.assertEqual(frei.status_code, 201)


class VerbindungspruefungTests(unittest.TestCase):
    """Der Pruefbefehl beim Verbinden muss sich wirklich anmelden.

    `_control_path()` schliesst das Passwort bewusst aus dem Hash aus (damit ein
    Passwortwechsel eine alte Verbindung nicht weiter nutzbar laesst), und `_ensure_master()`
    kehrt bei lebendem Socket sofort zurueck. Der Pruefbefehl von `/connect` lief dadurch
    ueber die bereits authentifizierte Verbindung: SSHPASS wurde nie benutzt, und ein
    falsches Passwort antwortete 200.
    """

    def _gesendeter_befehl(self, **zusatz):
        import routeros

        mitgeschrieben = {}

        class Ergebnis:
            returncode = 0
            stdout = "name: TestRouter\n"
            stderr = ""

        def beobachtet(befehl, **k):
            mitgeschrieben["befehl"] = list(befehl)
            return Ergebnis()

        with patch.object(routeros.subprocess, "run", beobachtet), \
                patch.object(routeros, "_ensure_master") as master:
            routeros.run_command(
                "192.168.99.230", "admin", "geheim", 22, "/system identity print", **zusatz,
            )
        return mitgeschrieben["befehl"], master

    def test_eigene_verbindung_schaltet_die_socket_mitbenutzung_ab(self):
        befehl, master = self._gesendeter_befehl(eigene_verbindung=True)

        self.assertIn("ControlPath=none", befehl)
        self.assertNotIn("ControlMaster=no", befehl)
        master.assert_not_called()

    def test_normale_befehle_nutzen_den_kontrollsocket_weiter(self):
        """Gegenprobe: die Beschleunigung durch Multiplexing bleibt fuer alle anderen
        Befehle erhalten (am 2026-10-17 am hAP gemessen: zwoelf parallele Abfragen)."""
        befehl, master = self._gesendeter_befehl()

        self.assertNotIn("ControlPath=none", befehl)
        master.assert_called_once()


class HostPruefungTests(unittest.TestCase):
    """Der Host aus /connect landet als Argument in `ssh-keyscan`.

    Ein Wert, der mit "-" beginnt, wird dort als Option gelesen statt als Host. Praktisch
    nur von einem lokalen Prozess erreichbar, aber ohne Pruefung landet auch jeder Tippfehler
    in einem Unterprozess statt in einer klaren Fehlermeldung.
    """

    def setUp(self):
        import routes_basis
        self.pruefen = routes_basis._verbindungs_host

    def test_adressen_und_namen_im_eigenen_netz_sind_erlaubt(self):
        for wert in ("192.168.100.1", "10.0.0.1", "172.16.5.4", "router",
                     "mikrotik.fritz.box", "hap-ac-lite.local", "fe80::1", "2001:db8::1",
                     # 2026-10-20: RouterOS nimmt "mein_router" als Identity, derselbe Name
                     # kommt dann per mDNS oder aus /etc/hosts. Vorher abgelehnt, und damit
                     # war so ein Router ueber seinen Namen nicht erreichbar.
                     "mein_router", "mein_router.fritz.box", "_ssh._tcp.local",
                     # Gemessen am 2026-10-20: lief schon vorher durch, weil
                     # ipaddress.ip_address() den Scope-Id seit Python 3.9 kennt. Das
                     # Gegenlesen vom 19.10. hatte es als abgelehnt gemeldet -- hier
                     # festgehalten, damit die Annahme nicht wieder umkippt.
                     "fe80::1%eth0", "[fe80::1%eth0]"):
            with self.subTest(wert=wert):
                self.assertEqual(self.pruefen(wert), wert)

    def test_optionsaehnliche_und_zusammengesetzte_werte_werden_abgelehnt(self):
        for wert in ("-oProxyCommand=x", "--config=/etc/passwd", "-4",
                     "host;befehl", "host name", "", "a" * 254,
                     "192.168.1.1 -oProxyCommand=x", "host|pipe", "$(befehl)",
                     # Der Unterstrich ist seit dem 2026-10-20 erlaubt, der fuehrende
                     # Bindestrich bleibt verboten -- genau der war der Anlass der Pruefung.
                     "-mein_router", "mein_router -oProxyCommand=x"):
            with self.subTest(wert=wert):
                with self.assertRaises(ValueError):
                    self.pruefen(wert)

    @patch("routes_basis.run_command")
    @patch("routes_basis.ensure_host_key_trusted")
    def test_connect_lehnt_einen_solchen_host_ab(self, _schluessel, mock_run):
        app_module.app.testing = True
        client = app_module.app.test_client()

        antwort = client.post(
            "/api/v1/connect",
            json={"host": "-oProxyCommand=x", "user": "admin", "password": "geheim"},
        )

        self.assertEqual(antwort.status_code, 400)
        mock_run.assert_not_called()


@unittest.skipUnless(HAS_PRO, "routes_pro.py nicht vorhanden (Basis-Checkout)")
class BenutzerNebenlaeufigkeitTests(unittest.TestCase):
    """Weg 3: der letzte Vollzugang verschwindet bei zwei gleichzeitigen Anfragen.

    Alle fuenf /users-Endpunkte halten `core._router_create_lock()`, aber beide
    Nebenlaeufigkeitstests der Suite decken nur fuenf andere Endpunkte ab
    (`test_create_concurrency.py`, `test_app_pro.py::CreateConcurrencyProTests`). Wer das
    `with`-Statement aus `users_enabled` oder `users_delete` entfernt, bekam bisher eine
    gruene Suite -- waehrend zwei Anfragen aus zwei Browser-Tabs beide die Benutzerliste mit
    zwei aktiven Vollzugaengen lesen, beide die Sperrpruefung bestehen und beide schreiben.
    Danach gibt es keinen aktiven Vollzugang mehr und der Kunde kann seinen Router nicht
    mehr verwalten.
    """

    BENUTZER = [
        {"name": "admin", "group": "full", "disabled": False},
        {"name": "zweitadmin", "group": "full", "disabled": False},
    ]

    def setUp(self):
        app_module.app.testing = True

    def tearDown(self):
        core_module.SESSIONS.clear()

    def _serialisierung_pruefen(self, methode: str, pfad: str, daten):
        erster_drin = threading.Event()
        freigabe = threading.Event()
        aufrufe = []
        # 2026-10-20: Vorher stand hier ein `time.sleep(0.15)` und danach die Pruefung, dass
        # die Liste nur einmal gelesen wurde. Das war keine Garantie, sondern eine Wette auf
        # die Maschine: kommt die zweite Anfrage unter Last in 150 ms nicht bis zur Sperre,
        # ist der Test gruen, auch wenn das `with`-Statement fehlt. Diese Semaphore zaehlt
        # jeden VERSUCH, die Sperre zu nehmen. Der Test wartet darauf als Erfolgsbedingung --
        # bleibt sie aus, faellt er. Zwischen dem Zaehlen und dem tatsaechlichen Blockieren
        # kann die zweite Anfrage nicht lesen, denn `list_users` liegt hinter der Sperre.
        sperrversuche = threading.Semaphore(0)

        def liste():
            aufrufe.append(1)
            if len(aufrufe) == 1:
                erster_drin.set()
                if not freigabe.wait(3):
                    raise RuntimeError("Freigabe im Test blieb aus")
            return [dict(b) for b in self.BENUTZER]

        def anfrage(sitzung):
            with app_module.app.test_client() as client:
                return client.open(
                    pfad, method=methode, json=daten,
                    headers={"X-Cockpit-Session": sitzung},
                ).status_code

        sitzungen = {
            name: {"host": "serialisierung.invalid", "user": "admin",
                   "password": "x", "ssh_port": 22}
            for name in ("nebenlaeufig-a", "nebenlaeufig-b")
        }

        with patch.dict(core_module.SESSIONS, sitzungen), \
                patch.object(core_module, "list_users", side_effect=liste), \
                patch.object(core_module, "router", return_value=""), \
                patch.object(core_module, "_router_create_lock",
                             side_effect=zaehlende_sperre(sperrversuche)), \
                patch.object(routes_pro_module, "_user_lockout_error", return_value=None):
            with ThreadPoolExecutor(max_workers=2) as pool:
                erster = pool.submit(anfrage, "nebenlaeufig-a")
                try:
                    self.assertTrue(erster_drin.wait(2), "Die erste Anfrage kam nicht an")
                    self.assertTrue(
                        sperrversuche.acquire(timeout=3),
                        "Die erste Anfrage hat die Sperre nicht genommen -- fehlt das "
                        "with-Statement im Endpunkt?",
                    )
                    zweiter = pool.submit(anfrage, "nebenlaeufig-b")
                    # Harte Bedingung statt Wartezeit: die zweite Anfrage muss nachweislich
                    # an der Sperre angekommen sein. Erst dann sagt die Zahl der Lesevorgaenge
                    # etwas aus -- liest die zweite trotzdem, arbeiten beide auf demselben
                    # veralteten Stand und der letzte Vollzugang kann verschwinden.
                    self.assertTrue(
                        sperrversuche.acquire(timeout=3),
                        "Die zweite Anfrage ist nie an der Sperre angekommen",
                    )
                    self.assertEqual(
                        len(aufrufe), 1,
                        "Die zweite Anfrage hat gelesen, obwohl die erste die Sperre hielt",
                    )
                finally:
                    freigabe.set()
                erster.result(timeout=3)
                zweiter.result(timeout=3)

        self.assertGreater(len(aufrufe), 1, "Die zweite Anfrage lief nach der Freigabe nicht an")

    def test_deaktivieren_wird_serialisiert(self):
        self._serialisierung_pruefen("PUT", "/api/v1/users/zweitadmin/enabled", {"enabled": False})

    def test_gruppenwechsel_wird_serialisiert(self):
        # "write" statt "read": Cockpit haengt nur nach USER_GROUP_TARGETS um (core.py:236),
        # "read" ist eine anzeigbare, aber keine Zielgruppe.
        self._serialisierung_pruefen("PUT", "/api/v1/users/zweitadmin/group", {"group": "write"})

    def test_loeschen_wird_serialisiert(self):
        self._serialisierung_pruefen("DELETE", "/api/v1/users/zweitadmin", None)


if __name__ == "__main__":
    unittest.main()
