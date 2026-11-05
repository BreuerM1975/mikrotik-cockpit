import os
import tempfile
import unittest
from unittest.mock import patch

# Muss vor "import core" stehen: core.py liest COCKPIT_BACKUP_DIR/COCKPIT_DEVICE_ROOMS_DIR
# beim Modul-Import (core.cfg = load_config()). Da dieses Modul alphabetisch vor test_app.py
# entdeckt wird (unittest discover), wuerde core.cfg sonst mit dem echten ~/.config-Pfad
# initialisiert werden, bevor test_app.py seinen eigenen setdefault() nachholen kann -- Python
# cached das core-Modul beim zweiten Import, der Pfad bliebe fuer den ganzen Testlauf falsch
# (siehe die Projektnotizen, 2026-09-10, Fund waehrend der Basis/Pro-Code-Trennung).
os.environ.setdefault("COCKPIT_BACKUP_DIR", tempfile.mkdtemp(prefix="cockpit-test-backups-"))
os.environ.setdefault("COCKPIT_DEVICE_ROOMS_DIR", tempfile.mkdtemp(prefix="cockpit-test-device-rooms-"))

import core
import routeros


class AddressListResolutionTests(unittest.TestCase):
    def test_static_source_list_covering_guest_keeps_drop_evidence(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=LAN src-address-list=guest-range\n"
            if command == '/ip firewall address-list print terse where list="guest-range" and dynamic=yes':
                return ""
            if command == '/ip firewall address-list print terse where list="guest-range" and dynamic=no':
                return "0 list=guest-range address=192.0.2.0/24\n"
            if command == '/ip address print terse where interface="guest"':
                return "0 interface=guest address=192.0.2.1/24\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_isolation("guest"), True)

    def test_dynamic_source_list_stays_unknown(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=LAN src-address-list=dhcp-guests\n"
            if command == '/ip firewall address-list print terse where list="dhcp-guests" and dynamic=yes':
                return "0 D list=dhcp-guests address=192.0.2.23\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_isolation("guest"))

    def test_static_destination_list_covering_lan_counts_as_lan(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest dst-address-list=home-net\n"
            if command == '/ip firewall address-list print terse where list="home-net" and dynamic=yes':
                return ""
            if command == '/ip firewall address-list print terse where list="home-net" and dynamic=no':
                return "0 list=home-net address=192.168.88.0/24\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == '/ip address print terse where interface="bridge"':
                return "0 interface=bridge address=192.168.88.1/24\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_isolation("guest"), True)

    def test_ipsec_policy_accept_is_not_treated_as_general_leak(self):
        with patch.object(core, "router", return_value=(
            "0 chain=forward action=accept in-interface=guest ipsec-policy=in,ipsec\n"
            "1 chain=forward action=drop in-interface=guest out-interface-list=LAN\n"
        )):
            self.assertIsNone(core._guest_isolation("guest"))


class AbgeschalteteEintraegeTests(unittest.TestCase):
    """Ein abgeschalteter Eintrag wirkt im Router nicht und darf deshalb nichts belegen.

    Gemessen am 2026-11-05 auf CHR 7.24.5 und 7.25.1: `print terse where dynamic=no` liefert auch
    abgeschaltete Adresslisten-Zeilen, erkennbar nur am Flag X. Die Hausnetz-Definition (Liste
    "LAN") zaehlt dagegen bewusst alles mit: dort waere Weglassen die riskante Richtung.
    """

    REGEL_LISTE = "0 chain=forward action=drop in-interface=guest out-interface-list=LAN src-address-list=guest-range\n"

    def _isolation(self, antworten):
        def router_stub(command):
            return antworten.get(command, "")

        with patch.object(core, "router", side_effect=router_stub):
            return core._guest_isolation("guest")

    def _adressliste(self, zeilen):
        return {
            "/ip firewall filter print terse where chain=forward": self.REGEL_LISTE,
            '/ip firewall address-list print terse where list="guest-range" and dynamic=yes': "",
            '/ip firewall address-list print terse where list="guest-range" and dynamic=no': zeilen,
            '/ip address print terse where interface="guest"': "0 interface=guest address=192.0.2.1/24\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }

    def test_abgeschaltete_adresszeile_belegt_keine_isolation(self):
        self.assertIsNone(self._isolation(self._adressliste("0 X list=guest-range address=192.0.2.0/24\n")))

    def test_liste_nur_aus_abgeschalteten_zeilen_ist_leer(self):
        with patch.object(core, "router", side_effect=lambda c: "" if "dynamic=yes" in c else "0 X list=a address=192.0.2.0/24\n"):
            self.assertEqual(core._static_address_list_networks("a"), set())

    def test_aktive_zeile_neben_abgeschalteter_bleibt_beleg(self):
        zeilen = "0 X list=guest-range address=10.0.0.0/8\n1   list=guest-range address=192.0.2.0/24\n"
        self.assertIs(self._isolation(self._adressliste(zeilen)), True)

    def test_abgeschaltete_weite_zeile_neben_fremder_aktiver(self):
        zeilen = "0 X list=guest-range address=192.0.0.0/8\n1   list=guest-range address=198.51.100.0/24\n"
        self.assertIsNone(self._isolation(self._adressliste(zeilen)))

    def test_abgeschaltetes_mitglied_bindet_drop_regel_nicht_ans_gastnetz(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface-list=gaeste out-interface-list=LAN\n",
            '/interface list member print terse where list="gaeste"': "0 X list=gaeste interface=guest\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }))

    def test_abgeschaltetes_mitglied_macht_accept_nicht_zum_leck(self):
        self.assertIs(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface-list=gaeste out-interface-list=LAN\n"
                "1 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="gaeste"': "0 X list=gaeste interface=guest\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }), True)

    def test_zielliste_mit_abgeschaltetem_hausnetz_deckt_es_nicht_ab(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface=guest out-interface-list=hausnetz\n",
            '/interface list member print terse where list="hausnetz"': "0 X list=hausnetz interface=bridge\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }))

    def test_drop_auf_lan_mit_abgeschaltetem_mitglied_ist_kein_beleg(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="LAN"':
                "0 X list=LAN interface=bridge\n1   list=LAN interface=ether5\n",
        }))

    def test_accept_auf_aktives_lan_mitglied_bleibt_ein_leck(self):
        self.assertIs(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="LAN"':
                "0 X list=LAN interface=bridge\n1   list=LAN interface=ether5\n",
        }), False)

    def test_accept_auf_lan_nur_mit_abgeschalteten_mitgliedern_trifft_nichts(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="LAN"': "0 X list=LAN interface=bridge\n",
        }))

    def test_gastnetz_als_abgeschaltetes_lan_mitglied_ist_kein_zweifel(self):
        self.assertIs(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface=guest out-interface-list=LAN\n"
                "1 chain=forward action=accept in-interface=guest\n",
            '/interface list member print terse where list="LAN"':
                "0 list=LAN interface=bridge\n1 X list=LAN interface=guest\n",
        }), True)

    def test_kommentar_taeuscht_kein_abgeschaltetes_mitglied_vor(self):
        self.assertIs(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface=guest out-interface-list=x\n"
                "1 chain=forward action=drop in-interface=guest\n",
            '/interface list member print terse where list="x"':
                "0 comment=notiz disabled=true list=x interface=bridge dynamic=no\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }), False)

    def test_kommentar_taeuscht_keine_abgeschaltete_regel_vor(self):
        self.assertIs(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 comment=notiz disabled=true chain=forward action=accept in-interface=guest\n"
                "1 chain=forward action=drop in-interface=guest\n",
        }), False)

    def test_kommentar_taeuscht_keine_abgeschaltete_adresszeile_vor(self):
        with patch.object(core, "router", side_effect=lambda c: "" if "dynamic=yes" in c else
                          "0 comment=notiz disabled=true list=a address=192.0.2.0/24 dynamic=no\n"):
            self.assertEqual(len(core._static_address_list_networks("a")), 1)

    def test_abgeschaltete_freigabe_wird_uebersprungen(self):
        self.assertIs(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 X chain=forward action=accept in-interface=guest\n"
                "1 chain=forward action=drop in-interface=guest\n",
        }), True)

    def test_bridge_filter_abgeschaltete_freigabe_wird_uebersprungen(self):
        antworten = {
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
            '/interface bridge port print terse where bridge="bridge"':
                "0 bridge=bridge interface=guest\n1 bridge=bridge interface=ether2\n",
            "/interface bridge filter print terse where chain=forward":
                "0 X chain=forward action=accept in-interface=guest\n"
                "1 chain=forward action=drop in-interface=guest\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._bridge_filter_isolation("guest", "bridge"), True)

    def test_lan_unlesbar_ist_kein_beleg(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=LAN\n"
            if "list=\"LAN\"" in command:
                raise core.RouterCommandFailed("failure: Testfehler")
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_isolation("guest"))

    def test_lan_leer_ist_kein_beleg(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
        }))

    def test_negierte_zielliste_ist_nicht_aufloesbar(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface=guest out-interface-list=!WAN\n"
                "1 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }))

    def test_eingebaute_liste_als_ziel_ist_nicht_aufloesbar(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface=guest out-interface-list=all\n"
                "1 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }))

    def test_eingebaute_liste_als_quelle_ist_nicht_aufloesbar(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface-list=all out-interface-list=LAN\n"
                "1 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }))

    def test_liste_mit_include_ist_nicht_aufloesbar(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface-list=gaeste out-interface-list=LAN\n"
                "1 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
            '/interface list print terse where name="gaeste"': "1 name=gaeste dynamic=no include=all exclude=LAN\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }))

    def test_leere_include_felder_stoeren_nicht(self):
        antworten = {
            '/interface list print terse where name="LAN"': "0 name=LAN dynamic=no include= exclude=\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertEqual(core._resolve_interface_list_members("LAN"), {"bridge"})

    def test_dynamisches_mitglied_belegt_nichts(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface=guest out-interface-list=lan-det\n",
            '/interface list member print terse where list="lan-det"':
                "1 D comment=LAN detected list=lan-det interface=bridge dynamic=yes\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }))

    def test_ipv6_regel_mit_adressliste_belegt_nichts(self):
        def router_stub(command):
            if command == "/ipv6 firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=LAN src-address-list=g\n"
            if 'list="g" and dynamic=no' in command:
                return "0 list=g address=192.0.2.0/24\n"
            if command == '/ip address print terse where interface="guest"':
                return "0 interface=guest address=192.0.2.1/24\n"
            if 'list="LAN"' in command:
                return "0 list=LAN interface=bridge\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_isolation("guest", filter_path="/ipv6 firewall filter"))

    def _gast_am_port(self, regel, extra=None):
        antworten = {
            "/ip firewall filter print terse where chain=forward": regel,
            '/interface bridge port print terse where interface="guest"': "0 interface=guest bridge=br-gast\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
        }
        antworten.update(extra or {})
        return self._isolation(antworten)

    def test_regel_auf_bridge_port_trifft_gerouteten_verkehr_nicht(self):
        self.assertIsNone(self._gast_am_port("0 chain=forward action=drop in-interface=guest out-interface-list=LAN\n"))

    def test_vlan_interface_auf_der_bridge_des_gastes_bleibt_unklar(self):
        self.assertIsNone(self._gast_am_port(
            "0 chain=forward action=accept in-interface=vlan20 out-interface-list=LAN\n"
            "1 chain=forward action=drop out-interface-list=LAN\n"))

    def test_bridge_nicht_lesbar_ist_kein_beleg(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=LAN\n"
            if "bridge port" in command:
                raise core.RouterCommandFailed("failure: Testfehler")
            return "0 list=LAN interface=bridge\n"

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_isolation("guest"))

    def test_lan_nur_aus_dem_gastnetz_belegt_nichts(self):
        for zeile in ("0 list=LAN interface=guest\n", "0 X list=LAN interface=guest\n"):
            with self.subTest(zeile=zeile):
                self.assertIsNone(self._isolation({
                    "/ip firewall filter print terse where chain=forward":
                        "0 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
                    '/interface list member print terse where list="LAN"': zeile,
                }))

    def test_accept_trifft_kein_hausnetz_wenn_lan_ausser_gast_aus_ist(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=accept in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="LAN"':
                "0 X list=LAN interface=bridge\n1 list=LAN interface=guest\n",
        }))

    def test_flagbuchstaben_im_kommentar_zaehlen_nicht(self):
        with patch.object(core, "router", side_effect=lambda c: "" if "print terse where name" in c else
                          "0 comment=Xbox D list=x interface=bridge dynamic=no\n"):
            self.assertEqual(core._resolve_interface_list_members("x", nur_aktive=True), {"bridge"})
        self.assertEqual(routeros.terse_flags("0 comment=Xbox list=x"), "")
        self.assertEqual(routeros.terse_flags("10 XD list=x"), "XD")

    def test_dynamisches_lan_mitglied_belegt_nichts(self):
        self.assertIsNone(self._isolation({
            "/ip firewall filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface=guest out-interface-list=LAN\n",
            '/interface list member print terse where list="LAN"': "0 D list=LAN interface=bridge dynamic=yes\n",
        }))

    def test_dynamisches_mitglied_zaehlt_als_hausnetz(self):
        with patch.object(core, "router", return_value="0 D list=LAN interface=bridge dynamic=yes\n"):
            self.assertEqual(core._resolve_interface_list_members("LAN"), {"bridge"})

    def test_ipv6_regel_mit_zielliste_belegt_nichts(self):
        def router_stub(command):
            if command == "/ipv6 firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest dst-address-list=g\n"
            if 'list="g" and dynamic=no' in command:
                return "0 list=g address=192.168.88.0/24\n"
            if 'list="LAN"' in command:
                return "0 list=LAN interface=bridge\n"
            if command == '/ip address print terse where interface="bridge"':
                return "0 interface=bridge address=192.168.88.1/24\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_isolation("guest", filter_path="/ipv6 firewall filter"))

    def test_eingebaute_listen_und_none(self):
        for name in ("all", "dynamic", "static"):
            with self.subTest(name=name), patch.object(core, "router", return_value=""):
                self.assertIsNone(core._resolve_interface_list_members(name))
        with patch.object(core, "router", return_value=""):
            self.assertEqual(core._resolve_interface_list_members("none"), set())

    def test_include_und_exclude_einzeln_und_der_wert_none(self):
        faelle = (("include=all exclude=", None), ("include= exclude=LAN", None), ("include=none exclude=none", {"bridge"}))
        for felder, erwartet in faelle:
            antworten = {
                '/interface list print terse where name="x"': f"1 name=x dynamic=no {felder}\n",
                '/interface list member print terse where list="x"': "0 list=x interface=bridge\n",
            }
            with self.subTest(felder=felder), patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
                self.assertEqual(core._resolve_interface_list_members("x"), erwartet)

    def test_vlan_zeile_mit_kommentar_disabled_bleibt_aktiv(self):
        antworten = {
            '/interface bridge print terse where name="b"': "0 name=b vlan-filtering=yes\n",
            '/interface bridge port print terse where interface="guest"': "0 interface=guest bridge=b pvid=20\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=b\n",
            '/interface bridge port print terse where bridge="b"':
                "0 bridge=b interface=guest\n1 bridge=b interface=ether2\n",
            '/interface bridge vlan print terse where bridge="b"':
                "0 comment=alt disabled=true bridge=b vlan-ids=20 current-untagged=ether2\n"
                "1 bridge=b vlan-ids=20 current-untagged=guest\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._vlan_isolation("guest", "b"), False)

    def test_abgeschaltete_vlan_zeile_zaehlt_nicht(self):
        antworten = {
            '/interface bridge print terse where name="b"': "0 name=b vlan-filtering=yes\n",
            '/interface bridge port print terse where interface="guest"': "0 interface=guest bridge=b pvid=20\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=b\n",
            '/interface bridge port print terse where bridge="b"':
                "0 bridge=b interface=guest\n1 bridge=b interface=ether2\n",
            '/interface bridge vlan print terse where bridge="b"':
                "0 X bridge=b vlan-ids=20 current-untagged=ether2\n1 bridge=b vlan-ids=20 current-untagged=guest\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._vlan_isolation("guest", "b"), True)

    def test_regel_auf_die_bridge_des_gastes_bleibt_unklar(self):
        self.assertIsNone(self._gast_am_port(
            "0 chain=forward action=accept in-interface=br-gast out-interface-list=LAN\n"
            "1 chain=forward action=drop out-interface-list=LAN\n"))

    def test_quellliste_mit_der_bridge_des_gastes_bleibt_unklar(self):
        self.assertIsNone(self._gast_am_port(
            "0 chain=forward action=accept in-interface-list=g out-interface-list=LAN\n"
            "1 chain=forward action=drop out-interface-list=LAN\n",
            {'/interface list member print terse where list="g"': "0 list=g interface=br-gast\n"}))

    def test_abgeschaltete_portzeile_verbindet_nicht(self):
        with patch.object(core, "router", return_value="0 X interface=guest bridge=alt\n1 interface=guest bridge=bridge\n"):
            self.assertEqual(core._bridge_port_of("guest"), "bridge")
        with patch.object(core, "router", return_value="0 X interface=guest bridge=alt\n"):
            self.assertIsNone(core._bridge_port_of("guest"))

    def test_abgeschalteter_bruder_port_ist_kein_hausnetz_port(self):
        with patch.object(core, "router", return_value="0 X bridge=b interface=ether2\n1 bridge=b interface=ether3\n"):
            self.assertEqual(core._bridge_siblings("b", "guest"), {"ether3"})

    def test_bypass_prueft_nur_aktive_ports_derselben_bridge(self):
        antworten = {
            '/interface bridge port print terse where interface="guest"': "0 interface=guest bridge=b\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=ether2\n",
            '/interface bridge port print terse where bridge="b"':
                "0 bridge=b interface=guest\n1 X bridge=b interface=ether2\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._guest_bridge_bypass("guest"), False)

    def test_vlan_nimmt_die_pvid_der_aktiven_portzeile(self):
        antworten = {
            '/interface bridge print terse where name="b"': "0 name=b vlan-filtering=yes\n",
            '/interface bridge port print terse where interface="guest"':
                "0 X interface=guest bridge=b pvid=20\n1 interface=guest bridge=b pvid=1\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=b\n",
            '/interface bridge port print terse where bridge="b"':
                "0 bridge=b interface=guest\n1 bridge=b interface=ether2\n",
            '/interface bridge vlan print terse where bridge="b"':
                "0 bridge=b vlan-ids=1 current-untagged=guest,ether2\n1 bridge=b vlan-ids=20 current-untagged=guest\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._vlan_isolation("guest", "b"), False)

    def test_leere_lan_liste_ist_kein_freispruch_beim_bypass(self):
        antworten = {'/interface bridge port print terse where interface="guest"': "0 interface=guest bridge=b\n"}
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIsNone(core._guest_bridge_bypass("guest"))

    def test_bridge_filter_sperre_auf_einen_von_zwei_ports_ist_kein_beleg(self):
        antworten = {
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
            '/interface bridge port print terse where bridge="bridge"':
                "0 bridge=bridge interface=guest\n1 bridge=bridge interface=ether2\n2 bridge=bridge interface=ether3\n",
            "/interface bridge filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface=guest out-interface=ether2\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIsNone(core._bridge_filter_isolation("guest", "bridge"))

    def test_lan_seite_zaehlt_abgeschaltete_auch_beim_listenvergleich(self):
        antworten = {
            '/interface list member print terse where list="LAN"': "0 X list=LAN interface=bridge\n1 list=LAN interface=ether5\n",
            '/interface list member print terse where list="x"': "0 list=x interface=ether5\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIsNone(core._interface_list_covers_lan("x"))

    def test_lan_seite_zaehlt_abgeschaltete_auch_bei_der_adressliste(self):
        antworten = {
            '/ip firewall address-list print terse where list="a" and dynamic=no': "0 list=a address=192.0.2.0/24\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=e1\n1 X list=LAN interface=e2\n",
            '/ip address print terse where interface="e1"': "0 interface=e1 address=192.0.2.1/24\n",
            '/ip address print terse where interface="e2"': "0 interface=e2 address=198.51.100.1/24\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIsNone(core._address_list_covers_interface("a", "LAN"))

    def test_lan_seite_zaehlt_abgeschaltete_auch_bei_den_hausnetz_ports(self):
        antworten = {
            '/interface list member print terse where list="LAN"': "0 X list=LAN interface=b\n",
            '/interface bridge port print terse where bridge="b"': "0 bridge=b interface=guest\n1 bridge=b interface=ether2\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertEqual(core._bridge_lan_ports("b", "guest"), {"ether2"})

    def test_ports_abgeschaltetes_mitglied_deckt_nichts_ab(self):
        with patch.object(core, "router", return_value="0 X list=p interface=ether2\n"):
            self.assertIs(core._interface_list_covers_ports("p", {"ether2"}), False)

    def test_bridge_filter_abgeschaltetes_mitglied_bindet_nicht_ans_gastnetz(self):
        antworten = {
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
            '/interface bridge port print terse where bridge="bridge"':
                "0 bridge=bridge interface=guest\n1 bridge=bridge interface=ether2\n",
            "/interface bridge filter print terse where chain=forward":
                "0 chain=forward action=drop in-interface-list=gaeste\n",
            '/interface list member print terse where list="gaeste"': "0 X list=gaeste interface=guest\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIsNone(core._bridge_filter_isolation("guest", "bridge"))

    def test_hausnetz_definition_zaehlt_abgeschaltete_mit(self):
        # Gegenrichtung: Die Bridge bleibt Hausnetz, auch wenn ihr Listeneintrag aus ist. Sonst
        # verschwaende der Bridge-Bypass und das Gastnetz saehe sicherer aus, als es ist.
        antworten = {
            '/interface bridge port print terse where interface="guest"': "0 bridge=bridge interface=guest\n",
            '/interface list member print terse where list="LAN"': "0 X list=LAN interface=bridge\n",
            "/interface bridge settings print": "use-ip-firewall: no\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._guest_bridge_bypass("guest"), True)
