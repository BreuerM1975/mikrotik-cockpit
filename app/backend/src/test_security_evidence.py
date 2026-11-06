import unittest
from unittest.mock import patch

import core
import routeros
import routes_basis
from routeros import RouterCommandFailed, RouterTimeout, parse_terse


class ServiceEvidenceTests(unittest.TestCase):
    def test_unresolved_earlier_rules_prevent_protection_claim(self):
        for rule in ("action=jump jump-target=custom", "action=accept out-interface=bridge",
                     "action=accept in-interface=!other", "action=accept connection-state=!invalid"):
            with self.subTest(rule=rule), patch.object(core, "router", return_value=(
                "0 " + rule + "\n1 action=drop in-interface=guest out-interface-list=LAN"
            )):
                self.assertIsNone(core._guest_isolation("guest"))
        with patch.object(core, "router", return_value=(
            "0 action=accept src-address-list=allowed\n1 action=drop"
        )):
            self.assertEqual(routes_basis._security_check_input_firewall()["status"], "unknown")

    def test_scoped_drops_are_not_general_protection(self):
        for matcher in ("src-address=192.0.2.9", "src-address-list=blocked",
                        "dst-address=192.0.2.1", "time=8h-9h,mon", "connection-mark=filtered",
                        "connection-nat-state=!dstnat", "future-matcher=restricted"):
            with self.subTest(matcher=matcher):
                row = parse_terse("0 chain=input action=drop " + matcher)[0]
                self.assertFalse(routes_basis._blocks_unauthorized_input(row))
                with patch.object(core, "router", return_value=(
                    "0 chain=forward action=drop in-interface=guest out-interface-list=LAN " + matcher
                )):
                    self.assertIsNone(core._guest_isolation("guest"))

    def test_interface_name_lan_is_not_the_lan_list(self):
        with patch.object(core, "router", return_value="0 chain=forward action=drop in-interface=guest out-interface=LAN"):
            self.assertIsNone(core._guest_isolation("guest"))

    def test_input_allow_all_before_drop_warns(self):
        with patch.object(core, "router", return_value="0 chain=input action=accept\n1 chain=input action=drop"):
            self.assertEqual(routes_basis._security_check_input_firewall()["status"], "warn")

    def test_disabled_allow_all_does_not_override_drop(self):
        def router_stub(command):
            if command == "/ipv6 settings print":
                # IPv6 bewusst aus, dieser Test prueft ausschliesslich die IPv4-Logik --
                # IPv6 hat eine eigene Testklasse (Ipv6InputFirewallTests unten).
                return "  disable-ipv6: yes\n"
            return "0 X chain=input action=accept\n1 chain=input action=drop"

        with patch.object(core, "router", side_effect=router_stub):
            self.assertEqual(routes_basis._security_check_input_firewall()["status"], "good")

    def test_incomplete_service_evidence_is_unknown(self):
        for output in ("", "unreadable", "0 X name=telnet"):
            with self.subTest(output=output), patch.object(core, "router", return_value=output):
                self.assertEqual(routes_basis._security_check_service_hygiene()["status"], "unknown")

    def test_known_enabled_service_warns_even_with_incomplete_inventory(self):
        with patch.object(core, "router", return_value="0 name=ftp"):
            self.assertEqual(routes_basis._security_check_service_hygiene()["status"], "warn")

    def test_both_disabled_services_are_confirmed(self):
        with patch.object(core, "router", return_value="0 X name=ftp\n1 X name=telnet"):
            self.assertEqual(routes_basis._security_check_service_hygiene()["status"], "good")


# Audit "vollstaendige Firewall-/Gastnetz-Abnahme", 10.09.2026: die drei am 09.09. dokumentierten
# Luecken (Listenmitgliedschaft, Bridge-Paketpfad, IPv6) -- siehe die Projektnotizen fuer den vollen Kontext.
class InterfaceListResolutionTests(unittest.TestCase):
    def test_out_interface_list_covering_lan_counts_as_lan(self):
        # Ein selbst benannter "Hausnetz"-Listenname statt "LAN" wurde bisher IMMER als
        # unaufloesbar behandelt, obwohl er ueber /interface list member trivial nachlesbar ist.
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=Hausnetz\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == '/interface list member print terse where list="Hausnetz"':
                return "0 list=Hausnetz interface=bridge\n1 list=Hausnetz interface=ether6\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_isolation("guest"), True)

    def test_out_interface_list_disjoint_from_lan_does_not_count(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=IOT\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == '/interface list member print terse where list="IOT"':
                return "0 list=IOT interface=ether7\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_isolation("guest"))

    def test_out_interface_list_partial_overlap_stays_unknown(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=Mixed\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n1 list=LAN interface=ether6\n"
            if command == '/interface list member print terse where list="Mixed"':
                return "0 list=Mixed interface=bridge\n"  # ether6 fehlt -- keine volle Abdeckung
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_isolation("guest"))

    def test_accept_rule_via_resolved_list_confirms_leak(self):
        # Verbessert eine bisherige Schwaeche: eine Accept-Regel mit einer nicht woertlich
        # "LAN" genannten, aber nachweislich LAN-deckenden Liste galt bisher nur als "unknown",
        # obwohl der Leck eindeutig nachweisbar ist.
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=accept in-interface=guest out-interface-list=Hausnetz\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == '/interface list member print terse where list="Hausnetz"':
                return "0 list=Hausnetz interface=bridge\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_isolation("guest"), False)

    def test_in_interface_list_membership_counts_like_in_interface(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface-list=Gaeste out-interface-list=LAN\n"
            if command == '/interface list member print terse where list="Gaeste"':
                return "0 list=Gaeste interface=guest\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_isolation("guest"), True)

    def test_in_interface_list_without_guest_is_irrelevant(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface-list=Andere out-interface-list=LAN\n"
            if command == '/interface list member print terse where list="Andere"':
                return "0 list=Andere interface=ether9\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_isolation("guest"))

    def test_negated_in_interface_list_stays_unresolved(self):
        # Das RouterOS-IPv6-Defconf-Muster "in-interface-list=!LAN" -- bewusst nicht aufgeloest,
        # zu vieldeutig fuer eine sichere automatische Interpretation in dieser Version.
        with patch.object(core, "router", return_value="0 chain=forward action=drop in-interface-list=!LAN\n"):
            self.assertIsNone(core._guest_isolation("guest"))


class BridgeBypassTests(unittest.TestCase):
    def test_confirmed_when_same_bridge_and_use_ip_firewall_off(self):
        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=bridge\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == "/interface bridge settings print":
                return "              use-ip-firewall: no\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_bridge_bypass("guest"), True)

    def test_false_when_not_a_bridge_port(self):
        with patch.object(core, "router", return_value=""):
            self.assertIs(core._guest_bridge_bypass("guest"), False)

    def test_false_when_use_ip_firewall_enabled(self):
        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=bridge\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == "/interface bridge settings print":
                return "              use-ip-firewall: yes\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_bridge_bypass("guest"), False)

    def test_false_when_different_bridge_without_lan_overlap(self):
        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=guest-bridge\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == '/interface bridge port print terse where bridge="guest-bridge"':
                return "0 interface=guest bridge=guest-bridge\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_bridge_bypass("guest"), False)

    def test_unknown_when_lan_list_unreadable(self):
        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=bridge\n"
            if command == '/interface list member print terse where list="LAN"':
                raise RouterCommandFailed("failure: no such item")
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_bridge_bypass("guest"))

    def test_unknown_when_lan_list_is_empty(self):
        # Bis 2026-11-05 hiess das False, "kein Bypass". Eine leere Liste sagt aber nichts ueber das
        # Hausnetz, und zusammen mit einer allgemeinen Drop-Regel wurde daraus Gruen, obwohl Gast
        # und Hausnetz auf derselben Bridge liegen koennen.
        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=bridge\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._guest_bridge_bypass("guest"))


class BridgeFilterIsolationTests(unittest.TestCase):
    """Audit "Bridge-Filter/VLAN-Isolation", 10.09.2026. Realistisches Szenario wie am
    Test-hAP: die Liste "LAN" enthaelt nur "bridge" selbst, "Hausnetz"-Ports sind also alle
    anderen Ports derselben Bridge (hier: ether2, ether3)."""

    def _stub(self, filter_output, ports_output="0 interface=ether2 bridge=bridge\n1 interface=ether3 bridge=bridge\n"):
        def router_stub(command):
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == '/interface bridge port print terse where bridge="bridge"':
                return ports_output
            if command == "/interface bridge filter print terse where chain=forward":
                return filter_output
            return ""
        return router_stub

    def test_no_rules_is_unknown(self):
        with patch.object(core, "router", side_effect=self._stub("")):
            self.assertIsNone(core._bridge_filter_isolation("guest", "bridge"))

    def test_full_drop_confirms_isolation(self):
        # Realistisches Muster fuer eine vollstaendige Bridge-Filter-Isolation: keine
        # out-interface-Einschraenkung -- "bridge" (das IP-Ebenen-"LAN" am Test-hAP) ist selbst
        # nie ein gueltiges Bridge-Filter-Ziel (Pakete verlassen physische Ports, nicht die
        # Bridge-Pseudoschnittstelle), "out-interface-list=LAN" waere hier faktisch wirkungslos.
        rule = "0 chain=forward action=drop in-interface=guest disabled=false\n"
        with patch.object(core, "router", side_effect=self._stub(rule)):
            self.assertIs(core._bridge_filter_isolation("guest", "bridge"), True)

    def test_out_interface_list_naming_the_ip_lan_list_does_not_cover_bridge_ports(self):
        # Bewusst dokumentiertes Detail: "out-interface-list=LAN" referenziert am Test-hAP nur
        # "bridge" selbst, nicht die einzelnen Ports -- ein Admin, der das in einer Bridge-
        # Filter-Regel so schreibt, blockt damit faktisch nichts. Kein falsches "good".
        rule = "0 chain=forward action=drop in-interface=guest out-interface-list=LAN disabled=false\n"
        with patch.object(core, "router", side_effect=self._stub(rule)):
            self.assertIsNone(core._bridge_filter_isolation("guest", "bridge"))

    def test_drop_scoped_to_one_protocol_is_not_full_isolation(self):
        rule = "0 chain=forward action=drop in-interface=guest mac-protocol=ip disabled=false\n"
        with patch.object(core, "router", side_effect=self._stub(rule)):
            self.assertIsNone(core._bridge_filter_isolation("guest", "bridge"))

    def test_accept_before_drop_denies_confirmation(self):
        rule = ("0 chain=forward action=accept in-interface=guest out-interface=ether2 disabled=false\n"
                "1 chain=forward action=drop in-interface=guest out-interface-list=LAN disabled=false\n")
        with patch.object(core, "router", side_effect=self._stub(rule)):
            self.assertIs(core._bridge_filter_isolation("guest", "bridge"), False)

    def test_disabled_drop_is_ignored(self):
        rule = "0 X chain=forward action=drop in-interface=guest out-interface-list=LAN\n"
        with patch.object(core, "router", side_effect=self._stub(rule)):
            self.assertIsNone(core._bridge_filter_isolation("guest", "bridge"))

    def test_rule_for_different_ingress_port_is_irrelevant(self):
        rule = "0 chain=forward action=drop in-interface=ether2 out-interface-list=LAN disabled=false\n"
        with patch.object(core, "router", side_effect=self._stub(rule)):
            self.assertIsNone(core._bridge_filter_isolation("guest", "bridge"))

    def test_lan_ports_unresolved_is_unknown(self):
        def router_stub(command):
            if command == '/interface list member print terse where list="LAN"':
                raise RouterCommandFailed("failure: no such item")
            return ""
        with patch.object(core, "router", side_effect=router_stub):
            self.assertIsNone(core._bridge_filter_isolation("guest", "bridge"))


class VlanIsolationTests(unittest.TestCase):
    def _stub(self, vlan_filtering, pvid, vlan_rows,
              ports_output="0 interface=ether2 bridge=bridge\n1 interface=ether3 bridge=bridge\n"):
        def router_stub(command):
            if command == '/interface bridge print terse where name="bridge"':
                return f"0 name=bridge vlan-filtering={vlan_filtering}\n"
            if command == '/interface bridge port print terse where interface="guest"':
                return f"0 interface=guest bridge=bridge pvid={pvid} ingress-filtering=yes frame-types=admit-all\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == '/interface bridge port print terse where bridge="bridge"':
                return ports_output
            if command == '/interface bridge vlan print terse where bridge="bridge"':
                return vlan_rows
            return ""
        return router_stub

    def test_vlan_filtering_off_is_unknown(self):
        stub = self._stub("no", "20", "0 bridge=bridge vlan-ids=20 untagged=guest\n")
        with patch.object(core, "router", side_effect=stub):
            self.assertIsNone(core._vlan_isolation("guest", "bridge"))

    def test_no_matching_table_entry_is_unknown(self):
        stub = self._stub("yes", "20", "0 bridge=bridge vlan-ids=30 untagged=ether2\n")
        with patch.object(core, "router", side_effect=stub):
            self.assertIsNone(core._vlan_isolation("guest", "bridge"))

    def test_own_vlan_without_lan_ports_confirms_isolation(self):
        rows = "0 bridge=bridge vlan-ids=20 current-untagged=guest\n"
        stub = self._stub("yes", "20", rows)
        with patch.object(core, "router", side_effect=stub):
            self.assertIs(core._vlan_isolation("guest", "bridge"), True)

    def test_shared_vlan_with_lan_port_denies_confirmation(self):
        rows = "0 bridge=bridge vlan-ids=1 current-untagged=guest,ether2,ether3\n"
        stub = self._stub("yes", "1", rows)
        with patch.object(core, "router", side_effect=stub):
            self.assertIs(core._vlan_isolation("guest", "bridge"), False)

    def test_no_other_bridge_ports_is_unknown(self):
        # Live-Regelfall am Test-hAP: vlan-filtering=no ist der primaere Grund, aber selbst bei
        # aktivierter Filterung waere ohne andere Bridge-Ports kein Vergleich moeglich.
        rows = "0 bridge=bridge vlan-ids=1 current-untagged=guest\n"
        stub = self._stub("yes", "1", rows, ports_output="")
        with patch.object(core, "router", side_effect=stub):
            self.assertIsNone(core._vlan_isolation("guest", "bridge"))


class Ipv6RelevantTests(unittest.TestCase):
    def test_active_by_routeros_default(self):
        with patch.object(core, "router", return_value="  disable-ipv6: no\n  forward: yes\n"):
            self.assertIs(core._ipv6_relevant(), True)

    def test_disabled(self):
        with patch.object(core, "router", return_value="  disable-ipv6: yes\n"):
            self.assertIs(core._ipv6_relevant(), False)

    def test_missing_package_is_not_relevant(self):
        with patch.object(core, "router", side_effect=RouterCommandFailed("bad command name ipv6")):
            self.assertIs(core._ipv6_relevant(), False)

    def test_unreadable_is_unknown(self):
        with patch.object(core, "router", return_value=""):
            self.assertIsNone(core._ipv6_relevant())


class InputKommentarTests(unittest.TestCase):
    """Dieselben Zeilen wie in der Messung vom 2026-11-06, jetzt fuer die Input-Kette."""

    WAN = '/interface list member print terse where list="WAN"'

    def _pruefe(self, regeln, **antworten):
        tabelle = {"/ip firewall filter print terse where chain=input": regeln, self.WAN: "0 list=WAN interface=ether1\n", **antworten}
        with patch.object(core, "router", side_effect=lambda c: tabelle.get(c, "")):
            return routes_basis._input_firewall_check()[0]

    def test_kommentar_taeuscht_keine_bestehenden_verbindungen_vor(self):
        self.assertIs(self._pruefe(
            "0 comment=alt connection-state=established chain=input action=accept\n"
            "1 chain=input action=drop\n"), False)

    def test_kommentar_taeuscht_keine_abgeschaltete_freigabe_vor(self):
        self.assertIs(self._pruefe(
            "0 comment=alt disabled=true chain=input action=accept\n"
            "1 chain=input action=drop\n"), False)

    def test_kommentar_taeuscht_keine_eingrenzung_vor(self):
        self.assertIs(self._pruefe(
            "0 comment=alt protocol=icmp chain=input action=accept\n"
            "1 chain=input action=drop\n"), False)

    def test_kommentar_entwertet_keine_sperre(self):
        self.assertIs(self._pruefe("0 comment=alt protocol=tcp chain=input action=drop\n"), True)

    def test_unlesbare_zeile_ist_unklar(self):
        self.assertIsNone(self._pruefe(
            "0 comment=a chain=b chain=input action=accept\n"
            "1 chain=input action=drop\n"))

    def test_regel_mit_geloeschtem_interface_wirkt_nicht(self):
        self.assertIs(self._pruefe(
            "0 I comment=no interface chain=input action=accept in-interface=*A\n"
            "1 chain=input action=drop\n"), True)

    def test_sperre_mit_geloeschtem_interface_belegt_nichts(self):
        self.assertIs(self._pruefe("0 I comment=no interface chain=input action=drop in-interface=!*A\n"), False)

    def test_sperre_mit_flag_i_belegt_nichts(self):
        for zeile in ("0 I chain=input action=drop\n",
                      "0 I comment=in/out-interface matcher not possible chain=input action=drop in-interface=ether1\n"):
            with self.subTest(zeile=zeile):
                self.assertIsNone(self._pruefe(zeile))

    def test_sperre_mit_flag_i_nennt_den_grund(self):
        tabelle = {"/ip firewall filter print terse where chain=input": "0 I comment=pppoe-out1 not ready chain=input action=drop in-interface=pppoe-out1\n",
                   self.WAN: "0 list=WAN interface=pppoe-out1\n", "/ipv6 settings print": "  disable-ipv6: yes\n"}
        with patch.object(core, "router", side_effect=lambda c: tabelle.get(c, "")):
            self.assertIn("wirkt gerade nicht", routes_basis._security_check_input_firewall()["plain"])

    def test_freigabe_mit_flag_i_bleibt_unklar(self):
        self.assertIsNone(self._pruefe("0 I chain=input action=accept\n1 chain=input action=drop\n"))

    def test_sperre_auf_fremdem_port_schuetzt_nicht(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface=ether5\n"), False)

    def test_sperre_auf_dem_wan_port_schuetzt(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface=ether1\n"), True)

    def test_sperre_auf_einem_von_zwei_wan_ports_schuetzt_nicht(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface=ether1\n",
                                   **{self.WAN: "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n"}), None)

    def test_sperre_ausser_wan_port_schuetzt_nicht(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface=!ether1\n"), False)

    def test_sperre_ausser_lan_port_schuetzt(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface=!ether2\n"), True)

    def test_sperre_ohne_wan_liste_bleibt_unklar(self):
        self.assertIsNone(self._pruefe("0 chain=input action=drop in-interface=ether1\n", **{self.WAN: ""}))

    def test_standardlisten_schuetzen_wenn_sie_den_anschluss_treffen(self):
        for regel in ("in-interface-list=!LAN", "in-interface-list=WAN"):
            with self.subTest(regel=regel):
                self.assertIs(self._pruefe(f"0 chain=input action=drop {regel}\n"), True)

    def test_sperre_auf_lan_liste_schuetzt_nicht(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface-list=LAN\n",
                                   **{'/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n"}), False)

    def test_eigene_liste_mit_wan_schuetzt(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface-list=aussen\n",
                                   **{'/interface list member print terse where list="aussen"': "0 list=aussen interface=ether1\n"}), True)

    def test_eigene_liste_mit_einem_von_zwei_wan_ports_schuetzt_nicht(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface-list=aussen\n",
                                   **{self.WAN: "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n",
                                      '/interface list member print terse where list="aussen"': "0 list=aussen interface=ether1\n"}), None)

    def test_eigene_liste_ohne_wan_schuetzt_nicht(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface-list=aussen\n",
                                   **{'/interface list member print terse where list="aussen"': "0 list=aussen interface=ether5\n"}), False)

    def test_negierte_eigene_liste_mit_wan_schuetzt_nicht(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface-list=!aussen\n",
                                   **{'/interface list member print terse where list="aussen"': "0 list=aussen interface=ether1\n"}), False)

    def test_negierte_eigene_liste_ohne_wan_schuetzt(self):
        self.assertIs(self._pruefe("0 chain=input action=drop in-interface-list=!innen\n",
                                   **{'/interface list member print terse where list="innen"': "0 list=innen interface=bridge\n"}), True)

    def test_dynamische_liste_bleibt_unklar(self):
        self.assertIsNone(self._pruefe("0 chain=input action=drop in-interface-list=aussen\n",
                                       **{'/interface list member print terse where list="aussen"': "0 D list=aussen interface=ether1\n"}))

    def test_liste_und_interface_zugleich_bleibt_unklar(self):
        self.assertIsNone(self._pruefe("0 chain=input action=drop in-interface=ether1 in-interface-list=WAN\n"))

    def test_notrack_macht_die_zustandsfreigabe_unklar(self):
        self.assertIsNone(self._pruefe(
            "0 chain=input action=accept connection-state=established,related,untracked\n"
            "1 chain=input action=drop\n",
            **{"/ip firewall raw print terse": "0 chain=prerouting action=notrack\n"}))

    def test_ohne_notrack_bleibt_die_zustandsfreigabe_harmlos(self):
        self.assertIs(self._pruefe(
            "0 chain=input action=accept connection-state=established,related,untracked\n"
            "1 chain=input action=drop\n"), True)


class Ipv6InputFirewallTests(unittest.TestCase):
    """Audit "IPv6 Router-Selbstschutz", 10.09.2026: _security_check_input_firewall() prüfte
    bisher nur chain=input auf IPv4 -- eine global erreichbare IPv6-Adresse (SLAAC/Prefix
    Delegation) konnte SSH/Winbox/API offenlegen, selbst wenn IPv4 sauber gesperrt war."""

    def test_ipv4_good_but_ipv6_open_warns(self):
        # IPv4 hat eine aktive Sperrregel, IPv6 hat gar keine -- Gesamtstatus muss warnen,
        # nicht das gute IPv4-Ergebnis feiern.
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=input":
                return "0 chain=input action=drop disabled=false\n"
            if command == "/ipv6 settings print":
                return "  disable-ipv6: no\n"
            if command == "/ipv6 firewall filter print terse where chain=input":
                return ""
            if command == "/ipv6 address print terse":
                return "0 G address=2a00:1450::1/64 interface=ether1\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            result = routes_basis._security_check_input_firewall()
        self.assertEqual(result["status"], "warn")
        self.assertIn("IPv6", result["detail"])

    def test_ipv4_and_ipv6_both_blocked_is_good(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=input":
                return "0 chain=input action=drop disabled=false\n"
            if command == "/ipv6 settings print":
                return "  disable-ipv6: no\n"
            if command == "/ipv6 firewall filter print terse where chain=input":
                return "0 chain=input action=drop disabled=false\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            result = routes_basis._security_check_input_firewall()
        self.assertEqual(result["status"], "good")

    def test_ipv6_disabled_does_not_require_a_second_check(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=input":
                return "0 chain=input action=drop disabled=false\n"
            if command == "/ipv6 settings print":
                return "  disable-ipv6: yes\n"
            if command == "/ipv6 firewall filter print terse where chain=input":
                raise AssertionError("IPv6-Filter darf bei deaktiviertem Stack nicht abgefragt werden")
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            result = routes_basis._security_check_input_firewall()
        self.assertEqual(result["status"], "good")

    def test_ipv6_status_unclear_downgrades_good_ipv4_to_unknown(self):
        def router_stub(command):
            if command == "/ip firewall filter print terse where chain=input":
                return "0 chain=input action=drop disabled=false\n"
            if command == "/ipv6 settings print":
                return ""
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            result = routes_basis._security_check_input_firewall()
        self.assertEqual(result["status"], "unknown")

class InputFreigabenTests(unittest.TestCase):
    """Enge Freigaben vor der Sperre. Die Faelle laufen auch als Wahrheitstest mit echten Paketen (mess_input.py)."""

    F4 = "/ip firewall filter print terse where chain=input"
    F6 = "/ipv6 firewall filter print terse where chain=input"
    WAN = '/interface list member print terse where list="WAN"'
    DIENSTE = "/ip service print terse"
    SPERRE = "9 chain=input action=drop in-interface-list=!LAN\n"

    def _tabelle(self, **extra):
        return {self.WAN: "0 list=WAN interface=ether1\n",
                self.DIENSTE: "0 name=ssh port=22\n1 name=www port=80\n", **extra}

    def _urteil(self, regeln, pfad="/ip firewall filter", **antworten):
        tabelle = self._tabelle(**antworten)
        tabelle[f"{pfad} print terse where chain=input"] = regeln
        with patch.object(core, "router", side_effect=lambda c: tabelle.get(c, "")):
            return routes_basis._input_firewall_check(pfad)[0]

    def test_standardfirewall_ipv4_ist_gruen(self):
        self.assertIs(self._urteil(
            "0 comment=defconf: accept established,related,untracked chain=input action=accept connection-state=established,related,untracked\n"
            "1 comment=defconf: drop invalid chain=input action=drop connection-state=invalid\n"
            "2 comment=defconf: accept ICMP chain=input action=accept protocol=icmp\n"
            "3 comment=defconf: accept to local loopback (for CAPsMAN) chain=input action=accept dst-address=127.0.0.1\n"
            "4 comment=defconf: drop all not coming from LAN chain=input action=drop in-interface-list=!LAN\n"), True)

    def test_standardfirewall_ipv6_ist_gruen(self):
        self.assertIs(self._urteil(
            "0 chain=input action=accept connection-state=established,related,untracked\n"
            "1 chain=input action=drop connection-state=invalid\n"
            "2 chain=input action=accept protocol=icmpv6\n"
            "3 chain=input action=accept protocol=udp dst-port=33434-33534\n"
            "4 chain=input action=accept protocol=udp src-address=fe80::/10 dst-port=546\n"
            "5 chain=input action=accept protocol=udp dst-port=500,4500\n"
            "6 chain=input action=accept protocol=ipsec-ah\n"
            "7 chain=input action=accept protocol=ipsec-esp\n"
            "8 chain=input action=accept ipsec-policy=in,ipsec\n"
            "9 chain=input action=drop in-interface-list=!LAN\n", pfad="/ipv6 firewall filter"), True)

    def test_vpn_port_ist_harmlos(self):
        self.assertIs(self._urteil("0 chain=input action=accept protocol=udp dst-port=51820\n" + self.SPERRE), True)
        self.assertIs(self._urteil("0 chain=input action=accept protocol=tcp dst-port=1723\n" + self.SPERRE), True)
        self.assertIs(self._urteil("0 chain=input action=accept protocol=udp dst-port=500,4500,1701-1702\n" + self.SPERRE), True)

    def test_loopback_als_ziel_ist_harmlos(self):
        for wert in ("127.0.0.1", "127.0.0.1/32", "::1", "::1/128"):
            with self.subTest(wert=wert):
                self.assertIs(self._urteil(f"0 chain=input action=accept dst-address={wert}\n" + self.SPERRE), True)

    def test_ipsec_protokolle_sind_harmlos(self):
        for feld in ("protocol=ipsec-ah", "protocol=ipsec-esp", "ipsec-policy=in,ipsec", "protocol=icmp", "protocol=icmpv6"):
            with self.subTest(feld=feld):
                self.assertIs(self._urteil(f"0 chain=input action=accept {feld}\n" + self.SPERRE), True)

    def test_dienste_nicht_lesbar_belegt_keinen_port(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept protocol=udp dst-port=51820\n" + self.SPERRE, **{self.DIENSTE: ""}))

    def test_sprungkette_bleibt_offen(self):
        self.assertIsNone(self._urteil("0 chain=input action=jump jump-target=x protocol=icmp\n" + self.SPERRE))

    def test_ungueltige_freigabe_bleibt_offen(self):
        self.assertIsNone(self._urteil("0 I comment=x not ready chain=input action=accept protocol=icmp\n" + self.SPERRE))

    def test_freigabe_von_innen_ist_harmlos(self):
        lan = '/interface list member print terse where list="LAN"'
        self.assertIs(self._urteil("0 chain=input action=accept in-interface-list=LAN\n" + self.SPERRE, **{lan: "0 list=LAN interface=bridge\n"}), True)
        self.assertIs(self._urteil("0 chain=input action=accept in-interface=bridge\n" + self.SPERRE), True)

    def test_sprung_ohne_sperre_dahinter_bleibt_offen(self):
        self.assertIsNone(self._urteil("0 chain=input action=jump jump-target=x\n"))

    def test_hinweis_nutzt_die_kette_seiner_adressfamilie(self):
        ergebnis = self._beide_familien("0 chain=input action=drop\n", "0 chain=input action=drop in-interface=he-tunnel\n", **{
            self.WAN: "", self.ROUTE6: "0 DAv dst-address=::/0 immediate-gw=he-tunnel\n1 s dst-address=::/0 immediate-gw=fe80::1%lte1\n",
            **self._name("he-tunnel", "lte1")})
        self.assertIn("alle deine Internetanschlüsse", ergebnis["plain"])

    def test_eingebaute_interfacegruppe_ist_nicht_innen(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface=all-ethernet\n" + self.SPERRE))
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface-list=all\n" + self.SPERRE))

    def test_liste_nicht_aufloesbar_ist_nicht_innen(self):
        lan = '/interface list print terse where name="LAN"'
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface-list=LAN\n" + self.SPERRE, **{lan: "0 name=LAN include=all\n"}))

    def _ohne_wan(self, regeln, route, *interfaces, pfad="/ip firewall filter", route_befehl='/ip route print terse where dst-address="0.0.0.0/0" and !disabled'):
        antworten = {self.WAN: "", route_befehl: route}
        for name in interfaces:
            antworten[f'/interface print terse where name="{name}"'] = f"0 name={name}\n"
        return self._urteil(regeln, pfad=pfad, **antworten)

    def test_ohne_liste_wan_entscheidet_die_standardroute(self):
        route = "0 As dst-address=0.0.0.0/0 routing-table=main gateway=192.168.1.1 immediate-gw=192.168.1.1%ether1\n"
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=ether1\n", route, "ether1"), True)
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=ether5\n", route, "ether1"), False)

    def test_standardroute_ipv6_wird_getrennt_gelesen(self):
        befehl = '/ipv6 route print terse where dst-address="::/0" and !disabled'
        route = "0 DAv dst-address=::/0 routing-table=main gateway=pppoe-out1 immediate-gw=pppoe-out1\n"
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=pppoe-out1\n", route, "pppoe-out1", pfad="/ipv6 firewall filter", route_befehl=befehl), True)
        self.assertIsNone(self._ohne_wan("0 chain=input action=drop in-interface=pppoe-out1\n", "", pfad="/ipv6 firewall filter", route_befehl=befehl))

    def test_zwei_standardrouten_muessen_beide_gedeckt_sein(self):
        route = ("0 As dst-address=0.0.0.0/0 routing-table=main immediate-gw=10.0.0.1%ether1\n"
                 "1 As dst-address=0.0.0.0/0 routing-table=main immediate-gw=10.0.1.1%ether2\n")
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=ether1\n", route, "ether1", "ether2"), None)

    def test_unsichere_routennamen_belegen_nichts(self):
        faelle = {
            "keine Route": "",
            "Name unbekannt": "0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%ether1\n",
            "Adresse statt Name": "0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1\n",
            "ohne Feld": "0 As dst-address=0.0.0.0/0 blackhole\n",
            "Zeichen": '0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%a"b\n',
        }
        for name, route in faelle.items():
            with self.subTest(fall=name):
                self.assertIsNone(self._ohne_wan("0 chain=input action=drop in-interface=ether1\n", route))

    def test_feste_verwaltungsports_gelten_auch_ohne_eintrag_in_den_diensten(self):
        for port in ("22", "80"):
            with self.subTest(port=port):
                self.assertIsNone(self._urteil(
                    f"0 chain=input action=accept protocol=tcp dst-port={port}\n" + self.SPERRE, **{self.DIENSTE: "0 name=winbox port=8291\n"}))

    def _lesefehler(self, regeln, kaputt, **antworten):
        tabelle = self._tabelle(**antworten)
        tabelle[self.F4] = regeln

        def router(befehl):
            if befehl == kaputt:
                raise routes_basis.RouterCommandFailed("x")
            return tabelle.get(befehl, "")

        with patch.object(core, "router", side_effect=router):
            return routes_basis._input_firewall_check()[0]

    def test_dienste_lesefehler_belegt_keinen_port(self):
        self.assertIsNone(self._lesefehler("0 chain=input action=accept protocol=udp dst-port=51820\n" + self.SPERRE, self.DIENSTE))

    def test_routen_lesefehler_belegt_nichts(self):
        route = '/ip route print terse where dst-address="0.0.0.0/0" and !disabled'
        self.assertIsNone(self._lesefehler("0 chain=input action=drop in-interface=ether1\n", route, **{self.WAN: ""}))

    def test_portliste_mit_text_belegt_nichts(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept protocol=tcp dst-port=abc,51820\n" + self.SPERRE))

    def test_ohne_uplink_ist_keine_freigabe_innen(self):
        self.assertIsNone(self._ohne_wan("0 chain=input action=accept in-interface=bridge\n1 chain=input action=drop\n", ""))

    def test_liste_wan_und_standardroute_zaehlen_zusammen(self):
        route = '/ip route print terse where dst-address="0.0.0.0/0" and !disabled'
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface=ether1\n", **{
            route: "0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%ether5\n", '/interface print terse where name="ether5"': "0 name=ether5\n"}))

    def test_mehrere_gateways_in_einer_route_muessen_gedeckt_sein(self):
        route = "0 As dst-address=0.0.0.0/0 routing-table=main immediate-gw=10.0.0.1%ether1,10.0.1.1%ether2\n"
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=ether1\n", route, "ether1", "ether2"), None)

    def test_unsicherer_routenname_landet_in_keinem_befehl(self):
        befehle = []
        tabelle = self._tabelle(**{
            self.WAN: "", self.F4: "0 chain=input action=drop in-interface=ether1\n",
            '/ip route print terse where dst-address="0.0.0.0/0" and !disabled': '0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%a"b\n'})

        def router(befehl):
            befehle.append(befehl)
            return tabelle.get(befehl, "")

        with patch.object(core, "router", side_effect=router):
            routes_basis._input_firewall_check()
        self.assertFalse([b for b in befehle if 'a"b' in b])

    def _beide_familien(self, v4, v6, **antworten):
        tabelle = self._tabelle(**antworten)
        tabelle[self.F4], tabelle[self.F6] = v4, v6
        tabelle["/ipv6 settings print"] = "  disable-ipv6: no\n"
        with patch.object(core, "router", side_effect=lambda c: tabelle.get(c, "")):
            return routes_basis._security_check_input_firewall()

    def test_bei_zwei_offenen_fragen_bleibt_ipv4_die_erste(self):
        frage = "0 chain=input action=accept src-address=10.0.0.1\n1 chain=input action=drop\n"
        self.assertIn("Noch offen bei IPv4", self._beide_familien(frage, frage)["plain"])

    def test_kein_befehl_bei_negiertem_port_und_bei_zwei_feldern(self):
        for regel in ("in-interface=!ether1", "in-interface=ether1 in-interface-list=x"):
            with self.subTest(regel=regel):
                ergebnis = self._pruefung(f"0 chain=input action=drop {regel}\n", **{self.WAN: ""})
                self.assertEqual(ergebnis["status"], "unknown")
                self.assertNotIn("/interface list", ergebnis["plain"])
                self.assertIn("nicht sicher bestimmen", ergebnis["plain"])

    ROUTE4 = '/ip route print terse where dst-address="0.0.0.0/0" and !disabled'
    ROUTE6 = '/ipv6 route print terse where dst-address="::/0" and !disabled'

    def _name(self, *namen):
        return {f'/interface print terse where name="{name}"': f"0 name={name}\n" for name in namen}

    def test_sperre_ohne_den_pppoe_zugang_ist_kein_beleg(self):
        route = "0 DAv dst-address=0.0.0.0/0 routing-table=main gateway=pppoe-out1 immediate-gw=pppoe-out1\n"
        for regel in ("in-interface=ether1", "in-interface-list=WAN"):
            with self.subTest(regel=regel):
                self.assertIsNone(self._urteil(f"0 chain=input action=drop {regel}\n", **{self.ROUTE4: route}, **self._name("pppoe-out1")))

    def test_liste_wan_mit_allen_wegen_ist_beleg(self):
        self.assertIs(self._urteil("0 chain=input action=drop in-interface-list=WAN\n", **{
            self.WAN: "0 list=WAN interface=pppoe-out1\n", self.ROUTE4: "0 DAv dst-address=0.0.0.0/0 immediate-gw=pppoe-out1\n"}, **self._name("pppoe-out1")), True)

    def test_leere_liste_wan_ohne_route_belegt_nichts(self):
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface-list=WAN\n", **{self.WAN: ""}))

    def test_liste_wan_nicht_auswertbar_belegt_nichts(self):
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface-list=!LAN\n", **{'/interface list print terse where name="WAN"': "0 name=WAN include=all\n"}))

    def test_nicht_lan_mit_internet_in_lan_schuetzt_nicht(self):
        lan = '/interface list member print terse where list="LAN"'
        self.assertIs(self._urteil(self.SPERRE, **{lan: "0 list=LAN interface=bridge\n1 list=LAN interface=ether1\n"}), False)

    def test_nicht_lan_mit_einem_von_zwei_wegen_ist_kein_beleg(self):
        lan = '/interface list member print terse where list="LAN"'
        self.assertIsNone(self._urteil(self.SPERRE, **{
            self.WAN: "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n", lan: "0 list=LAN interface=ether1\n"}))

    def test_nicht_lan_mit_include_ist_kein_beleg(self):
        self.assertIsNone(self._urteil(self.SPERRE, **{'/interface list print terse where name="LAN"': "0 name=LAN include=all\n"}))

    def test_nicht_lan_ohne_internet_in_lan_ist_beleg(self):
        lan = '/interface list member print terse where list="LAN"'
        self.assertIs(self._urteil(self.SPERRE, **{lan: "0 list=LAN interface=bridge\n"}), True)

    def test_inaktive_reserve_zaehlt(self):
        route = ("0 As dst-address=0.0.0.0/0 routing-table=main gateway=10.0.0.1 immediate-gw=10.0.0.1%ether3 distance=1\n"
                 "1  s dst-address=0.0.0.0/0 routing-table=main gateway=10.0.1.1 immediate-gw=10.0.1.1%ether5 distance=2\n")
        self.assertIsNone(self._ohne_wan("0 chain=input action=drop in-interface=ether3\n", route, "ether3", "ether5"))

    def test_freigabe_auf_der_reserve_ist_nicht_von_innen(self):
        route = "0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%ether1\n1  s dst-address=0.0.0.0/0 immediate-gw=10.0.1.1%lte1\n"
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface=lte1 protocol=tcp dst-port=8291\n" + self.SPERRE,
                                       **{self.ROUTE4: route}, **self._name("ether1", "lte1")))

    def test_blackhole_ist_kein_weg_und_kommentar_taeuscht_keinen_vor(self):
        route = ("0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%ether1\n"
                 "1  s comment=loch dst-address=0.0.0.0/0 routing-table=main blackhole immediate-gw= distance=4\n")
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=ether1\n", route, "ether1"), True)
        route = "0 As comment=alt blackhole dst-address=0.0.0.0/0 immediate-gw=10.0.1.1%ether5\n1 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%ether1\n"
        self.assertIsNone(self._ohne_wan("0 chain=input action=drop in-interface=ether1\n", route, "ether1", "ether5"))

    def test_kommentar_kann_kein_gateway_vortaeuschen(self):
        route = "0 As comment=immediate-gw=1.1.1.1%ether1 dst-address=0.0.0.0/0 immediate-gw=10.0.1.1%ether5\n"
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=ether5\n", route, "ether1", "ether5"), True)

    def test_route_mit_unerreichbarem_gateway_belegt_nichts(self):
        route = "0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%ether1\n1 Is dst-address=0.0.0.0/0 gateway=10.9.9.9 immediate-gw= distance=5\n"
        self.assertIsNone(self._ohne_wan("0 chain=input action=drop in-interface=ether1\n", route, "ether1"))

    def test_route_nur_mit_interface_als_gateway(self):
        route = "0 Is dst-address=0.0.0.0/0 gateway=pppoe-out1 immediate-gw= distance=1\n"
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=pppoe-out1\n", route, "pppoe-out1"), True)

    def test_anschluss_in_einer_vrf_ist_nicht_auswertbar(self):
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface=ether1\n", **{
            "/ip vrf print terse": "0   name=vrf5 interfaces=ether1,ether9\n1 * name=main interfaces=all\n"}))

    def test_fremde_vrf_stoert_nicht(self):
        self.assertIs(self._urteil("0 chain=input action=drop in-interface=ether1\n", **{
            "/ip vrf print terse": "0   name=vrf5 interfaces=ether5\n1 * name=main interfaces=all\n"}), True)

    def test_anschluss_als_bridge_port_ist_nicht_auswertbar(self):
        port = '/interface bridge port print terse where interface="ether1"'
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface-list=WAN\n", **{port: "0 interface=ether1 bridge=br\n"}))

    def test_vrf_oder_bridge_nicht_lesbar_belegt_nichts(self):
        for kaputt in ("/ip vrf print terse", '/interface bridge port print terse where interface="ether1"'):
            with self.subTest(kaputt=kaputt):
                self.assertIsNone(self._lesefehler("0 chain=input action=drop in-interface=ether1\n", kaputt))

    def test_name_mit_leerzeichen_in_der_liste_ist_nicht_auswertbar(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface=bridge\n" + self.SPERRE, **{self.WAN: "0 list=WAN interface=pppoe 2\n"}))

    def test_freigabe_von_innen_sieht_die_ipv4_route_auch_in_der_ipv6_kette(self):
        route = "0 DAv dst-address=0.0.0.0/0 immediate-gw=pppoe-out1\n"
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface=pppoe-out1\n" + self.SPERRE, pfad="/ipv6 firewall filter",
                                       **{self.ROUTE4: route}, **self._name("pppoe-out1")))

    def test_freigabe_von_innen_sieht_die_ipv6_route_auch_in_der_ipv4_kette(self):
        route = "0 DAv dst-address=::/0 immediate-gw=he-tunnel\n"
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface=he-tunnel\n" + self.SPERRE, **{self.ROUTE6: route}, **self._name("he-tunnel")))

    def test_route_nicht_lesbar_macht_nichts_zu_innen(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface=bridge\n" + self.SPERRE, **{
            self.ROUTE4: '0 As dst-address=0.0.0.0/0 immediate-gw=10.0.0.1%pppoe"2\n'}))

    def test_sperre_nur_fuer_ipv4_route_gilt_nur_fuer_ipv4(self):
        self.assertIs(self._urteil("0 chain=input action=drop in-interface=ether1\n", **{
            self.ROUTE6: "0 DAv dst-address=::/0 immediate-gw=he-tunnel\n"}, **self._name("he-tunnel")), True)

    def test_interfacegruppen_in_der_sperre_belegen_nichts(self):
        for regel in ("in-interface=!all-ppp", "in-interface=all-ppp", "in-interface=all-ethernet"):
            with self.subTest(regel=regel):
                self.assertIsNone(self._urteil(f"0 chain=input action=drop {regel}\n", **{self.WAN: "0 list=WAN interface=pppoe-out1\n"}))

    def test_neue_verbindungen_ohne_tracking_belegen_nichts(self):
        self.assertIsNone(self._urteil("0 chain=input action=drop connection-state=new in-interface-list=!LAN\n", **{
            "/ip firewall connection tracking print": "  enabled: no\n"}))

    def test_neue_verbindungen_mit_tracking_sind_beleg(self):
        self.assertIs(self._urteil("0 chain=input action=drop connection-state=new in-interface-list=!LAN\n", **{
            "/ip firewall connection tracking print": "  enabled: yes\n"}), True)

    def test_dynamische_vpn_und_client_dienste_zaehlen_nicht_als_verwaltung(self):
        dienste = ("0 D name=wireguard-wg1 port=51820 proto=udp\n1 D name=ntp port=123 proto=udp\n2 D name=ipsec port=500 proto=udp\n"
                   "3 D name=ipsec port=4500 proto=udp\n4 D name=dhcpclient port=546 proto=udp\n5 D name=dhcp port=547 proto=udp\n6 name=ssh port=2223 proto=tcp\n"
                   "7 D name=ovpn-server port=1194 proto=tcp\n8 D name=l2tp port=1701 proto=udp\n9 D name=ppp port=1723 proto=tcp\n10 D name=sstp-server port=4443 proto=tcp\n")
        for regel in ("protocol=udp dst-port=51820", "protocol=udp dst-port=123", "protocol=udp dst-port=500,4500", "protocol=udp dst-port=546", "protocol=udp dst-port=547",
                      "protocol=tcp dst-port=1194", "protocol=udp dst-port=1701", "protocol=tcp dst-port=1723", "protocol=tcp dst-port=4443"):
            with self.subTest(regel=regel):
                self.assertIs(self._urteil(f"0 chain=input action=accept {regel}\n" + self.SPERRE, **{self.DIENSTE: dienste}), True)

    def test_dynamische_verwaltungsdienste_zaehlen(self):
        for name, port in (("socks", 1081), ("wproxy", 3128), ("unbekannt", 9999)):
            with self.subTest(name=name):
                self.assertIsNone(self._urteil(f"0 chain=input action=accept protocol=tcp dst-port={port}\n" + self.SPERRE, **{
                    self.DIENSTE: f"0 D name={name} port={port} proto=tcp\n"}))

    def test_laufende_verbindung_in_den_diensten_zaehlt_nicht(self):
        self.assertIs(self._urteil("0 chain=input action=accept protocol=tcp dst-port=7000\n" + self.SPERRE, **{
            self.DIENSTE: "0 D c name=ssh port=7000 proto=tcp local=10.0.0.1 remote=10.0.0.2:1\n1 name=winbox port=8291\n"}), True)

    def test_loopback_mit_weiterleitung_bleibt_offen(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept dst-address=127.0.0.1\n" + self.SPERRE, **{
            "/ip firewall nat print terse": "0 chain=dstnat action=dst-nat to-addresses=127.0.0.1 to-ports=80\n"}))
        self.assertIsNone(self._urteil("0 chain=input action=accept dst-address=::1\n" + self.SPERRE, **{
            "/ipv6 firewall nat print terse": "0 chain=dstnat action=dst-nat to-address=::1/128 to-ports=80\n"}))

    def test_nat_nicht_lesbar_belegt_loopback_nicht(self):
        self.assertIsNone(self._lesefehler("0 chain=input action=accept dst-address=127.0.0.1\n" + self.SPERRE, "/ip firewall nat print terse"))

    def test_freigabe_ohne_sperre_dahinter_ist_offen(self):
        self.assertIs(self._urteil("0 chain=input action=accept src-address=10.0.0.1\n"), False)
        self.assertIs(self._urteil("0 chain=input action=accept src-address=10.0.0.1\n1 chain=input action=drop protocol=tcp dst-port=22\n"), False)

    def test_freigabe_mit_unklarem_rest_bleibt_offen(self):
        for rest in ("1 chain=input action=jump jump-target=x\n", "1 chain=input action=return\n", "1 comment=a chain=b chain=input action=drop\n",
                     "1 chain=input action=drop in-interface=ether1 in-interface-list=x\n"):
            with self.subTest(rest=rest):
                self.assertIsNone(self._urteil("0 chain=input action=accept src-address=10.0.0.1\n" + rest))

    def test_unklare_sperre_vor_der_freigabe_bleibt_offen(self):
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface=ether1 in-interface-list=x\n1 chain=input action=accept src-address=10.0.0.1\n"))

    def test_sprungregel_hat_eigenen_hinweis(self):
        ergebnis = self._pruefung("0 chain=input action=jump jump-target=x\n" + self.SPERRE)
        self.assertIn("leitet Pakete aus dieser Kette heraus", ergebnis["plain"])
        self.assertNotIn("denen du vertraust", ergebnis["plain"])

    def test_teilweise_sperre_nennt_alle_anschluesse_statt_fehlender_liste(self):
        ergebnis = self._pruefung("0 chain=input action=drop in-interface=ether1\n", **{self.WAN: "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n"})
        self.assertIn("alle deine Internetanschlüsse", ergebnis["plain"])
        self.assertNotIn("/interface list", ergebnis["plain"])

    def test_befehl_nennt_die_nebenwirkung(self):
        ergebnis = self._pruefung("0 chain=input action=drop in-interface=ether1\n", **{self.WAN: ""})
        self.assertIn(":if ([:len [/interface list find name=WAN]]=0)", ergebnis["plain"])
        self.assertIn("gelten danach auch", ergebnis["plain"])

    def test_access_point_nur_wenn_jede_rote_familie_keine_sperre_hat(self):
        self.assertNotIn("Access Point", self._beide_familien("0 chain=input action=accept\n", "", **{self.IPV6_ADRESSEN: "0 G address=2a00:1450::1/64 interface=ether2\n"})["plain"])
        self.assertIn("Access Point", self._beide_familien("", "")["plain"])

    def test_negierte_werte_sind_kein_beleg(self):
        for feld in ("protocol=!icmp", "protocol=tcp dst-port=!51820", "dst-address=!127.0.0.1", "ipsec-policy=out,ipsec", "ipsec-policy=in,none"):
            with self.subTest(feld=feld):
                self.assertIsNone(self._urteil(f"0 chain=input action=accept {feld}\n" + self.SPERRE))

    def test_verwaltungsport_ohne_offenen_dienst_bleibt_offen(self):
        for port in ("20", "21", "22", "23", "53", "69", "80", "161", "443", "445", "1080", "1812", "1813", "2000", "2049", "2828",
                     "3260", "3799", "4420", "5246", "5247", "5351", "5678", "8080", "8291", "8728", "8729",
                     "21,51820", "20-30", "8000-9000", "79-80"):
            with self.subTest(port=port):
                self.assertIsNone(self._urteil(f"0 chain=input action=accept protocol=tcp dst-port={port}\n" + self.SPERRE, **{self.DIENSTE: "0 X name=z port=9999 proto=tcp\n"}))

    def test_umgelegter_verwaltungsport_wird_rot(self):
        self.assertIs(self._urteil("0 chain=input action=accept protocol=tcp dst-port=8081\n" + self.SPERRE, **{self.DIENSTE: "0 name=www port=8081 proto=tcp\n"}), False)

    def test_statischer_dienst_mit_vpn_namen_zaehlt(self):
        self.assertIs(self._urteil("0 chain=input action=accept protocol=udp dst-port=7000\n" + self.SPERRE, **{self.DIENSTE: "0 name=ntp port=7000 proto=udp\n"}), False)
        self.assertIs(self._urteil("0 chain=input action=accept protocol=udp dst-port=7000\n" + self.SPERRE, **{self.DIENSTE: "0 name=wireguard-x port=7000 proto=udp\n"}), False)

    def test_port_als_text_und_fremde_adressen_bleiben_offen(self):
        for feld in ("protocol=tcp dst-port=abc", "src-address=10.0.0.1", "src-address-list=vertraut", "dst-address=192.168.88.1", "protocol=gre"):
            with self.subTest(feld=feld):
                self.assertIsNone(self._urteil(f"0 chain=input action=accept {feld}\n" + self.SPERRE))

    def test_freigabe_auf_dem_internetanschluss_wird_rot(self):
        lan = '/interface list member print terse where list="LAN"'
        self.assertIs(self._urteil("0 chain=input action=accept in-interface-list=LAN\n1 chain=input action=drop\n", **{lan: "0 list=LAN interface=ether1\n"}), False)
        self.assertIs(self._urteil("0 chain=input action=accept in-interface=ether1\n" + self.SPERRE), False)

    def test_internetanschluss_fehlt_in_der_liste_wan(self):
        route = '/ip route print terse where dst-address="0.0.0.0/0" and !disabled'
        pppoe = '/interface print terse where name="pppoe-out1"'
        self.assertIs(self._urteil(
            "0 chain=input action=accept in-interface=pppoe-out1\n" + self.SPERRE,
            **{route: "0 DAv dst-address=0.0.0.0/0 routing-table=main gateway=pppoe-out1 immediate-gw=pppoe-out1\n", pppoe: "0 R name=pppoe-out1\n"}), False)

    def test_access_point_auch_wenn_nur_ipv6_keine_sperre_hat(self):
        ergebnis = self._beide_familien("0 chain=input action=drop\n", "", **{self.IPV6_ADRESSEN: "0 G address=2a00:1450::1/64 interface=ether2\n"})
        self.assertIn("Access Point", ergebnis["plain"])

    def test_befehl_nicht_bei_anschluss_in_einer_bridge(self):
        port = '/interface bridge port print terse where interface="ether1"'
        ergebnis = self._pruefung("0 chain=input action=drop in-interface=ether1\n", **{port: "0 interface=ether1 bridge=br\n"})
        self.assertEqual(ergebnis["status"], "unknown")
        self.assertNotIn("/interface list", ergebnis["plain"])
        self.assertIn("Bridge oder VRF", ergebnis["plain"])

    def test_verwaltungsdienst_aus_dem_internet_wird_rot(self):
        for regel in ("protocol=tcp dst-port=80", "protocol=tcp dst-port=22,51820", "protocol=tcp dst-port=20-30", "protocol=tcp",
                      "in-interface=ether1", "in-interface-list=WAN", "in-interface=ether1 protocol=tcp dst-port=80"):
            with self.subTest(regel=regel):
                self.assertIs(self._urteil(f"0 chain=input action=accept {regel}\n1 chain=input action=drop\n"), False)

    def test_rote_freigabe_nennt_die_regel(self):
        ergebnis = self._pruefung("0 chain=input action=accept protocol=tcp dst-port=80\n" + self.SPERRE)
        self.assertEqual(ergebnis["status"], "warn")
        self.assertIn("IPv4: Die Regel „accept protocol=tcp dst-port=80“ öffnet die Verwaltung", ergebnis["plain"])
        self.assertIn("öffnet einen Verwaltungsdienst", ergebnis["detail"])

    def test_dienst_ist_nur_mit_offenem_zugang_ein_beleg(self):
        regel = "0 chain=input action=accept protocol=tcp dst-port=80\n1 chain=input action=drop\n"
        for dienst in ("0 X name=www port=80 proto=tcp\n", "0 name=www port=80 proto=tcp available-from=10.0.0.0/8\n",
                       "0 D name=www port=80 proto=tcp\n", "0 D c name=www port=80 proto=tcp local=1.1.1.1 remote=2.2.2.2:3\n",
                       "0 name=www port=80 proto=udp\n"):
            with self.subTest(dienst=dienst):
                self.assertIsNone(self._urteil(regel, **{self.DIENSTE: dienst}))

    def test_dienst_ohne_protokollangabe_gilt_als_tcp(self):
        self.assertIs(self._urteil("0 chain=input action=accept protocol=tcp dst-port=80\n1 chain=input action=drop\n", **{self.DIENSTE: "0 name=www port=80\n"}), False)

    def test_weitere_bedingung_ist_kein_beleg_fuer_offen(self):
        for regel in ("src-address=10.0.0.1 protocol=tcp dst-port=80", "protocol=tcp dst-port=80 limit=5,5:packet", "protocol=gre", "dst-port=80", "protocol=tcp dst-port=abc"):
            with self.subTest(regel=regel):
                self.assertIsNone(self._urteil(f"0 chain=input action=accept {regel}\n1 chain=input action=drop\n"))

    def test_freigabe_auf_fremdem_interface_ist_kein_beleg_fuer_offen(self):
        lan = '/interface list member print terse where list="LAN"'
        self.assertIs(self._urteil("0 chain=input action=accept in-interface=bridge protocol=tcp dst-port=80\n" + self.SPERRE), True)
        self.assertIs(self._urteil("0 chain=input action=accept in-interface-list=LAN protocol=tcp dst-port=80\n" + self.SPERRE, **{lan: "0 list=LAN interface=bridge\n"}), True)

    def test_ohne_bekannten_anschluss_ist_eine_freigabe_kein_beleg(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept protocol=tcp dst-port=80\n1 chain=input action=drop\n", **{self.WAN: ""}))

    def test_freigabe_hinter_der_sperre_kommt_nie_an(self):
        wan = "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n"
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface=ether1\n1 chain=input action=accept in-interface=ether1 protocol=tcp dst-port=80\n2 chain=input action=drop\n", **{self.WAN: wan}))
        self.assertIs(self._urteil("0 chain=input action=drop in-interface=ether1\n1 chain=input action=accept in-interface=lte1 protocol=tcp dst-port=80\n2 chain=input action=drop\n", **{self.WAN: wan}), False)

    def test_zwei_sperren_decken_zusammen_alle_wege(self):
        wan = "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n"
        self.assertIs(self._urteil("0 chain=input action=drop in-interface=ether1\n1 chain=input action=drop in-interface=lte1\n", **{self.WAN: wan}), True)
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface=ether1\n", **{self.WAN: wan}))

    def test_zustandssperre_zaehlt_nicht_fuer_die_deckung(self):
        wan = "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n"
        self.assertIsNone(self._urteil("0 chain=input action=drop connection-state=new in-interface=ether1\n1 chain=input action=drop in-interface=lte1\n", **{
            self.WAN: wan, "/ip firewall connection tracking print": "  enabled: no\n"}))

    def test_negierte_sperre_trifft_teilweise(self):
        wan = "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n"
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface=!ether1\n", **{self.WAN: wan}))
        self.assertIs(self._urteil("0 chain=input action=drop in-interface=!ether1\n"), False)
        self.assertIs(self._urteil("0 chain=input action=drop in-interface=!bridge\n"), True)

    def test_negierte_freigabe_ohne_den_anschluss_ist_von_innen(self):
        self.assertIs(self._urteil("0 chain=input action=accept in-interface=!ether1\n" + self.SPERRE), True)
        self.assertIs(self._urteil("0 chain=input action=accept in-interface-list=!WAN\n" + self.SPERRE), True)

    def test_negierte_freigabe_mit_dem_anschluss_ist_nicht_von_innen(self):
        self.assertIs(self._urteil("0 chain=input action=accept in-interface=!bridge\n1 chain=input action=drop\n"), False)
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface=!bridge src-address=10.0.0.1\n1 chain=input action=drop\n"))

    def test_oeffentliche_adresse_zaehlt_als_weg_ins_internet(self):
        adressen = "/ip address print terse"
        zeile = {adressen: "0 address=8.8.4.4/24 network=8.8.4.0 interface=ether2\n1 address=192.168.1.1/24 network=192.168.1.0 interface=bridge\n"}
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface-list=WAN\n", **zeile))
        self.assertIs(self._urteil("0 chain=input action=drop in-interface-list=!LAN\n", **zeile), True)

    def test_private_adresse_ist_kein_weg_ins_internet(self):
        self.assertIs(self._urteil("0 chain=input action=drop in-interface-list=WAN\n", **{"/ip address print terse": "0 address=192.168.100.2/24 interface=ether2\n"}), True)

    def test_adressen_nicht_lesbar_belegen_nichts(self):
        self.assertIsNone(self._lesefehler("0 chain=input action=drop in-interface-list=WAN\n", "/ip address print terse"))
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface-list=WAN\n", **{"/ip address print terse": "0 address=kaputt interface=ether2\n"}))

    def test_oeffentliche_ipv4_adresse_zaehlt_in_der_ipv6_kette_nicht_fuer_sperren(self):
        self.assertIs(self._urteil("0 chain=input action=drop in-interface-list=WAN\n", pfad="/ipv6 firewall filter", **{"/ip address print terse": "0 address=8.8.4.4/24 interface=ether2\n"}), True)

    def test_oeffentliche_ipv4_adresse_zaehlt_fuer_freigaben_auch_in_der_ipv6_kette(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept in-interface=ether2 src-address=fd00::1\n" + self.SPERRE, pfad="/ipv6 firewall filter", **{"/ip address print terse": "0 address=8.8.4.4/24 interface=ether2\n"}))

    DETECT = "/interface detect-internet print"

    def test_detect_internet_liste_belegt_nichts(self):
        for feld in ("lan-interface-list", "wan-interface-list", "internet-interface-list"):
            with self.subTest(feld=feld):
                liste = "LAN" if feld.startswith("lan") else "WAN"
                self.assertIsNone(self._urteil(f"0 chain=input action=drop in-interface-list=!{liste}\n", **{self.DETECT: f"  {feld}: {liste}\n"}))

    def test_detect_internet_auf_der_liste_wan_belegt_auch_interface_regeln_nicht(self):
        self.assertIsNone(self._urteil("0 chain=input action=drop in-interface=ether1\n", **{self.DETECT: "  wan-interface-list: WAN\n"}))

    def test_sperre_in_der_ipv6_kette_nutzt_die_ipv6_route(self):
        befehl = '/ipv6 route print terse where dst-address="::/0" and !disabled'
        route = "0 As dst-address=::/0 immediate-gw=he-tunnel\n"
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=ether5\n", route, "he-tunnel", pfad="/ipv6 firewall filter", route_befehl=befehl), False)

    def test_detect_internet_nicht_lesbar_belegt_auch_interface_regeln_nicht(self):
        self.assertIsNone(self._lesefehler("0 chain=input action=drop in-interface=ether1\n", self.DETECT))

    def test_dienst_mit_altem_adressfeld_ist_kein_beleg(self):
        self.assertIsNone(self._urteil("0 chain=input action=accept protocol=tcp dst-port=80\n1 chain=input action=drop\n", **{self.DIENSTE: "0 name=www port=80 proto=tcp address=10.0.0.0/8\n"}))

    def test_rat_passt_zur_adressfamilie(self):
        global_v6 = {self.IPV6_ADRESSEN: "0 G address=2a00:1450::1/64 interface=ether2\n"}
        nur_v6 = self._beide_familien("0 chain=input action=drop\n", "", **global_v6)["plain"]
        self.assertIn("Für IPv6 nimm", nur_v6)
        self.assertNotIn("/ip firewall filter add", nur_v6)
        nur_v4 = self._beide_familien("", "0 chain=input action=drop\n")["plain"]
        self.assertIn("/ip firewall filter add chain=input action=accept connection-state=established,related,untracked", nur_v4)
        self.assertNotIn("Für IPv6 nimm", nur_v4)
        beide = self._beide_familien("", "", **global_v6)["plain"]
        self.assertIn("Für IPv6 nimm", beide)
        self.assertIn("/ip firewall filter add", beide)

    def test_allgemeine_freigabe_nennt_den_grund_statt_den_rat(self):
        plain = self._pruefung("0 chain=input action=accept\n1 chain=input action=drop\n")["plain"]
        self.assertIn("IPv4: Eine Freigabe ohne jede Bedingung", plain)
        self.assertNotIn("/ip firewall filter add", plain)

    def test_prueflauf_liest_jeden_weg_nur_einmal(self):
        befehle = []
        tabelle = self._tabelle()
        tabelle[self.F4] = "".join(f"{i} chain=input action=accept in-interface=bridge{i}\n" for i in range(30)) + self.SPERRE

        def router(befehl):
            befehle.append(befehl)
            return tabelle.get(befehl, "")

        with patch.object(core, "router", side_effect=router):
            self.assertIs(routes_basis._input_firewall_check()[0], True)
        # Einmal fuer Sperren, einmal fuer Freigaben, die beide Adressfamilien sehen muessen.
        self.assertLessEqual(befehle.count(self.WAN), 2)
        self.assertLess(len(befehle), 30)

    def test_naechster_prueflauf_liest_frisch(self):
        befehle = []

        def router(befehl):
            befehle.append(befehl)
            return self._tabelle(**{self.F4: self.SPERRE}).get(befehl, "")

        with patch.object(core, "router", side_effect=router):
            routes_basis._input_firewall_check()
            routes_basis._input_firewall_check()
        self.assertEqual(befehle.count(self.WAN), 2)

    def test_detect_internet_aus_stoert_nicht(self):
        self.assertIs(self._urteil(self.SPERRE, **{self.DETECT: "  lan-interface-list: none\n  wan-interface-list: none\n"}), True)

    def test_detect_internet_nicht_lesbar_belegt_nichts(self):
        self.assertIsNone(self._lesefehler(self.SPERRE, self.DETECT))

    def test_tracking_aus_nennt_den_grund(self):
        ergebnis = self._pruefung("0 chain=input action=accept connection-state=established\n" + self.SPERRE, **{"/ip firewall connection tracking print": "  enabled: no\n"})
        self.assertEqual(ergebnis["status"], "unknown")
        self.assertIn("Verbindungsverfolgung ist abgeschaltet", ergebnis["plain"])
        ergebnis = self._pruefung("0 chain=input action=drop connection-state=new in-interface-list=!LAN\n", **{"/ip firewall connection tracking print": "  enabled: no\n"})
        self.assertIn("Verbindungsverfolgung ist abgeschaltet", ergebnis["plain"])

    def test_nicht_belegte_anschluesse_werden_genannt(self):
        ergebnis = self._pruefung("0 chain=input action=drop in-interface=ether1\n", **{self.WAN: "0 list=WAN interface=ether1\n1 list=WAN interface=lte1\n"})
        self.assertIn("Nicht belegt: lte1.", ergebnis["plain"])
        self.assertNotIn("/interface list", ergebnis["plain"])

    def test_befehl_nur_ohne_jeden_bekannten_anschluss(self):
        route = '/ip route print terse where dst-address="0.0.0.0/0" and !disabled'
        for extra in ({route: "0 Is dst-address=0.0.0.0/0 gateway=10.9.9.9 immediate-gw=\n"},
                      {'/interface list print terse where name="WAN"': "0 name=WAN include=all\n"}):
            with self.subTest(extra=list(extra)):
                ergebnis = self._pruefung("0 chain=input action=drop in-interface=ether1\n", **{self.WAN: "", **extra})
                self.assertEqual(ergebnis["status"], "unknown")
                self.assertNotIn("/interface list", ergebnis["plain"])
                self.assertIn("nicht sicher bestimmen", ergebnis["plain"])

    def test_routenkommentar_blendet_keine_reserve_aus(self):
        route = "1 s comment=alt dst-address=x blackhole dst-address=0.0.0.0/0 immediate-gw=10.0.1.1%ether5\n"
        self.assertIs(self._ohne_wan("0 chain=input action=drop in-interface=ether5\n", route, "ether5"), True)

    IPV6_ADRESSEN = "/ipv6 address print terse"

    def test_ipv6_ohne_globale_adresse_und_route_warnt_nicht(self):
        ergebnis = self._beide_familien("0 chain=input action=drop\n", "", **{self.IPV6_ADRESSEN: "0 DL address=fe80::1/64 interface=ether1\n1 G address=fd00::1/64 interface=ether2\n"})
        self.assertEqual(ergebnis["status"], "good")
        self.assertIn("kein Weg aus dem Internet", ergebnis["detail"])

    def test_ipv6_mit_globaler_adresse_oder_route_warnt(self):
        for extra in ({self.IPV6_ADRESSEN: "0 G address=2a00:1450::1/64 interface=ether2\n"},
                      {self.ROUTE6: "0 As dst-address=::/0 immediate-gw=fe80::1%ether1\n", **self._name("ether1")},
                      {self.ROUTE6: '0 As dst-address=::/0 immediate-gw=fe80::1%a"b\n'},
                      {self.IPV6_ADRESSEN: "0 G address=kaputt interface=ether2\n"}):
            with self.subTest(extra=list(extra)):
                self.assertEqual(self._beide_familien("0 chain=input action=drop\n", "", **extra)["status"], "warn")

    def test_ipv6_adressen_nicht_lesbar_warnt(self):
        tabelle = self._tabelle()
        tabelle[self.F4], tabelle[self.F6], tabelle["/ipv6 settings print"] = "0 chain=input action=drop\n", "", "  disable-ipv6: no\n"

        def router(befehl):
            if befehl == self.IPV6_ADRESSEN:
                raise routes_basis.RouterCommandFailed("x")
            return tabelle.get(befehl, "")

        with patch.object(core, "router", side_effect=router):
            self.assertEqual(routes_basis._security_check_input_firewall()["status"], "warn")

    def test_ipv6_ohne_internet_gilt_nur_bei_fehlender_sperre(self):
        ergebnis = self._beide_familien("0 chain=input action=drop\n", "0 chain=input action=accept\n1 chain=input action=drop\n")
        self.assertEqual(ergebnis["status"], "warn")

    def test_warnung_nennt_einen_befehl_mit_verwaltungszugang(self):
        ergebnis = self._pruefung("")
        self.assertIn("Verwaltungszugang in der Liste LAN", ergebnis["plain"])
        self.assertIn("/ip firewall filter add chain=input action=drop in-interface-list=!LAN", ergebnis["plain"])

    def test_timeout_beim_lesen_bleibt_offen(self):
        from routeros import RouterTimeout
        for kaputt in (self.F4, self.WAN):
            with self.subTest(kaputt=kaputt):
                tabelle = self._tabelle()
                tabelle[self.F4] = "0 chain=input action=drop in-interface=ether1\n"

                def router(befehl):
                    if befehl == kaputt:
                        raise RouterTimeout("x")
                    return tabelle.get(befehl, "")

                with patch.object(core, "router", side_effect=router):
                    self.assertIsNone(routes_basis._input_firewall_check()[0])

    def test_nur_eine_sperre_auf_fremdem_port_bleibt_warnung(self):
        self.assertIs(self._urteil("0 chain=input action=drop in-interface=ether5\n"), False)

    def _pruefung(self, regeln, **antworten):
        tabelle = self._tabelle(**antworten)
        tabelle[self.F4] = regeln
        tabelle[self.F6] = "0 chain=input action=drop\n"
        tabelle["/ipv6 settings print"] = "  disable-ipv6: no\n"
        with patch.object(core, "router", side_effect=lambda c: tabelle.get(c, "")):
            return routes_basis._security_check_input_firewall()

    def test_offene_frage_nennt_die_regel(self):
        ergebnis = self._pruefung("0 chain=input action=accept src-address=10.0.0.1\n" + self.SPERRE)
        self.assertEqual(ergebnis["status"], "unknown")
        self.assertIn("Noch offen bei IPv4", ergebnis["plain"])
        self.assertIn("accept src-address=10.0.0.1", ergebnis["plain"])
        self.assertIn("auch nicht, dass alles sicher ist", ergebnis["plain"])

    def test_offene_frage_nennt_die_erste_unklare_sperre_und_den_befehl(self):
        ergebnis = self._pruefung(
            "0 chain=input action=drop in-interface=ether1\n1 chain=input action=drop in-interface=ether7\n", **{self.WAN: ""})
        self.assertEqual(ergebnis["status"], "unknown")
        self.assertIn("drop in-interface=ether1“", ergebnis["plain"])
        self.assertIn('/interface list member add list=WAN interface="ether1"', ergebnis["plain"])

    def test_offene_frage_nennt_ipv6_wenn_nur_dort_offen(self):
        tabelle = self._tabelle()
        tabelle[self.F4] = "0 chain=input action=drop\n"
        tabelle[self.F6] = "0 chain=input action=accept src-address=fd00::1\n1 chain=input action=drop\n"
        tabelle["/ipv6 settings print"] = "  disable-ipv6: no\n"
        with patch.object(core, "router", side_effect=lambda c: tabelle.get(c, "")):
            ergebnis = routes_basis._security_check_input_firewall()
        self.assertIn("Noch offen bei IPv6", ergebnis["plain"])
        self.assertIn("src-address=fd00::1", ergebnis["plain"])

    def test_warnung_ohne_sperre_nennt_den_access_point(self):
        ergebnis = self._pruefung("")
        self.assertEqual(ergebnis["status"], "warn")
        self.assertIn("Access Point", ergebnis["plain"])

    def test_warnung_mit_breiter_freigabe_nennt_keinen_access_point(self):
        ergebnis = self._pruefung("0 chain=input action=accept\n1 chain=input action=drop\n")
        self.assertEqual(ergebnis["status"], "warn")
        self.assertNotIn("Access Point", ergebnis["plain"])

    def test_lange_regel_wird_gekuerzt(self):
        self.assertLessEqual(len(routes_basis._regel_kurz({"action": "accept", "src-address-list": "x" * 300})), 100)


class GeleseneNamenTests(unittest.TestCase):
    """Am CHR gemessen: RouterOS nimmt Namen mit " und ; an, ein so eingebetteter Befehl laeuft wirklich."""

    BOESE = 'x"; /system reboot; :put "y'

    def _befehle(self, funktion, tabelle):
        befehle = []

        def router(befehl):
            befehle.append(befehl)
            return tabelle.get(befehl, "")

        with patch.object(core, "router", side_effect=router):
            ergebnis = funktion()
        self.assertFalse([b for b in befehle if "reboot" in b], befehle)
        return ergebnis

    def test_gelesener_name(self):
        self.assertEqual(core._gelesener_name("ether1"), "ether1")
        self.assertEqual(core._gelesener_name("a b"), "a b")
        for name in (self.BOESE, "a;b", 'a"b', "", None, "a\nb", "br$1", "a\\b"):
            with self.subTest(name=name), self.assertRaises(routes_basis.RouterCommandFailed):
                core._gelesener_name(name)

    def test_bridge_mit_dollar_zeichen_wird_nicht_zum_falschen_gruen(self):
        befehl = '/interface bridge port print terse where interface="ether2"'
        with patch.object(core, "router", side_effect=lambda c: "0 interface=ether2 bridge=br$1\n" if c == befehl else ""):
            with self.assertRaises(routes_basis.RouterCommandFailed):
                core._bridge_port_of("ether2")

    def test_unsicherer_name_ist_ein_eigener_fehler(self):
        from routeros import RouterWertUnsicher
        with self.assertRaises(RouterWertUnsicher):
            core._gelesener_name(self.BOESE)
    def test_liste_aus_einer_regel(self):
        self.assertIsNone(self._befehle(lambda: core._resolve_interface_list_members(self.BOESE), {}))

    def test_liste_im_input_check(self):
        regel = f"0 chain=input action=drop in-interface-list={self.BOESE}\n"
        self.assertIsNot(self._befehle(routes_basis._input_firewall_check, {
            "/ip firewall filter print terse where chain=input": regel,
            '/interface list member print terse where list="WAN"': "0 list=WAN interface=ether1\n"})[0], True)

    def test_eingang_in_der_absenderpruefung(self):
        self.assertFalse(self._befehle(
            lambda: core._absender_schliesst_gast_aus({"src-address": "10.0.0.0/8"}, {self.BOESE}, "/ip firewall filter"),
            {"/ip settings print": "  rp-filter: strict\n"}))

    def test_port_aus_der_vlan_tabelle(self):
        tabelle = {
            '/interface bridge port print terse where interface="guest"': "0 interface=guest bridge=br1 pvid=20 ingress-filtering=yes frame-types=admit-only-untagged\n",
            '/interface bridge print terse where name="br1"': "0 name=br1 vlan-filtering=yes pvid=1\n",
            '/interface bridge port print terse where bridge="br1"': "0 interface=guest bridge=br1 pvid=20\n1 interface=ether2 bridge=br1 pvid=1\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=br1\n",
            '/interface bridge vlan print terse where bridge="br1"': f"0 bridge=br1 vlan-ids=20 tagged=br1 untagged=guest current-tagged=br1 current-untagged=guest,{self.BOESE}\n",
            '/interface print terse where name="guest"': "0 name=guest\n",
        }
        self.assertIsNone(self._befehle(lambda: core._vlan_isolation("guest", "br1"), tabelle))

    def test_wan_kandidat_mit_unsicherem_namen_zaehlt_nicht(self):
        for befehl, zeile in (('/ip dhcp-client print terse where status="bound"', f"0 interface={self.BOESE}\n"),
                              ("/interface pppoe-client print terse", f"0 R name={self.BOESE}\n")):
            with self.subTest(befehl=befehl), patch.object(core, "current_conn", return_value={}):
                with patch.object(core, "router", side_effect=lambda c, z=zeile, b=befehl: z if c == b else ""):
                    with self.assertRaises(routes_basis.WanInterfaceUnavailable):
                        routes_basis._wan_interface()

    def test_wan_kandidat_neben_einem_unsicheren_namen_bleibt_gueltig(self):
        tabelle = {'/ip dhcp-client print terse where status="bound"': f"0 interface={self.BOESE}\n1 interface=ether5\n"}
        with patch.object(core, "current_conn", return_value={}), patch.object(core, "router", side_effect=lambda c: tabelle.get(c, "")):
            self.assertEqual(routes_basis._wan_interface(), "ether5")

    def test_vlan_name_im_gast_eingang(self):
        tabelle = {
            '/interface bridge port print terse where interface="ether2"': "0 interface=ether2 bridge=br pvid=20\n",
            '/interface bridge print terse where name="br"': "0 name=br vlan-filtering=yes pvid=1\n",
            '/interface vlan print terse where interface="br"': f"0 name={self.BOESE} interface=br vlan-id=20\n",
        }
        self.assertIsNone(self._befehle(lambda: core._gast_eingang("ether2"), tabelle))
    def test_bridge_name(self):
        befehl = '/interface bridge port print terse where interface="ether2"'
        with patch.object(core, "router", side_effect=lambda c: f"0 interface=ether2 bridge={self.BOESE}\n" if c == befehl else ""):
            with self.assertRaises(routes_basis.RouterCommandFailed):
                core._bridge_port_of("ether2")
        with patch.object(core, "router", side_effect=lambda c: "0 interface=ether2\n" if c == befehl else ""):
            self.assertIsNone(core._bridge_port_of("ether2"))
        with patch.object(core, "router", side_effect=lambda c: "0 interface=ether2 bridge=br\n" if c == befehl else ""):
            self.assertEqual(core._bridge_port_of("ether2"), "br")


class BefehlSchutzTests(unittest.TestCase):
    """Letzte Schutzschicht in core.router: Was die Struktur eines Befehls aendert, wird nicht gesendet."""

    GUT = (
        '/ip firewall filter print terse where chain=input',
        '/interface list print terse where name="a;b [c] d"',
        '/ip route print terse where dst-address="0.0.0.0/0" and !disabled',
        '/ip dhcp-server lease remove [find mac-address="AA:BB" and address="1.1.1.1"]',
        '/ip firewall nat remove [find where comment~"^cockpit"]',
        ':put [/ip firewall filter print as-value where chain="input"]',
        ':put [:serialize to=json options=json.no-string-conversion value=[/interface print as-value]]',
        ':foreach i in=[/ip firewall filter find where chain="input"] do={:put $i}',
        '/user set [find name="a"] password="p\\"w\\$x;y"',
        '/ip firewall filter add chain=input action=accept comment="x; y [z]"',
    )
    BOESE = (
        ('/interface list print terse where name="x"; /system reboot; :put "y"', "zweite Anweisung"),
        ('/ip dhcp-server lease add server=[/system/reboot] comment=""', "unbekannter Befehl"),
        ('/ip firewall filter add chain=input place-before=[/system reboot]', "unbekannter Befehl"),
        ('/ip address print terse where interface="$[/system reboot]"', "Befehl im Text"),
        ('/ip address print terse where interface="$(/system reboot)"', "Befehl im Text"),
        ('/ip firewall filter set 0 comment=$[/system reboot]', "Befehl als Wert"),
        ('/ip address print terse where interface="x', "offenes Anfuehrungszeichen"),
        ('/ip address print\n/system reboot', "Zeilenumbruch"),
    )

    def test_gueltige_befehle_gehen_durch(self):
        for befehl in self.GUT:
            with self.subTest(befehl=befehl):
                self.assertIsNone(routeros.befehl_unsicher(befehl))

    def test_eingeschleuste_befehle_werden_erkannt(self):
        for befehl, grund in self.BOESE:
            with self.subTest(befehl=befehl):
                self.assertIn(grund, routeros.befehl_unsicher(befehl.replace("\\n", "\n")) or "")

    def test_escape_haelt_den_text_zusammen(self):
        self.assertIsNone(routeros.befehl_unsicher(r'/x y="a\"; b"'))
        self.assertEqual(routeros.befehl_unsicher(r'/x y="a\\"; /system reboot; :put "b"'), "zweite Anweisung")
        self.assertIsNone(routeros.befehl_unsicher(r'/x y="a\\"'))
        self.assertIsNone(routeros.befehl_unsicher(r'/x y="a\$[b]"'))

    def test_schreibende_klammern_gelten_nie_als_lesen(self):
        for befehl in ("/x y=[/file remove find]", "/x y=[/system script run print]", "/x y=[/user set get]"):
            with self.subTest(befehl=befehl):
                self.assertEqual(routeros.befehl_unsicher(befehl), "unbekannter Befehl in Klammern")

    def test_lesende_klammern_gehen_durch(self):
        for befehl in (':put [/ip dns get servers]', ':put [/interface wifi get [find name="w"] security.passphrase]',
                       ':put [/interface wireless security-profiles get [find name="d"] wpa2-pre-shared-key]'):
            with self.subTest(befehl=befehl):
                self.assertIsNone(routeros.befehl_unsicher(befehl))
    def test_core_router_sendet_nichts(self):
        with patch.object(core, "run_command") as senden, patch.object(core, "current_conn", return_value={"host": "h", "user": "u", "password": "p", "ssh_port": 22}):
            with self.assertRaises(routeros.RouterWertUnsicher):
                core.router('/a b="x"; /system reboot; :put "y"')
            senden.assert_not_called()
            core.router('/ip address print terse')
            senden.assert_called_once()


class GastPfadTests(unittest.TestCase):
    """Das Gesamturteil ueber Layer 2 und Layer 3. Die Topologien entsprechen den Szenarien des
    Wahrheitstests mit echten Clients am CHR (2026-11-05), die Zeilen dem Format aus RouterOS."""

    FW4 = "/ip firewall filter print terse where chain=forward"
    FW6 = "/ipv6 firewall filter print terse where chain=forward"

    def _vlan(self, regeln="", regeln6=None, lan="vlan10", gast_pvid="20", ingress="yes", frames="admit-all",
              vlan_ifs=("vlan10", "vlan20"), adressen=("vlan10", "vlan20"), v6=("vlan10", "vlan20"),
              tabelle=None, weitere_ports="", bridge_pvid="1"):
        """Bridge br mit VLAN-Filter: ether3 ist der Gast, ether4 das Haus."""
        ids = {"vlan10": "10", "vlan20": "20"}
        antworten = {
            '/interface bridge port print terse where interface="ether3"':
                f"0 interface=ether3 bridge=br pvid={gast_pvid} ingress-filtering={ingress} frame-types={frames}\n",
            '/interface bridge print terse where name="br"': f"0 name=br vlan-filtering=yes pvid={bridge_pvid}\n",
            '/interface bridge port print terse where bridge="br"':
                "0 interface=ether3 bridge=br\n1 interface=ether4 bridge=br\n" + weitere_ports,
            "/interface bridge port print terse":
                "0 interface=ether3 bridge=br\n1 interface=ether4 bridge=br\n" + weitere_ports,
            '/interface bridge vlan print terse where bridge="br"': tabelle if tabelle is not None else (
                "0 bridge=br vlan-ids=10 current-tagged=br current-untagged=ether4 tagged=br untagged=\n"
                "1 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3 tagged=br untagged=\n"),
            '/interface vlan print terse where interface="br"':
                "".join(f"{i} name={n} interface=br vlan-id={ids[n]}\n" for i, n in enumerate(vlan_ifs)),
            '/interface list member print terse where list="LAN"':
                "".join(f"{i} list=LAN interface={n}\n" for i, n in enumerate(lan.split(","))),
            "/ipv6 settings print": "  disable-ipv6: no\n",
            self.FW4: regeln,
            self.FW6: regeln if regeln6 is None else regeln6,
            '/interface wifi print terse where name="ether3"': "",
            '/interface wireless print terse where name="ether3"': "",
        }
        antworten["/ip address print terse"] = "".join(f"{i} interface={n} address=192.168.{ids[n]}.1/24\n" for i, n in enumerate(adressen))
        antworten["/ipv6 address print terse"] = "".join(f"{i} interface={n} address=fd00:{ids[n]}::1/64\n" for i, n in enumerate(v6))
        for n in adressen:
            antworten[f'/ip address print terse where interface="{n}"'] = f"0 interface={n} address=192.168.{ids[n]}.1/24\n"
        for n in v6:
            antworten[f'/ipv6 address print terse where interface="{n}"'] = (
                f"0 DL address=fe80::1/64 interface={n}\n1 address=fd00:{ids[n]}::1/64 interface={n}\n")
        return antworten

    def _befund(self, antworten, name="ether3"):
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            return core._gast_befund(name)

    SPERRE = "0 chain=forward action=drop in-interface=vlan20 out-interface-list=LAN\n"

    def test_vlan_ohne_firewall_ist_nicht_gruen(self):
        befund = self._befund(self._vlan())
        self.assertEqual(befund["status"], "unknown")
        self.assertIs(befund["schicht2"]["getrennt"], True)
        self.assertIsNone(befund["v4"])

    def test_vlan_mit_sperre_ist_gruen(self):
        self.assertEqual(self._befund(self._vlan(self.SPERRE))["status"], "good")

    def test_bridge_in_lan_aendert_daran_nichts(self):
        self.assertEqual(self._befund(self._vlan(lan="br,vlan10"))["status"], "unknown")
        self.assertEqual(self._befund(self._vlan(self.SPERRE, lan="br,vlan10"))["status"], "good")

    def test_vlan_freigabe_vor_der_sperre_ist_ein_leck(self):
        regeln = "0 chain=forward action=accept in-interface=vlan20 out-interface-list=LAN\n" + self.SPERRE
        self.assertEqual(self._befund(self._vlan(regeln))["status"], "warn")

    def test_sperre_nur_auf_den_port_belegt_nichts(self):
        regeln = "0 chain=forward action=drop in-interface=ether3 out-interface-list=LAN\n"
        self.assertEqual(self._befund(self._vlan(regeln))["status"], "unknown")

    def test_freigabe_nur_auf_den_port_ist_kein_leck(self):
        regeln = "0 chain=forward action=accept in-interface=ether3 out-interface-list=LAN\n" + self.SPERRE
        self.assertEqual(self._befund(self._vlan(regeln))["status"], "good")

    def test_gast_vlan_selbst_in_lan_ist_der_normalfall(self):
        self.assertEqual(self._befund(self._vlan(self.SPERRE, lan="vlan10,vlan20"))["status"], "good")

    def test_nur_gast_vlan_in_lan_belegt_nichts(self):
        self.assertEqual(self._befund(self._vlan(self.SPERRE, lan="vlan20"))["status"], "unknown")

    def test_lan_nur_aus_bridge_ports_belegt_nichts(self):
        self.assertEqual(self._befund(self._vlan(self.SPERRE, lan="ether4"))["status"], "unknown")

    def test_bridge_ports_in_lan_stoeren_die_regelliste_nicht(self):
        # Wie am L009: LAN nennt auch die Ports, die Regel nennt die Liste "vlans".
        regeln = "0 chain=forward action=drop in-interface=vlan20 out-interface-list=vlans\n"
        antworten = self._vlan(regeln, lan="ether4,vlan10,vlan20")
        antworten['/interface list member print terse where list="vlans"'] = "0 list=vlans interface=vlan10\n1 list=vlans interface=vlan20\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_quellliste_wird_gegen_das_vlan_interface_geprueft(self):
        regeln4 = "0 chain=forward action=drop in-interface=vlan20 out-interface-list=LAN src-address-list=g\n"
        antworten = self._vlan(regeln4, regeln6=self.SPERRE)
        antworten['/ip firewall address-list print terse where list="g" and dynamic=no'] = "0 list=g address=192.168.20.0/24\n"
        self.assertEqual(self._befund(antworten)["status"], "good")
        antworten['/ip firewall address-list print terse where list="g" and dynamic=no'] = "0 list=g address=10.0.0.0/8\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_zielliste_privater_netze(self):
        regeln4 = "0 chain=forward action=drop in-interface=vlan20 dst-address-list=privat\n"
        antworten = self._vlan(regeln4, regeln6=self.SPERRE, lan="br,ether4,vlan10,vlan20")
        antworten['/ip firewall address-list print terse where list="privat" and dynamic=no'] = "0 list=privat address=192.168.0.0/16\n"
        self.assertEqual(self._befund(antworten)["status"], "good")
        antworten['/ip firewall address-list print terse where list="privat" and dynamic=no'] = "0 list=privat address=10.0.0.0/8\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_zielliste_ohne_geroutetes_hausnetz_belegt_nichts(self):
        with patch.object(core, "router", side_effect=lambda c: {
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=br\n",
            '/ip firewall address-list print terse where list="a" and dynamic=no': "0 list=a address=192.168.0.0/16\n",
        }.get(c, "")):
            self.assertIsNone(core._address_list_covers_interface("a", "LAN"))

    def test_ipv6_ohne_regel_ist_nicht_gruen(self):
        befund = self._befund(self._vlan(self.SPERRE, regeln6=""))
        self.assertEqual(befund["status"], "unknown")
        self.assertIs(befund["v4"], True)
        self.assertIsNone(befund["v6"])

    def test_ipv6_freigabe_ist_ein_leck(self):
        regeln6 = "0 chain=forward action=accept in-interface=vlan20 out-interface-list=LAN\n"
        self.assertEqual(self._befund(self._vlan(self.SPERRE, regeln6=regeln6))["status"], "warn")

    def test_link_local_zaehlt_nicht_als_routing(self):
        antworten = {'/ipv6 address print terse where interface="x"': "0 DL address=fe80::1/64 interface=x\n"}
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._hat_routbare_adresse("x", "/ipv6 firewall filter"), False)

    def test_abgeschaltete_adresse_zaehlt_nicht_als_routing(self):
        antworten = {'/ip address print terse where interface="x"': "0 X address=192.0.2.1/24 interface=x\n"}
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._hat_routbare_adresse("x", "/ip firewall filter"), False)

    def test_ipv6_paket_fehlt_heisst_keine_adresse(self):
        def stub(command):
            raise core.RouterCommandFailed("bad command name")
        with patch.object(core, "router", side_effect=stub):
            self.assertIs(core._hat_routbare_adresse("x", "/ipv6 firewall filter"), False)
            self.assertIsNone(core._hat_routbare_adresse("x", "/ip firewall filter"))

    def test_gleiches_vlan_mit_lan_port_ist_ein_leck(self):
        tabelle = "0 bridge=br vlan-ids=10 current-tagged=br current-untagged=ether3,ether4\n"
        befund = self._befund(self._vlan(gast_pvid="10", lan="vlan10,ether4", vlan_ifs=("vlan10",), adressen=("vlan10",), v6=("vlan10",), tabelle=tabelle))
        self.assertEqual(befund["status"], "warn")
        self.assertEqual(befund["schicht2"]["beleg"], "vlan_geteilt")

    def test_trunk_ist_kein_leck(self):
        tabelle = ("0 bridge=br vlan-ids=10 current-tagged=br,ether5 current-untagged=ether4\n"
                   "1 bridge=br vlan-ids=20 current-tagged=br,ether5 current-untagged=ether3\n")
        antworten = self._vlan(self.SPERRE, lan="vlan10,ether5", tabelle=tabelle, weitere_ports="2 interface=ether5 bridge=br\n")
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_bridge_in_lan_mit_weiterem_ungetaggten_port_ist_unklar(self):
        # Zweites Gast-Funkband oder Hausnetz-Port? Wenn LAN nur die Bridge nennt, steht das nirgends.
        tabelle = "0 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3,ether4\n"
        befund = self._befund(self._vlan(self.SPERRE, lan="br", tabelle=tabelle))
        self.assertEqual(befund["schicht2"]["beleg"], "vlan_unklar")
        self.assertEqual(befund["status"], "unknown")

    def test_gast_in_der_pvid_der_bridge_mit_bridge_in_lan_ist_ein_leck(self):
        tabelle = "0 bridge=br vlan-ids=1 current-untagged=br,ether3\n"
        befund = self._befund(self._vlan(gast_pvid="1", lan="br", tabelle=tabelle, vlan_ifs=(), adressen=(), v6=()))
        self.assertEqual(befund["status"], "warn")

    def test_gast_in_der_pvid_der_bridge_routet_ueber_die_bridge(self):
        antworten = self._vlan(gast_pvid="1", vlan_ifs=(), adressen=(), v6=())
        antworten['/ip address print terse where interface="br"'] = "0 interface=br address=192.168.1.1/24\n"
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertEqual(core._gast_eingang("ether3"), {"br"})

    def test_ohne_ingress_filter_taggt_sich_der_gast_selbst_ins_hausnetz(self):
        befund = self._befund(self._vlan(self.SPERRE, ingress="no"))
        self.assertEqual(befund["status"], "warn")
        self.assertEqual(befund["schicht2"]["beleg"], "vlan_geteilt")

    def test_ohne_ingress_filter_aber_nur_ungetaggt_ist_dicht(self):
        antworten = self._vlan(self.SPERRE, ingress="no", frames="admit-only-untagged-and-priority-tagged")
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_nur_getaggt_ohne_ingress_filter_ist_nicht_dicht(self):
        antworten = self._vlan(self.SPERRE, ingress="no", frames="admit-only-vlan-tagged")
        self.assertEqual(self._befund(antworten)["status"], "warn")

    def test_fehlendes_ingress_feld_bleibt_unklar(self):
        antworten = self._vlan(self.SPERRE)
        antworten['/interface bridge port print terse where interface="ether3"'] = "0 interface=ether3 bridge=br pvid=20\n"
        befund = self._befund(antworten)
        self.assertEqual(befund["status"], "unknown")
        self.assertEqual(befund["schicht2"]["beleg"], "vlan_unklar")

    def test_insel_ohne_router_und_ohne_weg_hinaus(self):
        tabelle = ("0 bridge=br vlan-ids=10 current-tagged=br current-untagged=ether4\n"
                   "1 D bridge=br vlan-ids=20 current-untagged=ether3\n")
        befund = self._befund(self._vlan(vlan_ifs=("vlan10",), adressen=("vlan10",), v6=("vlan10",), tabelle=tabelle))
        self.assertEqual(befund["status"], "good")
        self.assertEqual(befund["v4"], "insel")

    def test_trunk_ohne_router_hier_verweist_auf_das_andere_geraet(self):
        tabelle = ("0 bridge=br vlan-ids=10 current-tagged=br,ether5 current-untagged=ether4\n"
                   "1 bridge=br vlan-ids=20 current-tagged=ether5 current-untagged=ether3\n")
        antworten = self._vlan(vlan_ifs=("vlan10",), adressen=("vlan10",), v6=("vlan10",), tabelle=tabelle, weitere_ports="2 interface=ether5 bridge=br\n")
        befund = self._befund(antworten)
        self.assertEqual(befund["status"], "unknown")
        self.assertEqual(befund["v4"], "extern")
        self.assertEqual(befund["v6"], "extern")

    def test_vlan_interface_ohne_adresse_routet_nicht(self):
        # Wie am hAP ax2: VLAN-Interface Guest ohne IP, Router ist ein anderes Geraet.
        tabelle = ("0 bridge=br vlan-ids=10 current-tagged=br,ether5 current-untagged=ether4\n"
                   "1 bridge=br vlan-ids=20 current-tagged=br,ether5 current-untagged=ether3\n")
        antworten = self._vlan(adressen=("vlan10",), v6=("vlan10",), tabelle=tabelle, weitere_ports="2 interface=ether5 bridge=br\n")
        self.assertEqual(self._befund(antworten)["v4"], "extern")

    def test_nur_ipv6_extern_wird_nicht_zu_keine_adresse(self):
        tabelle = ("0 bridge=br vlan-ids=10 current-tagged=br,ether5 current-untagged=ether4\n"
                   "1 bridge=br vlan-ids=20 current-tagged=ether5 current-untagged=ether3\n")
        antworten = self._vlan(self.SPERRE, vlan_ifs=("vlan10",), adressen=("vlan10",), v6=("vlan10",), tabelle=tabelle, weitere_ports="2 interface=ether5 bridge=br\n")
        self.assertEqual(self._befund(antworten)["v6"], "extern")

    def test_wlan_mit_eigenem_vlan_bleibt_unklar(self):
        for zeile in ("0 name=ether3 datapath.vlan-id=30\n", "0 name=ether3 datapath=dp-gast\n"):
            antworten = self._vlan(self.SPERRE)
            antworten['/interface wifi print terse where name="ether3"'] = zeile
            with self.subTest(zeile=zeile):
                self.assertEqual(self._befund(antworten)["status"], "unknown")
        antworten = self._vlan(self.SPERRE)
        antworten['/interface wireless print terse where name="ether3"'] = "0 name=ether3 vlan-mode=use-tag vlan-id=30\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_wlan_ohne_eigenes_vlan_nutzt_die_pvid(self):
        antworten = self._vlan(self.SPERRE)
        antworten['/interface wifi print terse where name="ether3"'] = "0 name=ether3 datapath.bridge=br configuration.mode=ap\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_wlan_nicht_lesbar_bleibt_unklar(self):
        def stub(command):
            if "/interface wifi" in command:
                raise core.RouterUnreachable("weg")
            return ""
        with patch.object(core, "router", side_effect=stub):
            self.assertIsNone(core._wlan_setzt_vlan("ether3"))

    def test_fehlendes_wifi_menue_ist_kein_vlan(self):
        def stub(command):
            raise core.RouterCommandFailed("bad command name")
        with patch.object(core, "router", side_effect=stub):
            self.assertIs(core._wlan_setzt_vlan("ether3"), False)

    def _eigene_bridge(self, regeln="", adresse=True, weitere=""):
        antworten = {
            '/interface bridge port print terse where interface="ether3"': "0 interface=ether3 bridge=brg pvid=1\n",
            '/interface bridge print terse where name="brg"': "0 name=brg vlan-filtering=no pvid=1\n",
            '/interface bridge port print terse where bridge="brg"': "0 interface=ether3 bridge=brg\n" + weitere,
            "/interface bridge port print terse": "0 interface=ether3 bridge=brg\n" + weitere,
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=ether4\n",
            "/ipv6 settings print": "  disable-ipv6: yes\n",
            self.FW4: regeln,
        }
        if adresse:
            antworten['/ip address print terse where interface="brg"'] = "0 interface=brg address=192.168.20.1/24\n"
        return antworten

    def test_eigene_bridge(self):
        self.assertEqual(self._befund(self._eigene_bridge())["status"], "unknown")
        self.assertEqual(self._befund(self._eigene_bridge("0 chain=forward action=drop in-interface=brg out-interface-list=LAN\n"))["status"], "good")
        self.assertEqual(self._befund(self._eigene_bridge("0 chain=forward action=drop in-interface=ether3 out-interface-list=LAN\n"))["status"], "unknown")
        self.assertEqual(self._befund(self._eigene_bridge(adresse=False))["v4"], "insel")
        self.assertEqual(self._befund(self._eigene_bridge(adresse=False, weitere="1 interface=ether5 bridge=brg\n"))["v4"], "extern")

    def test_quellliste_mit_dem_eingang_gilt_auch_an_der_bridge(self):
        antworten = self._eigene_bridge("0 chain=forward action=drop in-interface-list=g out-interface-list=LAN\n")
        antworten['/interface list member print terse where list="g"'] = "0 list=g interface=brg\n"
        self.assertEqual(self._befund(antworten)["status"], "good")
        antworten['/interface list member print terse where list="g"'] = "0 list=g interface=ether3\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_negierter_eingang(self):
        antworten = self._eigene_bridge("0 chain=forward action=accept in-interface=!brg out-interface-list=LAN\n"
                                        "1 chain=forward action=drop in-interface=brg out-interface-list=LAN\n")
        self.assertEqual(self._befund(antworten)["status"], "good")
        antworten = self._eigene_bridge("0 chain=forward action=accept in-interface=!ether7 out-interface-list=LAN\n"
                                        "1 chain=forward action=drop in-interface=brg out-interface-list=LAN\n")
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def _flach(self, regeln="", filter_regeln=""):
        return {
            '/interface bridge port print terse where interface="ether3"': "0 interface=ether3 bridge=br pvid=1\n",
            '/interface bridge print terse where name="br"': "0 name=br vlan-filtering=no pvid=1\n",
            '/interface bridge port print terse where bridge="br"': "0 interface=ether3 bridge=br\n1 interface=ether4 bridge=br\n",
            "/interface bridge port print terse": "0 interface=ether3 bridge=br\n1 interface=ether4 bridge=br\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=br\n",
            "/interface bridge settings print": "  use-ip-firewall: no\n",
            "/interface bridge filter print terse where chain=forward": filter_regeln,
            '/ip address print terse where interface="br"': "0 interface=br address=192.168.10.1/24\n",
            "/ipv6 settings print": "  disable-ipv6: yes\n",
            self.FW4: regeln,
        }

    FILTER = "0 chain=forward action=drop in-interface=ether3 out-interface=ether4\n"

    def test_flach_ist_ein_leck(self):
        befund = self._befund(self._flach())
        self.assertEqual(befund["status"], "warn")
        self.assertEqual(befund["schicht2"]["beleg"], "bypass")

    def test_flach_mit_filter_laesst_den_umweg_ueber_den_router_offen(self):
        self.assertEqual(self._befund(self._flach(filter_regeln=self.FILTER))["status"], "unknown")

    def test_flach_mit_filter_und_forward_sperre_ist_gruen(self):
        regeln = "0 chain=forward action=drop in-interface=br out-interface-list=LAN\n"
        self.assertEqual(self._befund(self._flach(regeln, self.FILTER))["status"], "good")

    def test_flach_mit_filter_und_freigabe_ist_ein_leck(self):
        regeln = "0 chain=forward action=accept in-interface=br out-interface-list=LAN\n"
        self.assertEqual(self._befund(self._flach(regeln, self.FILTER))["status"], "warn")

    def test_vlan_geteilt_mit_filter_und_sperre(self):
        tabelle = "0 bridge=br vlan-ids=10 current-tagged=br current-untagged=ether3,ether4\n"
        antworten = self._vlan("0 chain=forward action=drop in-interface=vlan10 out-interface-list=LAN\n", gast_pvid="10", lan="vlan10,ether4", vlan_ifs=("vlan10",), adressen=("vlan10",), v6=("vlan10",), tabelle=tabelle)
        antworten["/interface bridge filter print terse where chain=forward"] = self.FILTER
        befund = self._befund(antworten)
        self.assertEqual(befund["schicht2"]["beleg"], "filter")
        self.assertEqual(befund["status"], "good")

    def test_ohne_vlan_filter_erreicht_der_gast_die_vlan_interfaces(self):
        antworten = self._flach("0 chain=forward action=drop in-interface=br out-interface-list=LAN\n")
        antworten['/interface list member print terse where list="LAN"'] = "0 list=LAN interface=vlan10\n"
        antworten['/interface vlan print terse where interface="br"'] = "0 name=vlan10 interface=br vlan-id=10\n"
        befund = self._befund(antworten)
        self.assertEqual(befund["status"], "warn")
        self.assertEqual(befund["schicht2"]["beleg"], "bypass")

    def test_vlan_filter_verhindert_diesen_bypass(self):
        antworten = {
            '/interface bridge port print terse where interface="g"': "0 interface=g bridge=br\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=vlan10\n",
            '/interface vlan print terse where interface="br"': "0 name=vlan10 interface=br vlan-id=10\n",
            '/interface bridge print terse where name="br"': "0 name=br vlan-filtering=yes\n",
        }
        with patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertIs(core._guest_bridge_bypass("g"), False)

    def test_bypass_vlan_abfrage_fehlgeschlagen_bleibt_unklar(self):
        def stub(command):
            if command.startswith("/interface vlan"):
                raise core.RouterCommandFailed("failure")
            return {'/interface bridge port print terse where interface="g"': "0 interface=g bridge=br\n",
                    '/interface list member print terse where list="LAN"': "0 list=LAN interface=x\n"}.get(command, "")
        with patch.object(core, "router", side_effect=stub):
            self.assertIsNone(core._guest_bridge_bypass("g"))

    def test_normalfall_ohne_bridge(self):
        antworten = {
            '/interface print terse where name="wlan-gast"': "0 name=wlan-gast\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
            "/ipv6 settings print": "  disable-ipv6: no\n",
            self.FW4: "0 chain=forward action=drop in-interface=wlan-gast out-interface-list=LAN\n",
            self.FW6: "0 chain=forward action=drop in-interface=wlan-gast out-interface-list=LAN\n",
        }
        befund = self._befund(antworten, name="wlan-gast")
        self.assertEqual(befund["status"], "good")
        self.assertEqual(befund["schicht2"]["beleg"], "keine_bridge")

    def test_lesefehler_bleiben_unklar(self):
        def stub(ziel):
            def innen(command):
                if ziel in command:
                    raise core.RouterCommandFailed("failure")
                return self._vlan(self.SPERRE).get(command, "")
            return innen
        for ziel in ('where interface="ether3"', '/interface bridge print', 'where interface="vlan20"', 'print terse where interface="br"', '/interface bridge port print terse', '/interface bridge vlan'):
            with self.subTest(ziel=ziel), patch.object(core, "router", side_effect=stub(ziel)):
                self.assertNotEqual(core._gast_befund("ether3")["status"], "good")

    def test_weiterer_weg_im_zweifel_ja(self):
        def weg(command):
            raise core.RouterCommandFailed("failure")
        with patch.object(core, "router", side_effect=weg):
            self.assertIs(core._gast_hat_weiteren_weg("g", "br"), True)
        with patch.object(core, "router", return_value=""):
            self.assertIs(core._gast_hat_weiteren_weg("g", "br"), True)

    def test_pro_karte_nutzt_dasselbe_urteil(self):
        # Vorher las die Karte nur die IPv4-Regeln und meldete "bestaetigt", wo der Check warnte.
        for regeln6, erwartet in (("0 chain=forward action=accept in-interface=wlan out-interface-list=LAN\n", False),
                                  ("", None),
                                  ("0 chain=forward action=drop in-interface=wlan out-interface-list=LAN\n", True)):
            antworten = {
                '/interface print terse where name="wlan"': "0 name=wlan\n",
                "/ipv6 address print terse": "0 interface=bridge address=fd00::1/64\n",
                '/interface list member print terse where list="LAN"': "0 list=LAN interface=bridge\n",
                "/ipv6 settings print": "  disable-ipv6: no\n",
                self.FW4: "0 chain=forward action=drop in-interface=wlan out-interface-list=LAN\n",
                self.FW6: regeln6,
                '/interface wireless print terse where name="wlan"': '0 name=wlan ssid=Gast\n',
            }
            with self.subTest(erwartet=erwartet), patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")), \
                    patch.object(core, "_wireless_driver", return_value="wireless"):
                self.assertIs(core._guest_row("wlan")[1]["isolated"], erwartet)

    def test_unbekannter_name_ist_nicht_getrennt(self):
        # Wie am hAP ax2: terse zeigt das Rohbyte 0xB2 als "axB2". Regel und Abfrage passen zum falschen
        # Namen, der Gast haengt in Wahrheit an der Haus-Bridge (im Labor gemessen, Szenario name-mit-byte).
        antworten = {
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=br\n",
            "/ipv6 settings print": "  disable-ipv6: yes\n",
            self.FW4: "0 chain=forward action=drop in-interface=gastB2 out-interface-list=LAN\n",
        }
        befund = self._befund(antworten, name="gastB2")
        self.assertEqual(befund["status"], "unknown")
        self.assertIsNone(befund["schicht2"]["getrennt"])
        self.assertEqual(befund["schicht2"]["beleg"], "name_unbekannt")

    def test_unlesbare_interface_liste_ist_nicht_getrennt(self):
        with self._router({}, fehler=('/interface print terse where name="ether3"',)):
            schicht2 = core._gast_layer2("ether3")
        self.assertIsNone(schicht2["getrennt"])
        self.assertEqual(schicht2["beleg"], "unlesbar")

    def test_check_nennt_den_unbekannten_namen(self):
        self.assertIn("nicht zu finden", self._check("unknown", beleg="name_unbekannt")["detail"])

    def _nicht_wan(self, regel, lan="vlan10"):
        antworten = self._vlan(regel, lan=lan)
        antworten['/interface list member print terse where list="WAN"'] = "0 list=WAN interface=ether1\n"
        return antworten

    def test_sperre_alles_ausser_wan_als_liste(self):
        regel = "0 chain=forward action=drop in-interface=vlan20 out-interface-list=!WAN\n"
        self.assertEqual(self._befund(self._nicht_wan(regel))["status"], "good")

    def test_sperre_alles_ausser_wan_als_interface(self):
        # Form der Regel am L009, dort mit connection-state=new.
        regel = ("0 chain=forward action=drop connection-state=invalid\n"
                 "1 chain=forward action=drop connection-state=new in-interface=vlan20 out-interface=!ether1\n")
        self.assertEqual(self._befund(self._nicht_wan(regel))["status"], "good")

    def test_fasttrack_nur_intern_oeffnet_nichts(self):
        # Form der Regel am L009 aus dem CAKE-Umbau: betrifft nur bestehende Verbindungen.
        for eingang in ("in-interface=!ether1 out-interface=!ether1", "in-interface-list=!WAN"):
            with self.subTest(eingang=eingang):
                regel = (f"0 chain=forward action=fasttrack-connection connection-state=established,related,untracked {eingang}\n"
                         "1 chain=forward action=drop connection-state=invalid\n"
                         "2 chain=forward action=drop connection-state=new in-interface=vlan20 out-interface=!ether1\n")
                self.assertEqual(self._befund(self._nicht_wan(regel))["status"], "good")

    def test_freigabe_mit_negiertem_eingang_bleibt_unklar_wenn_sie_oeffnen_kann(self):
        for zustand in ("", "connection-state=new", "connection-state=established,new", "connection-state=!invalid", "connection-state=invalid"):
            with self.subTest(zustand=zustand):
                regel = (f"0 chain=forward action=accept in-interface=!ether1 {zustand}\n"
                         "1 chain=forward action=drop connection-state=invalid\n"
                         "2 chain=forward action=drop connection-state=new in-interface=vlan20 out-interface=!ether1\n")
                self.assertEqual(self._befund(self._nicht_wan(regel))["status"], "unknown")

    def test_nur_bestehende_verbindungen_zaehlen_nicht_ohne_verlaessliches_tracking(self):
        # Mit notrack wird Gastverkehr "untracked", diese Freigabe laesst ihn also durch. Die Sperre dahinter
        # greift ohne Zustand und wuerde sonst Gruen ergeben.
        regel = ("0 chain=forward action=accept connection-state=established,related,untracked in-interface=!ether1\n"
                 "1 chain=forward action=drop in-interface=vlan20 out-interface=!ether1\n")
        antworten = self._nicht_wan(regel)
        self.assertEqual(self._befund(antworten)["status"], "good")
        antworten["/ip firewall raw print terse"] = "0 chain=prerouting action=notrack in-interface=vlan20\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    WAN_MEMBER = '/interface list member print terse where list="WAN"'

    def _wan(self, regeln, adresse="192.168.178.2/24", wan="ether1", familie="/ip address print terse"):
        antworten = self._vlan(regeln)
        antworten[self.WAN_MEMBER] = "".join(f"{i} list=WAN interface={n}\n" for i, n in enumerate(wan.split(",")))
        antworten[familie] += f"8 interface=ether1 address={adresse}\n"
        return antworten

    def test_netz_hinter_dem_wan_ist_durch_sperre_auf_lan_nicht_gedeckt(self):
        befund = self._befund(self._wan(self.SPERRE))
        self.assertEqual(befund["status"], "unknown")
        self.assertIs(befund["hinter_router"], True)

    def test_oeffentliche_wan_adresse_bleibt_ausserhalb(self):
        for adresse in ("87.1.2.3/24", "100.64.1.2/24", "172.32.0.1/24", "11.0.0.1/24"):
            with self.subTest(adresse=adresse):
                befund = self._befund(self._wan(self.SPERRE, adresse=adresse))
                self.assertEqual(befund["status"], "good")
                self.assertIs(befund["hinter_router"], False)

    def test_private_wan_netze_alle_drei(self):
        for adresse in ("10.0.0.2/24", "172.16.0.2/24", "172.31.255.2/24", "192.168.178.2/24"):
            with self.subTest(adresse=adresse):
                self.assertEqual(self._befund(self._wan(self.SPERRE, adresse=adresse))["status"], "unknown")

    def test_sperre_ausser_oeffentlichem_ausgang_deckt_privates_wan(self):
        # Form am L009: ether1 mit privater Adresse zum Modem, Internet ueber pppoe-out1.
        regel = "0 chain=forward action=drop in-interface=vlan20 out-interface=!pppoe-out1\n"
        antworten = self._wan(regel, wan="ether1,pppoe-out1")
        antworten["/ip address print terse"] += "9 interface=pppoe-out1 address=87.1.2.3/32\n"
        befund = self._befund(antworten)
        self.assertEqual(befund["status"], "good")
        self.assertIs(befund["hinter_router"], True)

    def test_sperre_ausser_privatem_wan_deckt_es_nicht(self):
        regel = "0 chain=forward action=drop in-interface=vlan20 out-interface=!ether1\n"
        self.assertEqual(self._befund(self._wan(regel))["status"], "unknown")

    def test_freigabe_ins_private_wan_ist_unklar_nicht_rot(self):
        for ziel in ("out-interface=ether1", "out-interface-list=WAN"):
            with self.subTest(ziel=ziel):
                regel = f"0 chain=forward action=accept in-interface=vlan20 {ziel}\n" + self.SPERRE
                self.assertEqual(self._befund(self._wan(regel))["status"], "unknown")

    def test_freigabe_ins_oeffentliche_wan_bleibt_gruen(self):
        for ziel in ("out-interface=ether1", "out-interface-list=WAN"):
            with self.subTest(ziel=ziel):
                regel = f"0 chain=forward action=accept in-interface=vlan20 {ziel}\n" + self.SPERRE
                self.assertEqual(self._befund(self._wan(regel, adresse="87.1.2.3/24"))["status"], "good")

    def test_privates_wan_auch_bei_ipv6(self):
        antworten = self._wan(self.SPERRE, adresse="fd12::2/64", familie="/ipv6 address print terse")
        befund = self._befund(antworten)
        self.assertIsNone(befund["v6"])
        self.assertEqual(befund["status"], "unknown")

    def test_freigabe_auf_oeffentliches_ziel_ausserhalb_von_wan_ist_unklar(self):
        # Selbst geschriebene Firewall ohne Liste WAN. Der Satz "ins Hausnetz" waere falsch.
        antworten = self._vlan("0 chain=forward action=accept in-interface=vlan20 out-interface=pppoe-out1\n" + self.SPERRE)
        antworten["/ip address print terse"] += "8 interface=pppoe-out1 address=87.1.2.3/32\n"
        antworten["/ipv6 address print terse"] += "8 interface=pppoe-out1 address=2a01::1/64\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_freigabe_auf_liste_mit_oeffentlichem_ziel_ist_unklar(self):
        antworten = self._vlan("0 chain=forward action=accept in-interface=vlan20 out-interface-list=INTERNET\n" + self.SPERRE)
        antworten['/interface list member print terse where list="INTERNET"'] = "0 list=INTERNET interface=pppoe-out1\n"
        antworten["/ip address print terse"] += "8 interface=pppoe-out1 address=87.1.2.3/32\n"
        antworten["/ipv6 address print terse"] += "8 interface=pppoe-out1 address=2a01::1/64\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_freigabe_auf_liste_mit_privatem_ziel_bleibt_ein_leck(self):
        antworten = self._vlan("0 chain=forward action=accept in-interface=vlan20 out-interface-list=HOME\n" + self.SPERRE, lan="br")
        antworten['/interface list member print terse where list="HOME"'] = "0 list=HOME interface=vlan10\n"
        self.assertEqual(self._befund(antworten)["status"], "warn")

    def test_leere_lan_liste_belegt_keine_vlan_trennung(self):
        tabelle = "0 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3,ether4 tagged=br untagged=ether4\n"
        antworten = self._vlan("0 chain=forward action=drop in-interface=vlan20\n", tabelle=tabelle)
        antworten['/interface list member print terse where list="LAN"'] = ""
        self.assertNotEqual(self._befund(antworten)["status"], "good")

    def _sammelzeile(self, tabelle, lan="vlan10", ether4_pvid="10", frames="admit-all"):
        antworten = self._vlan(self.SPERRE, lan=lan, tabelle=tabelle, frames=frames)
        antworten['/interface bridge port print terse where bridge="br"'] = (
            f"0 interface=ether3 bridge=br pvid=20\n1 interface=ether4 bridge=br pvid={ether4_pvid}\n2 interface=ether5 bridge=br pvid=1\n")
        return antworten

    def test_eigene_vlan_zeile_mit_festem_gastport_ist_kein_leck(self):
        tabelle = ("0 bridge=br vlan-ids=10 tagged=br untagged=ether4 current-tagged=br current-untagged=ether4\n"
                   "1 bridge=br vlan-ids=20 tagged=br untagged=ether3 current-tagged=br current-untagged=ether3\n")
        self.assertEqual(self._befund(self._vlan(self.SPERRE, tabelle=tabelle))["status"], "good")

    def test_sammelzeile_mit_untagged_hausport_ist_ein_leck(self):
        tabelle = "0 bridge=br vlan-ids=10,20 tagged=br untagged=ether3,ether4 current-tagged=br current-untagged=ether3,ether4\n"
        self.assertEqual(self._befund(self._sammelzeile(tabelle))["status"], "warn")

    def test_sammelzeile_mit_getaggtem_gastport_ist_ein_leck(self):
        tabelle = "0 bridge=br vlan-ids=10,20 tagged=br,ether3 untagged= current-tagged=br,ether3 current-untagged=\n"
        self.assertEqual(self._befund(self._sammelzeile(tabelle))["status"], "warn")

    def test_sammelzeile_getaggt_mit_nur_untagged_frames_ist_kein_beleg_fuer_ein_leck(self):
        tabelle = "0 bridge=br vlan-ids=10,20 tagged=br,ether3 untagged= current-tagged=br,ether3 current-untagged=\n"
        self.assertEqual(self._befund(self._sammelzeile(tabelle, frames="admit-only-untagged-and-priority-tagged"))["status"], "good")

    def test_sammelzeile_als_trunk_ohne_leck(self):
        # Die Access-Ports stehen nur ueber ihre PVID in der Zeile, jeder in seinem eigenen VLAN.
        tabelle = "0 bridge=br vlan-ids=10,20 tagged=br,ether5 untagged= current-tagged=br,ether5 current-untagged=ether3,ether4\n"
        self.assertEqual(self._befund(self._sammelzeile(tabelle, lan="vlan10,ether4"))["status"], "good")

    def test_sammelzeile_als_trunk_mit_hausport_im_gastvlan_ist_ein_leck(self):
        tabelle = "0 bridge=br vlan-ids=10,20 tagged=br,ether5 untagged= current-tagged=br,ether5 current-untagged=ether3,ether4\n"
        self.assertEqual(self._befund(self._sammelzeile(tabelle, lan="vlan10,ether4", ether4_pvid="20"))["status"], "warn")

    def test_lesefehler_am_wlan_ist_kein_nein(self):
        antworten = self._vlan(self.SPERRE)
        fehler = core.RouterCommandFailed("failure: kein Zugriff")
        def router(c):
            if c == "/interface wifi access-list print terse":
                raise fehler
            return antworten.get(c, "")
        with patch.object(core, "router", side_effect=router):
            self.assertIsNone(core._wlan_setzt_vlan("ether3"))

    def test_fehlendes_wlan_menue_ist_ein_nein(self):
        antworten = self._vlan(self.SPERRE)
        def router(c):
            if "wifi" in c:
                raise core.RouterCommandFailed("bad command name wifi (line 1 column 12)")
            return antworten.get(c, "")
        with patch.object(core, "router", side_effect=router):
            self.assertIs(core._wlan_setzt_vlan("ether3"), False)

    def test_lesefehler_am_offload_ist_kein_nein(self):
        antworten = self._vlan(self.SPERRE)
        def router(c):
            if c == "/interface ethernet switch print terse":
                raise core.RouterCommandFailed("failure: kein Zugriff")
            return antworten.get(c, "")
        with patch.object(core, "router", side_effect=router):
            self.assertEqual(core._gast_befund("ether3")["status"], "unknown")

    def test_fehlendes_switch_menue_ist_kein_offload(self):
        antworten = self._vlan(self.SPERRE)
        def router(c):
            if c == "/interface ethernet switch print terse":
                raise core.RouterCommandFailed("bad command name switch (line 1 column 20)")
            return antworten.get(c, "")
        with patch.object(core, "router", side_effect=router):
            self.assertEqual(core._gast_befund("ether3")["status"], "good")

    def test_unlesbare_wan_adresse_zaehlt_als_privat(self):
        self.assertEqual(self._befund(self._wan(self.SPERRE, adresse="kaputt"))["status"], "unknown")

    def test_freigabe_ins_private_wan_bleibt_unklar_trotz_deckender_sperre(self):
        regel = ("0 chain=forward action=accept in-interface=vlan20 out-interface=ether1\n"
                 "1 chain=forward action=drop in-interface=vlan20 out-interface=!pppoe-out1\n")
        antworten = self._wan(regel, wan="ether1,pppoe-out1")
        antworten["/ip address print terse"] += "9 interface=pppoe-out1 address=87.1.2.3/32\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_freigabe_auf_liste_oeffentlich_bleibt_unklar_trotz_vollsperre(self):
        antworten = self._vlan("0 chain=forward action=accept in-interface=vlan20 out-interface-list=INTERNET\n"
                               "1 chain=forward action=drop in-interface=vlan20\n")
        antworten['/interface list member print terse where list="INTERNET"'] = "0 list=INTERNET interface=pppoe-out1\n"
        antworten["/ip address print terse"] += "8 interface=pppoe-out1 address=87.1.2.3/32\n"
        antworten["/ipv6 address print terse"] += "8 interface=pppoe-out1 address=2a01::1/64\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_freigabe_auf_lan_liste_bleibt_ein_leck_auch_mit_oeffentlichem_mitglied(self):
        antworten = self._vlan("0 chain=forward action=accept in-interface=vlan20 out-interface-list=LAN\n" + self.SPERRE, lan="ether9,pppoe-out1")
        antworten["/ip address print terse"] += "8 interface=pppoe-out1 address=87.1.2.3/32\n"
        antworten["/ipv6 address print terse"] += "8 interface=pppoe-out1 address=2a01::1/64\n"
        self.assertEqual(self._befund(antworten)["status"], "warn")

    def test_sammelzeile_fester_hausport_ist_ein_leck_auch_wenn_der_gast_nur_ueber_pvid_dabei_ist(self):
        tabelle = "0 bridge=br vlan-ids=10,20 tagged=br untagged=ether4 current-tagged=br current-untagged=ether3,ether4\n"
        self.assertEqual(self._befund(self._sammelzeile(tabelle))["status"], "warn")

    def test_sammelzeile_abgeschalteter_port_zaehlt_nicht(self):
        tabelle = "0 bridge=br vlan-ids=10,20 tagged=br untagged=ether9 current-tagged=br current-untagged=ether3\n"
        antworten = self._sammelzeile(tabelle)
        antworten['/interface bridge port print terse where bridge="br"'] += "3 X interface=ether9 bridge=br pvid=10\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_sammelzeile_ohne_lesbare_pvids_ist_unklar(self):
        tabelle = "0 bridge=br vlan-ids=10,20 tagged=br,ether5 untagged= current-tagged=br,ether5 current-untagged=ether3,ether4\n"
        antworten = self._sammelzeile(tabelle, lan="vlan10,ether4")
        with patch.object(core, "_port_pvids", return_value=None), patch.object(core, "router", side_effect=lambda c: antworten.get(c, "")):
            self.assertEqual(core._gast_befund("ether3")["status"], "unknown")

    def test_auch_no_such_command_heisst_menue_fehlt(self):
        self.assertTrue(core._befehl_fehlt(core.RouterCommandFailed("no such command prefix")))
        self.assertTrue(core._befehl_fehlt(core.RouterCommandFailed("bad command name wifi")))
        self.assertFalse(core._befehl_fehlt(core.RouterCommandFailed("failure: kein Zugriff")))

    def test_sperre_alles_ausser_hausnetz_belegt_nichts(self):
        for regel in ("0 chain=forward action=drop in-interface=vlan20 out-interface=!vlan10\n",
                      "0 chain=forward action=drop in-interface=vlan20 out-interface-list=!LAN\n"):
            with self.subTest(regel=regel):
                self.assertEqual(self._befund(self._nicht_wan(regel))["status"], "unknown")

    def test_liste_ueberschneidet_das_hausnetz(self):
        regel = "0 chain=forward action=drop in-interface=vlan20 out-interface-list=!WAN\n"
        self.assertEqual(self._befund(self._nicht_wan(regel, lan="vlan10,ether1"))["status"], "unknown")

    def test_sperre_alles_ausser_wan_ohne_hausnetz_belegt_nichts(self):
        for regel in ("0 chain=forward action=drop in-interface=vlan20 out-interface=!ether1\n",
                      "0 chain=forward action=drop in-interface=vlan20 out-interface-list=!WAN\n"):
            with self.subTest(regel=regel):
                self.assertEqual(self._befund(self._nicht_wan(regel, lan="vlan20"))["status"], "unknown")

    def test_freigabe_alles_ausser_wan_bleibt_unklar(self):
        for regel in ("0 chain=forward action=accept in-interface=vlan20 out-interface=!ether1\n" + self.SPERRE,
                      "0 chain=forward action=accept in-interface=vlan20 out-interface-list=!WAN\n" + self.SPERRE):
            with self.subTest(regel=regel):
                self.assertEqual(self._befund(self._nicht_wan(regel))["status"], "unknown")

    def test_teilsperre_alles_ausser_wan_belegt_nichts(self):
        regel = "0 chain=forward action=drop protocol=tcp in-interface=vlan20 out-interface=!ether1\n"
        self.assertEqual(self._befund(self._nicht_wan(regel))["status"], "unknown")

    # Befunde der beiden Pruefer vom 2026-11-05. Der Wahrheitstest misst dieselben Faelle mit echten Clients.

    INVALID = "0 chain=forward action=drop connection-state=invalid\n"
    NEU = "1 chain=forward action=drop connection-state=new in-interface=vlan20 out-interface-list=LAN\n"

    def test_lan_ohne_das_geroutete_hausnetz_belegt_nichts(self):
        self.assertEqual(self._befund(self._vlan(self.SPERRE, lan="br"))["status"], "unknown")

    def test_sperre_alles_ausser_hausnetz_bei_lan_nur_bridge(self):
        regel = "0 chain=forward action=drop in-interface=vlan20 out-interface=!vlan10\n"
        self.assertEqual(self._befund(self._vlan(regel, lan="br"))["status"], "unknown")
        antworten = self._vlan("0 chain=forward action=drop in-interface=vlan20 out-interface-list=!H\n", lan="br")
        antworten['/interface list member print terse where list="H"'] = "0 list=H interface=vlan10\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_freigabe_auf_liste_ausserhalb_von_lan_ist_ein_leck(self):
        regeln = "0 chain=forward action=accept in-interface=vlan20 out-interface-list=H\n" + self.SPERRE
        antworten = self._vlan(regeln, lan="br")
        antworten['/interface list member print terse where list="H"'] = "0 list=H interface=vlan10\n"
        self.assertEqual(self._befund(antworten)["status"], "warn")

    def test_zielliste_muss_auch_netze_ausserhalb_von_lan_abdecken(self):
        regel4 = "0 chain=forward action=drop in-interface=vlan20 dst-address-list=p\n"
        antworten = self._vlan(regel4, regeln6=self.SPERRE, lan="vlan10")
        antworten["/ip address print terse"] += "9 interface=vlan30 address=10.3.0.1/24\n"
        antworten['/ip address print terse where interface="vlan30"'] = "0 interface=vlan30 address=10.3.0.1/24\n"
        antworten['/ip firewall address-list print terse where list="p" and dynamic=no'] = "0 list=p address=192.168.0.0/16\n"
        self.assertNotEqual(self._befund(antworten)["status"], "good")

    def test_gast_port_getaggt_in_fremdem_vlan_ist_ein_leck(self):
        tabelle = ("0 bridge=br vlan-ids=10 current-tagged=br,ether3 current-untagged=ether4\n"
                   "1 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3\n")
        befund = self._befund(self._vlan(self.SPERRE, tabelle=tabelle))
        self.assertEqual(befund["status"], "warn")
        self.assertEqual(befund["schicht2"]["beleg"], "vlan_geteilt")

    def test_gast_port_in_fremdem_vlan_mit_nur_ungetaggt_ist_dicht(self):
        tabelle = ("0 bridge=br vlan-ids=10 current-tagged=br,ether3 current-untagged=ether4\n"
                   "1 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3\n")
        antworten = self._vlan(self.SPERRE, tabelle=tabelle, frames="admit-only-untagged-and-priority-tagged")
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_vlan_bereich_in_der_tabelle(self):
        self.assertTrue(core._vlan_id_in("20-30", "25"))
        self.assertTrue(core._vlan_id_in("10,20-30", "10"))
        self.assertFalse(core._vlan_id_in("20-30", "31"))
        self.assertFalse(core._vlan_id_in("10,20", "2"))
        self.assertTrue(core._vlan_id_in("kaputt", "20"))
        tabelle = "0 bridge=br vlan-ids=15-25 current-tagged=br current-untagged=ether3,ether4\n"
        self.assertEqual(self._befund(self._vlan(self.SPERRE, lan="ether4", tabelle=tabelle))["status"], "warn")

    def test_haus_port_im_gast_vlan_ausserhalb_von_lan_ist_unklar(self):
        # Der Port steht nicht in LAN, das Gast-VLAN aber schon: Es kann das Hausnetz sein.
        tabelle = "0 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3,ether4\n"
        befund = self._befund(self._vlan(self.SPERRE, lan="vlan20,vlan10", tabelle=tabelle))
        self.assertEqual(befund["status"], "unknown")

    def test_zweiter_gast_port_ausserhalb_von_lan_stoert_nicht(self):
        tabelle = "0 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3,ether5\n"
        self.assertEqual(self._befund(self._vlan(self.SPERRE, tabelle=tabelle))["status"], "good")

    def _zwei_funkbaender(self, ssid2):
        tabelle = "0 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3,wifi2\n"
        antworten = self._vlan(self.SPERRE, lan="br,vlan10,wifi2", tabelle=tabelle)
        antworten['/interface wifi print terse where name="ether3"'] = "0 name=ether3 configuration.ssid=Gast\n"
        antworten['/interface wifi print terse where name="wifi2"'] = f"0 name=wifi2 configuration.ssid={ssid2}\n"
        return antworten

    def test_zweites_funkband_desselben_gastnetzes_ist_kein_hausnetz(self):
        self.assertEqual(self._befund(self._zwei_funkbaender("Gast"))["status"], "good")

    def test_anderes_wlan_im_gast_vlan_ist_unklar_und_nicht_rot(self):
        self.assertEqual(self._befund(self._zwei_funkbaender("Haus"))["status"], "unknown")

    def test_wlan_mit_eigenem_vlan_ist_auch_bei_fremder_pvid_nicht_rot(self):
        for zeile in ("0 name=ether3 datapath.vlan-id=20\n", "0 name=ether3 datapath=dp\n", "0 name=ether3 configuration=cfg\n"):
            antworten = self._vlan(self.SPERRE, gast_pvid="1", lan="br,vlan10", vlan_ifs=("vlan10", "vlan20"),
                                   tabelle="0 bridge=br vlan-ids=1 current-untagged=ether3,ether4\n", bridge_pvid="99")
            antworten['/interface wifi print terse where name="ether3"'] = zeile
            with self.subTest(zeile=zeile):
                self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_vlan_je_geraet_oder_passwort_ist_unklar(self):
        for pfad, zeile in (("/interface wifi access-list", "0 action=accept vlan-id=30\n"),
                            ("/interface wifi security multi-passphrase", "0 group=g vlan-id=30\n"),
                            ("/interface wireless access-list", "0 vlan-id=30\n")):
            antworten = self._vlan(self.SPERRE)
            antworten[f"{pfad} print terse"] = zeile
            with self.subTest(pfad=pfad):
                self.assertEqual(self._befund(antworten)["status"], "unknown")
        antworten = self._vlan(self.SPERRE)
        antworten["/interface wifi access-list print terse"] = "0 X action=accept vlan-id=30\n1 action=reject\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_notrack_hebt_regeln_mit_zustand_auf(self):
        regeln = ("0 chain=forward action=accept connection-state=established,related,untracked\n" + self.INVALID.replace("0 ", "1 ", 1) + self.NEU.replace("1 ", "2 ", 1))
        self.assertEqual(self._befund(self._vlan(regeln))["status"], "good")
        for pfad in ("/ip firewall raw print terse", "/ipv6 firewall raw print terse"):
            antworten = self._vlan(regeln)
            antworten[pfad] = "0 chain=prerouting action=notrack in-interface=vlan20\n"
            with self.subTest(pfad=pfad):
                self.assertEqual(self._befund(antworten)["status"], "unknown")
        antworten = self._vlan(regeln)
        antworten["/ip firewall raw print terse"] = "0 X chain=prerouting action=notrack in-interface=vlan20\n1 chain=prerouting action=drop\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_ohne_connection_tracking_gilt_kein_zustand(self):
        antworten = self._vlan(self.INVALID + self.NEU)
        antworten["/ip firewall connection tracking print"] = "  enabled: no\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")
        antworten["/ip firewall connection tracking print"] = "  enabled: auto\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_unlesbarer_tracking_stand_gilt_als_unzuverlaessig(self):
        for ziel in ("/ip firewall connection tracking print", "/ip firewall raw print terse"):
            with self._router(self._vlan(self.INVALID + self.NEU), fehler=(ziel,)), self.subTest(ziel=ziel):
                self.assertNotEqual(core._gast_befund("ether3")["status"], "good")

    def test_sperre_nur_fuer_new_braucht_die_sperre_fuer_invalid(self):
        self.assertEqual(self._befund(self._vlan(self.NEU))["status"], "unknown")
        schlusssperre = self.NEU + "2 chain=forward action=drop\n"
        self.assertEqual(self._befund(self._vlan(schlusssperre))["status"], "good")
        teil = "0 chain=forward action=drop connection-state=invalid protocol=tcp\n" + self.NEU
        self.assertEqual(self._befund(self._vlan(teil))["status"], "unknown")

    def test_freigabe_mit_in_interface_all(self):
        regeln = "0 chain=forward action=accept in-interface=all-vlan out-interface-list=LAN\n" + self.SPERRE
        self.assertEqual(self._befund(self._vlan(regeln))["status"], "unknown")
        regeln = "0 chain=forward action=drop in-interface=all-vlan out-interface-list=LAN\n" + self.SPERRE
        self.assertEqual(self._befund(self._vlan(regeln))["status"], "good")

    def _standardfirewall(self):
        v4 = ("0 chain=forward action=accept ipsec-policy=in,ipsec\n1 chain=forward action=accept ipsec-policy=out,ipsec\n"
              "2 chain=forward action=accept connection-state=established,related,untracked\n3 chain=forward action=drop connection-state=invalid\n"
              "4 chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=WAN\n"
              "5 chain=forward action=drop in-interface=vlan20 out-interface-list=LAN\n")
        v6 = ("0 chain=forward action=accept connection-state=established,related,untracked\n1 chain=forward action=drop connection-state=invalid\n"
              "2 chain=forward action=drop src-address-list=no_forward_ipv6\n3 chain=forward action=drop dst-address-list=no_forward_ipv6\n"
              "4 chain=forward action=drop in-interface=vlan20 out-interface-list=LAN\n5 chain=forward action=accept protocol=icmpv6\n"
              "6 chain=forward action=drop in-interface-list=!LAN\n")
        antworten = self._vlan(v4, regeln6=v6)
        antworten['/interface list member print terse where list="WAN"'] = "0 list=WAN interface=ether1\n"
        antworten["/ip ipsec policy print terse"] = "0 T* group=default src-address=::/0 dst-address=::/0 template=yes\n"
        return antworten

    def test_standardfirewall_mit_gast_sperre_ist_gruen(self):
        self.assertEqual(self._befund(self._standardfirewall())["status"], "good")

    def test_echte_ipsec_policy_laesst_die_freigabe_stehen(self):
        antworten = self._standardfirewall()
        antworten["/ip ipsec policy print terse"] += "1 src-address=192.168.20.0/24 dst-address=10.0.0.0/8\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")
        with self._router(self._standardfirewall(), fehler=("/ip ipsec policy print terse",)):
            self.assertEqual(core._gast_befund("ether3")["status"], "unknown")

    def test_ipsec_mit_weiterer_bedingung_bleibt_unklar(self):
        antworten = self._standardfirewall()
        antworten[self.FW4] = "0 chain=forward action=accept ipsec-policy=in,ipsec protocol=tcp\n" + self.SPERRE
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def _internet_freigabe(self, regel):
        antworten = self._vlan(regel + self.SPERRE)
        antworten['/interface list member print terse where list="WAN"'] = "0 list=WAN interface=ether1\n"
        return antworten

    def test_internet_freigabe_vor_der_sperre_ist_kein_zweifel(self):
        for regel in ("0 chain=forward action=accept in-interface=vlan20 out-interface=ether1\n",
                      "0 chain=forward action=accept in-interface=vlan20 out-interface-list=WAN\n"):
            with self.subTest(regel=regel):
                self.assertEqual(self._befund(self._internet_freigabe(regel))["status"], "good")

    def test_freigabe_direkt_ins_hausnetz_ist_ein_leck(self):
        regel = "0 chain=forward action=accept in-interface=vlan20 out-interface=vlan10\n"
        self.assertEqual(self._befund(self._internet_freigabe(regel))["status"], "warn")

    def test_freigabe_mit_weiterer_bedingung_ins_hausnetz_bleibt_unklar(self):
        regel = "0 chain=forward action=accept protocol=udp dst-port=53 in-interface=vlan20 out-interface=vlan10\n"
        self.assertEqual(self._befund(self._internet_freigabe(regel))["status"], "unknown")

    def test_freigabe_auf_unbekanntes_interface_bleibt_unklar(self):
        regel = "0 chain=forward action=accept in-interface=vlan20 out-interface=ether7\n"
        self.assertEqual(self._befund(self._internet_freigabe(regel))["status"], "unknown")

    def test_reject_wirkt_wie_drop(self):
        for regel in ("0 chain=forward action=reject in-interface=vlan20 out-interface-list=LAN\n",
                      "0 chain=forward action=reject reject-with=icmp-admin-prohibited in-interface=vlan20 out-interface-list=LAN\n"):
            with self.subTest(regel=regel):
                self.assertEqual(self._befund(self._vlan(regel))["status"], "good")

    def _faelschbar(self, rp_filter, absender="192.168.30.0/24"):
        regeln = f"0 chain=forward action=accept src-address={absender}\n" + self.SPERRE
        antworten = self._vlan(regeln, regeln6=self.SPERRE)
        antworten["/ip settings print"] = f"  rp-filter: {rp_filter}\n"
        return antworten

    def test_freigabe_fuer_fremde_absender_nur_mit_strict_egal(self):
        self.assertEqual(self._befund(self._faelschbar("strict"))["status"], "good")
        self.assertEqual(self._befund(self._faelschbar("loose"))["status"], "unknown")
        self.assertEqual(self._befund(self._faelschbar("no"))["status"], "unknown")

    def test_freigabe_fuer_das_gastnetz_selbst_bleibt_auch_mit_strict(self):
        for absender in ("192.168.20.0/24", "192.168.0.0/16", "192.168.20.5"):
            with self.subTest(absender=absender):
                self.assertNotEqual(self._befund(self._faelschbar("strict", absender))["status"], "good")

    def test_unlesbarer_absender_oder_unlesbare_einstellung_bleibt_unklar(self):
        self.assertEqual(self._befund(self._faelschbar("strict", "!192.168.30.0/24"))["status"], "unknown")
        self.assertEqual(self._befund(self._faelschbar("strict", "10.0.0.1-10.0.0.5"))["status"], "unknown")
        with self._router(self._faelschbar("strict"), fehler=("/ip settings print",)):
            self.assertEqual(core._gast_befund("ether3")["status"], "unknown")

    def test_strict_gilt_nicht_fuer_ipv6(self):
        regeln6 = "0 chain=forward action=accept src-address=fd00:30::/64\n" + self.SPERRE
        antworten = self._vlan(self.SPERRE, regeln6=regeln6)
        antworten["/ip settings print"] = "  rp-filter: strict\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_hw_port_kein_beleg_durch_bridge_filter(self):
        antworten = self._flach("0 chain=forward action=drop in-interface=br out-interface-list=LAN\n", filter_regeln=self.FILTER)
        self.assertEqual(self._befund(antworten)["status"], "good")
        antworten['/interface bridge port print terse where interface="ether3"'] = "0 H interface=ether3 bridge=br pvid=1 hw=yes\n"
        befund = self._befund(antworten)
        self.assertEqual(befund["status"], "warn")
        self.assertEqual(befund["schicht2"]["beleg"], "bypass")

    def test_hw_port_kein_beleg_durch_use_ip_firewall(self):
        antworten = self._flach()
        antworten["/interface bridge settings print"] = "  use-ip-firewall: yes\n"
        with self._router(antworten):
            self.assertIs(core._guest_bridge_bypass("ether3"), False)
        antworten['/interface bridge port print terse where interface="ether3"'] = "0 H interface=ether3 bridge=br pvid=1 hw=yes\n"
        with self._router(antworten):
            self.assertIsNone(core._guest_bridge_bypass("ether3"))

    def test_hw_yes_ohne_flag_ist_kein_offload(self):
        # Am CHR und am hAP ax2 gelesen: hw=yes ohne H. Am CHR fuehrte das Feld als Merkmal zu falschem Rot.
        antworten = self._flach("0 chain=forward action=drop in-interface=br out-interface-list=LAN\n", filter_regeln=self.FILTER)
        antworten['/interface bridge port print terse where interface="ether3"'] = "0 interface=ether3 bridge=br pvid=1 hw=yes\n"
        self.assertEqual(self._befund(antworten)["status"], "good")
        with self._router({'/interface bridge port print terse where interface="p"': "0 IH interface=p hw=yes\n"}):
            self.assertIs(core._port_im_switch_chip("p"), True)

    def test_hw_lesefehler_ist_nicht_nein(self):
        with self._router({}, fehler=('/interface bridge port print terse where interface="ether3"',)):
            self.assertIsNone(core._port_im_switch_chip("ether3"))

    def test_l3_hardware_offload_ist_unklar(self):
        antworten = self._vlan(self.SPERRE)
        antworten["/interface ethernet switch print terse"] = "0 name=switch1 type=Marvell-98DX3236 l3-hw-offloading=yes\n"
        befund = self._befund(antworten)
        self.assertEqual(befund["status"], "unknown")
        self.assertIsNone(befund["v4"])
        antworten["/interface ethernet switch print terse"] = "0 name=switch1 type=IPQ-PPE l3-hw-offloading=no\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_l3_abfrage_unerreichbar_und_ohne_switch(self):
        def stub(c):
            if c == "/interface ethernet switch print terse":
                raise core.RouterUnreachable("weg")
            return ""
        with patch.object(core, "router", side_effect=stub):
            self.assertIsNone(core._gast_layer3("ether3", {"bridge": None, "eigener_eingang": True}, self.FW4))

    def test_ipv6_lesefehler_ist_nicht_keine_adresse(self):
        with self._router({}, fehler=('/ipv6 address print terse where interface="x"',)):
            self.assertIsNone(core._hat_routbare_adresse("x", self.FW6))

    def test_fehlendes_ipv6_paket_ist_keine_adresse(self):
        def stub(c):
            raise core.RouterCommandFailed("bad command name address")
        with patch.object(core, "router", side_effect=stub):
            self.assertIs(core._hat_routbare_adresse("x", self.FW6), False)

    def test_gast_ohne_ipv6_adresse_routet_ueber_link_local(self):
        # Im Labor gemessen, Szenario fe80-gateway: Ohne Adresse im Gastnetz bleibt der Weg offen.
        antworten = self._vlan(self.SPERRE, regeln6="", v6=("vlan10",))
        befund = self._befund(antworten)
        self.assertIsNone(befund["v6"])
        self.assertEqual(befund["status"], "unknown")
        self.assertEqual(self._befund(self._vlan(self.SPERRE, v6=("vlan10",)))["status"], "good")

    def test_ohne_anderes_ipv6_netz_gibt_es_nichts_zu_routen(self):
        antworten = self._vlan(self.SPERRE, regeln6="", v6=("vlan20",))
        befund = self._befund(antworten)
        self.assertEqual(befund["v6"], "keine_adresse")
        self.assertEqual(befund["status"], "good")
        antworten = self._vlan(self.SPERRE, regeln6="", v6=())
        self.assertEqual(self._befund(antworten)["v6"], "keine_adresse")

    def test_geroutete_ziele(self):
        antworten = {"/ip address print terse": ("0 interface=vlan10 address=192.168.10.1/24\n1 interface=ether1 address=203.0.113.2/24\n"
                                                 "2 X interface=vlan40 address=10.4.0.1/24\n3 interface=vlan20 address=192.168.20.1/24\n"),
                     '/interface list member print terse where list="WAN"': "0 list=WAN interface=ether1\n",
                     "/ipv6 address print terse": "0 DL interface=vlan10 address=fe80::1/64\n1 D interface=lo address=::1/128\n"}
        with self._router(antworten):
            self.assertEqual(core._geroutete_ziele(self.FW4, {"vlan20"}), {"vlan10"})
            self.assertEqual(core._geroutete_ziele(self.FW6, {"vlan20"}), set())
        with self._router({"/ip address print terse": "keine Zeile im erwarteten Format\n"}):
            self.assertIsNone(core._geroutete_ziele(self.FW4, {"vlan20"}))
        with self._router({}, fehler=("/ip address print terse",)):
            self.assertIsNone(core._geroutete_ziele(self.FW4, {"vlan20"}))

    def test_check_router_woanders_nur_bei_belegter_trennung(self):
        befund = {"status": "unknown", "schicht2": {"getrennt": None, "beleg": "vlan_unklar"}, "v4": "extern", "v6": "extern", "ipv6_an": True}
        with patch.object(core, "current_conn", return_value={"guest_interface": "ether3"}), patch.object(core, "_gast_befund", return_value=befund):
            ergebnis = routes_basis._security_check_guest_isolation()
        self.assertNotIn("getrennt. Geroutet", ergebnis["plain"])

    def test_gruener_text_verspricht_nichts_zum_router_selbst(self):
        self.assertIn("Verwaltung des Routers", self._check("good", v4=True, v6=True)["plain"])

    def test_abgeschaltete_zeilen_zaehlen_nicht(self):
        with self._router({'/interface bridge port print terse where interface="p"': "0 XH interface=p hw=yes\n1 interface=p hw=yes\n"}):
            self.assertIs(core._port_im_switch_chip("p"), False)
        with self._router({'/interface vlan print terse where interface="br"': "0 X name=vlan20 interface=br vlan-id=20\n"}):
            self.assertIs(core._vlan_interface_in_lan("br", "20", {"vlan20"}), False)
        with self._router({"/ip ipsec policy print terse": "0 T template=yes\n1 X src-address=10.0.0.0/8\n"}):
            self.assertIs(core._keine_ipsec_policy(), True)
        with self._router({"/ip settings print": "  rp-filter: strict\n",
                           '/ip address print terse where interface="x"': "0 X interface=x address=192.168.30.1/24\n1 interface=x address=192.168.20.1/24\n"}):
            self.assertIs(core._absender_schliesst_gast_aus({"src-address": "192.168.30.0/24"}, {"x"}, "/ip firewall filter"), True)
        antworten = self._vlan(self.SPERRE)
        antworten['/interface bridge port print terse where interface="ether3"'] = (
            "0 X interface=ether3 bridge=br pvid=30 ingress-filtering=no frame-types=admit-all\n"
            "1 interface=ether3 bridge=br pvid=20 ingress-filtering=yes frame-types=admit-all\n")
        with self._router(antworten):
            self.assertIs(core._vlan_isolation("ether3", "br"), True)
        antworten = self._vlan(self.SPERRE)
        antworten["/interface ethernet switch print terse"] = "0 X name=switch1 l3-hw-offloading=yes\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_abgeschaltetes_listenmitglied_macht_die_freigabe_nicht_zum_leck(self):
        regeln = "0 chain=forward action=accept in-interface=vlan20 out-interface-list=H\n" + self.SPERRE
        antworten = self._vlan(regeln)
        antworten['/interface list member print terse where list="H"'] = "0 X list=H interface=vlan10\n1 list=H interface=vlan40\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_wlan_abfragen_im_einzelnen(self):
        for zeile in ("0 name=g configuration=cfg\n", "0 name=g datapath=dp\n", "0 name=g datapath.vlan-id=30\n"):
            with self._router({'/interface wifi print terse where name="g"': zeile}), self.subTest(zeile=zeile):
                self.assertIs(core._wlan_setzt_vlan("g"), True)
        with self._router({'/interface wireless print terse where name="g"': "0 name=g vlan-mode=use-tag\n"}):
            self.assertIs(core._wlan_setzt_vlan("g"), True)
        with self._router({'/interface wifi print terse where name="g"': "0 name=g configuration.ssid=Gast\n"}):
            self.assertIs(core._wlan_setzt_vlan("g"), False)

    def test_wlan_unerreichbar_ist_unklar(self):
        for ziel in ('/interface wifi print terse where name="g"', "/interface wifi access-list print terse"):
            def stub(c, ziel=ziel):
                if c == ziel:
                    raise core.RouterUnreachable("weg")
                return ""
            with patch.object(core, "router", side_effect=stub), self.subTest(ziel=ziel):
                self.assertIsNone(core._wlan_setzt_vlan("g"))

    def test_eigenes_wlan_vlan_sperrt_beide_auswertungen(self):
        antworten = self._vlan(self.SPERRE)
        antworten['/interface wifi print terse where name="ether3"'] = "0 name=ether3 datapath.vlan-id=30\n"
        with self._router(antworten):
            self.assertIsNone(core._vlan_isolation("ether3", "br"))
            self.assertIsNone(core._gast_eingang("ether3"))

    def test_zwei_wlans_ohne_sichtbare_ssid_sind_nicht_dasselbe(self):
        antworten = self._zwei_funkbaender("Gast")
        antworten['/interface wifi print terse where name="ether3"'] = "0 name=ether3\n"
        antworten['/interface wifi print terse where name="wifi2"'] = "0 name=wifi2\n"
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_eingang_ohne_adresse_ist_kein_beleg_fuer_fremden_absender(self):
        with self._router({"/ip settings print": "  rp-filter: strict\n"}):
            self.assertIs(core._absender_schliesst_gast_aus({"src-address": "10.0.0.0/8"}, {"x"}, "/ip firewall filter"), False)

    def test_unlesbare_adressen_sind_kein_beleg(self):
        with self._router(self._vlan(self.SPERRE), fehler=("/ip address print terse",)):
            befund = core._gast_befund("ether3")
        self.assertIsNone(befund["v4"])
        self.assertEqual(befund["status"], "unknown")
        with self._router(self._vlan(self.SPERRE), fehler=("/ipv6 address print terse",)):
            befund = core._gast_befund("ether3")
        self.assertIsNone(befund["v6"])
        self.assertEqual(befund["status"], "unknown")

    def test_unklare_sperren_sind_kein_grund_aufzugeben(self):
        for vorab in ("0 chain=forward action=drop in-interface-list=D out-interface-list=LAN\n",
                      "0 chain=forward action=drop in-interface=!ether7 out-interface-list=LAN\n",
                      "0 chain=forward action=drop in-interface=vlan20 src-address-list=d\n",
                      "0 chain=forward action=drop in-interface=vlan20 dst-address-list=d\n"):
            antworten = self._vlan(vorab + self.SPERRE, regeln6=self.SPERRE)
            antworten['/interface list member print terse where list="D"'] = "0 D list=D interface=vlan20\n"
            antworten['/ip firewall address-list print terse where list="d" and dynamic=yes'] = "0 D list=d address=10.0.0.1\n"
            with self.subTest(vorab=vorab):
                self.assertEqual(self._befund(antworten)["status"], "good")

    def test_ohne_tracking_zaehlt_eine_sperre_ohne_zustand(self):
        antworten = self._vlan(self.INVALID + self.SPERRE.replace("0 ", "1 ", 1))
        antworten["/ip firewall connection tracking print"] = "  enabled: no\n"
        self.assertEqual(self._befund(antworten)["status"], "good")

    def test_freigabe_auf_einzelne_interfaces(self):
        regel = "0 chain=forward action=accept in-interface=vlan20 out-interface=%s\n"
        # LAN-Mitglied ohne Adresse
        antworten = self._vlan(regel % "ether9" + self.SPERRE, lan="vlan10,ether9")
        self.assertEqual(self._befund(antworten)["status"], "warn")
        # Geroutetes Netz ausserhalb von LAN
        antworten = self._vlan(regel % "vlan10" + self.SPERRE, lan="br")
        self.assertEqual(self._befund(antworten)["status"], "warn")
        # Bridge-Port: Eine Regel auf einen Port trifft im Routing nie, ein Leck ist das nicht belegt.
        antworten = self._vlan(regel % "ether4" + self.SPERRE, lan="vlan10,ether4")
        self.assertEqual(self._befund(antworten)["status"], "unknown")

    def test_geteiltes_vlan_mit_filter_am_hw_port_bleibt_ein_leck(self):
        tabelle = "0 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3,ether4\n"
        antworten = self._vlan(self.SPERRE, lan="ether4,vlan10", tabelle=tabelle)
        antworten["/interface bridge filter print terse where chain=forward"] = "0 chain=forward action=drop in-interface=ether3 out-interface=ether4\n"
        antworten['/interface bridge port print terse where interface="ether3"'] = (
            "0 H interface=ether3 bridge=br pvid=20 ingress-filtering=yes frame-types=admit-all hw=yes\n")
        befund = self._befund(antworten)
        self.assertEqual(befund["schicht2"]["beleg"], "vlan_geteilt")
        self.assertEqual(befund["status"], "warn")

    def test_l3_offload_nicht_lesbar_ist_kein_beleg(self):
        antworten = self._vlan(self.SPERRE)
        def stub(c):
            if c == "/interface ethernet switch print terse":
                raise core.RouterUnreachable("weg")
            return antworten.get(c, "")
        with patch.object(core, "router", side_effect=stub):
            self.assertIsNone(core._gast_layer3("ether3", {"bridge": "br", "eigener_eingang": True}, "/ip firewall filter"))
        with self._router(antworten):
            self.assertIs(core._gast_layer3("ether3", {"bridge": "br", "eigener_eingang": True}, "/ip firewall filter"), True)

    def test_sperre_alles_ausser_lan_mitglied_ohne_adresse_belegt_nichts(self):
        regel = "0 chain=forward action=drop in-interface=vlan20 out-interface=!ether9\n"
        self.assertEqual(self._befund(self._vlan(regel, lan="vlan10,ether9"))["status"], "unknown")

    def test_ipv6_kandidaten_unlesbar(self):
        with self._router({}), patch.object(core, "_gast_eingang", side_effect=[set(), None]):
            self.assertIsNone(core._gast_layer3("ether3", {"bridge": "br", "eigener_eingang": True}, self.FW6))

    # Die folgenden Tests schliessen Luecken, die die Gegenprobe am 2026-11-05 gezeigt hat.

    def _router(self, antworten, fehler=()):
        def stub(command):
            if command in fehler:
                raise core.RouterCommandFailed("failure")
            return antworten.get(command, "")
        return patch.object(core, "router", side_effect=stub)

    def test_abgeschaltetes_vlan_interface_macht_keinen_bypass(self):
        antworten = {
            '/interface bridge port print terse where interface="ether3"': "0 interface=ether3 bridge=br\n",
            '/interface bridge port print terse where bridge="br"': "0 interface=ether3 bridge=br\n",
            '/interface bridge print terse where name="br"': "0 name=br vlan-filtering=no\n",
            '/interface list member print terse where list="LAN"': "0 list=LAN interface=vlan10\n",
            '/interface vlan print terse where interface="br"': "0 X name=vlan10 interface=br vlan-id=10\n",
            "/interface bridge settings print": "  use-ip-firewall: no\n",
        }
        with self._router(antworten):
            self.assertIs(core._guest_bridge_bypass("ether3"), False)

    def test_vlan_mitglieder_ohne_abgeschaltete_zeilen_und_ohne_bridge(self):
        antworten = self._vlan(tabelle="0 X bridge=br vlan-ids=20 tagged=ether5\n"
                                       "1 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3\n")
        with self._router(antworten):
            self.assertEqual(core._gast_vlan_mitglieder("ether3", "br", "20"), set())

    def test_abgeschaltete_portzeile_bestimmt_weder_eingang_noch_weg(self):
        antworten = self._vlan(tabelle="0 bridge=br vlan-ids=10 tagged=ether5\n1 bridge=br vlan-ids=20 current-untagged=ether3\n")
        antworten['/interface bridge port print terse where interface="ether3"'] = (
            "0 X interface=ether3 bridge=br pvid=10\n1 interface=ether3 bridge=br pvid=20 ingress-filtering=yes\n")
        with self._router(antworten):
            self.assertEqual(core._gast_eingang("ether3"), {"vlan20"})
            self.assertIs(core._gast_hat_weiteren_weg("ether3", "br"), False)

    def test_abgeschaltetes_vlan_interface_ist_kein_eingang(self):
        antworten = self._vlan()
        antworten['/interface vlan print terse where interface="br"'] = "0 X name=vlan20 interface=br vlan-id=20\n"
        with self._router(antworten):
            self.assertEqual(core._gast_eingang("ether3"), set())

    def test_bridge_mit_adresse_ist_bei_anderer_pvid_kein_eingang(self):
        antworten = self._vlan()
        antworten['/ip address print terse where interface="br"'] = "0 interface=br address=192.168.99.1/24\n"
        with self._router(antworten):
            self.assertEqual(core._gast_eingang("ether3"), {"vlan20"})

    def test_lan_nur_aus_ausnahmen_deckt_keine_liste(self):
        antworten = {'/interface list member print terse where list="LAN"': "0 list=LAN interface=ether4\n",
                     '/interface list member print terse where list="x"': "0 list=x interface=ether4\n"}
        with self._router(antworten):
            self.assertIsNone(core._interface_list_covers_lan("x", {"ether4"}))

    def test_zielliste_muss_das_gastnetz_nicht_abdecken(self):
        antworten = self._vlan(lan="vlan10,vlan20")
        antworten['/ip firewall address-list print terse where list="h" and dynamic=no'] = "0 list=h address=192.168.10.0/24\n"
        with self._router(antworten):
            self.assertIs(core._address_list_covers_interface("h", "LAN", {"vlan20"}), True)
            self.assertIsNone(core._address_list_covers_interface("h", "LAN"))

    def test_unlesbare_adresszeile_eines_lan_mitglieds_belegt_nichts(self):
        antworten = self._vlan(lan="vlan10,vlan20")
        antworten['/ip firewall address-list print terse where list="h" and dynamic=no'] = "0 list=h address=192.168.10.0/24\n"
        antworten['/ip address print terse where interface="vlan20"'] = "keine Zeile im erwarteten Format\n"
        with self._router(antworten):
            self.assertIsNone(core._address_list_covers_interface("h", "LAN"))

    def test_bridge_in_lan_mit_gleicher_pvid_ist_kein_eigenes_vlan(self):
        antworten = self._vlan(lan="br,vlan10", gast_pvid="1", tabelle="0 bridge=br vlan-ids=1 current-untagged=ether3\n")
        with self._router(antworten):
            self.assertIs(core._vlan_isolation("ether3", "br"), False)

    def test_konfigurierter_ungetaggter_lan_port_zaehlt_auch_ohne_current(self):
        antworten = self._vlan(lan="ether4", tabelle="0 bridge=br vlan-ids=20 current-tagged=br current-untagged=ether3 tagged=br untagged=ether4\n")
        with self._router(antworten):
            self.assertIs(core._vlan_isolation("ether3", "br"), False)

    def test_quellliste_muss_jeden_eingang_abdecken(self):
        regel = "0 chain=forward action=drop out-interface-list=LAN src-address-list=g\n"
        antworten = {self.FW4: regel, '/interface list member print terse where list="LAN"': "0 list=LAN interface=vlan10\n"}
        with self._router(antworten), patch.object(core, "_gast_eingang", return_value={"a", "b"}), \
                patch.object(core, "_address_list_covers_interface", side_effect=lambda liste, name, *rest: name == "a"):
            self.assertIsNone(core._guest_isolation("ether3"))

    def test_unlesbare_bridge_ist_auf_layer_2_unklar(self):
        with self._router({}, fehler=('/interface bridge port print terse where interface="ether3"',)):
            schicht2 = core._gast_layer2("ether3")
        self.assertIsNone(schicht2["getrennt"])
        self.assertEqual(schicht2["beleg"], "unlesbar")

    def test_unlesbare_bridge_einstellung_ist_auf_layer_2_unklar(self):
        antworten = self._flach()
        with self._router(antworten, fehler=("/interface bridge settings print",)):
            schicht2 = core._gast_layer2("ether3")
        self.assertIsNone(schicht2["getrennt"])
        self.assertEqual(schicht2["beleg"], "unlesbar")

    def test_unlesbare_vlan_tabelle_ist_ein_weiterer_weg(self):
        antworten = self._vlan()
        with self._router(antworten, fehler=('/interface bridge vlan print terse where bridge="br"',)):
            self.assertIs(core._gast_hat_weiteren_weg("ether3", "br"), True)

    def test_ohne_bekannte_bridge_ist_es_keine_insel(self):
        with self._router({}), patch.object(core, "_gast_eingang", return_value=set()):
            self.assertEqual(core._gast_layer3("ether3", {"bridge": None, "eigener_eingang": True}, self.FW4), "extern")

    def test_unklarer_ipv6_status_ist_nicht_gruen(self):
        with self._router(self._vlan(self.SPERRE), fehler=("/ipv6 settings print",)):
            befund = core._gast_befund("ether3")
        self.assertIsNone(befund["ipv6_an"])
        self.assertIsNone(befund["v6"])
        self.assertEqual(befund["status"], "unknown")

    def _check(self, status, beleg="vlan", v4=None, v6=None, fehler=None):
        befund = {"status": status, "schicht2": {"getrennt": True, "beleg": beleg}, "v4": v4, "v6": v6, "ipv6_an": True}
        with patch.object(core, "current_conn", return_value={"guest_interface": "ether3"}), \
                patch.object(core, "_gast_befund", return_value=befund, side_effect=fehler):
            return routes_basis._security_check_guest_isolation()

    def test_check_geteiltes_vlan_nennt_die_fehlende_trennung(self):
        self.assertIn("NICHT sauber getrennt", self._check("warn", beleg="vlan_geteilt")["plain"])

    def test_check_nennt_den_router_davor(self):
        befund = {"status": "unknown", "schicht2": {"getrennt": True, "beleg": "vlan"}, "v4": None, "v6": True, "ipv6_an": True, "hinter_router": True}
        with patch.object(core, "current_conn", return_value={"guest_interface": "ether3"}), patch.object(core, "_gast_befund", return_value=befund):
            self.assertIn("hinter einem anderen Router", routes_basis._security_check_guest_isolation()["detail"])
        befund["status"] = "good"
        with patch.object(core, "current_conn", return_value={"guest_interface": "ether3"}), patch.object(core, "_gast_befund", return_value=befund):
            self.assertNotIn("hinter einem anderen Router", routes_basis._security_check_guest_isolation()["detail"])

    def test_check_zeitueberschreitung_ist_unklar(self):
        ergebnis = self._check("good", fehler=RouterTimeout("zu langsam"))
        self.assertEqual(ergebnis["status"], "unknown")

    def test_check_router_woanders(self):
        ergebnis = self._check("unknown", v4="extern", v6="extern")
        self.assertIn("Geroutet wird auf einem anderen Gerät", ergebnis["detail"])
        self.assertIn("Prüfe dort", ergebnis["plain"])

    def test_check_leck_bleibt_ein_leck_auch_wenn_ipv4_woanders_laeuft(self):
        ergebnis = self._check("warn", v4="extern", v6=False)
        self.assertEqual(ergebnis["status"], "warn")
        self.assertIn("können aktuell ins Hausnetz", ergebnis["plain"])

    def test_check_lesefehler_ist_unklar(self):
        ergebnis = self._check("good", fehler=core.RouterCommandFailed("failure"))
        self.assertEqual(ergebnis["status"], "unknown")
