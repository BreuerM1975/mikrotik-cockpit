import unittest
from unittest.mock import patch

import core
import routes_basis
from routeros import RouterCommandFailed, parse_terse


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
# Luecken (Listenmitgliedschaft, Bridge-Paketpfad, IPv6) -- siehe den Projektnotizen fuer den vollen Kontext.
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

    def test_false_when_lan_list_is_empty(self):
        # Eine leere Antwort ist kein Fehler, sondern eine gueltige (wenn auch unuebliche)
        # Aussage: die Liste "LAN" hat aktuell keine Mitglieder -- kein Bypass nachweisbar.
        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=bridge\n"
            return ""

        with patch.object(core, "router", side_effect=router_stub):
            self.assertIs(core._guest_bridge_bypass("guest"), False)


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
                return f"0 interface=guest bridge=bridge pvid={pvid}\n"
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
