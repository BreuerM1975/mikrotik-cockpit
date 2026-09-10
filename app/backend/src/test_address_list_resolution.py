import os
import tempfile
import unittest
from unittest.mock import patch

# Muss vor "import core" stehen: core.py liest COCKPIT_BACKUP_DIR/COCKPIT_DEVICE_ROOMS_DIR
# beim Modul-Import (core.cfg = load_config()). Da dieses Modul alphabetisch vor test_app.py
# entdeckt wird (unittest discover), wuerde core.cfg sonst mit dem echten ~/.config-Pfad
# initialisiert werden, bevor test_app.py seinen eigenen setdefault() nachholen kann -- Python
# cached das core-Modul beim zweiten Import, der Pfad bliebe fuer den ganzen Testlauf falsch
# (siehe den Projektnotizen, 2026-09-10, Fund waehrend der Basis/Pro-Code-Trennung).
os.environ.setdefault("COCKPIT_BACKUP_DIR", tempfile.mkdtemp(prefix="cockpit-test-backups-"))
os.environ.setdefault("COCKPIT_DEVICE_ROOMS_DIR", tempfile.mkdtemp(prefix="cockpit-test-device-rooms-"))

import core


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
