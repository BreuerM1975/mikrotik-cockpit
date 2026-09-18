import os
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from urllib.parse import quote

os.environ.setdefault("COCKPIT_BACKUP_DIR", tempfile.mkdtemp(prefix="cockpit-test-backups-"))
os.environ.setdefault("COCKPIT_DEVICE_ROOMS_DIR", tempfile.mkdtemp(prefix="cockpit-test-device-rooms-"))

import app as app_module
import core as core_module
import config as config_module
from routeros import (
    HostKeyChanged,
    HostKeyUnknown,
    RouterAuthFailed,
    RouterCommandFailed,
    RouterUnreachable,
)

FAKE_OUTPUT = {
    "/system identity print": '  name: L009\n',
    # Benutzer: admin aktiv und einziger Vollzugang (Standardzustand ab Werk), dazu ein
    # write-Benutzer. Echtes Format von RouterOS 7.23 (live 18.09.): disabled nur als Flag X,
    # last-logged-in fehlt bei nie angemeldeten Benutzern.
    "/user print terse": (
        ' 0   comment=system default user name=admin group=full inactivity-timeout=10m '
        'inactivity-policy=none address= last-logged-in=2026-09-17 21:04:11\n'
        ' 1   name=hilfe group=write inactivity-timeout=10m inactivity-policy=none address=\n'
    ),
    "/system resource print": '  version: 7.22.2 (stable)\n  uptime: 12d3h4m5s\n',
    '/interface print terse where name="ether1"': ' 0  name="ether1" running=true\n',
    '/ip address print terse where interface="ether1"': ' 0  address="203.0.113.7/24" interface="ether1"\n',
    '/ip route print terse where dst-address="0.0.0.0/0" and active=yes': (
        '0 As dst-address=0.0.0.0/0 gateway=203.0.113.1\n'
    ),
    '/ip dhcp-server lease print terse where status="bound"': (
        ' 0  address=192.168.178.42 mac-address=B8:27:EB:12:34:56 host-name="shelly-kueche" status=bound server=dhcp1\n'
    ),
    "/ip dhcp-server lease print terse": (
        ' 0  address=192.168.178.42 mac-address=B8:27:EB:12:34:56 host-name="shelly-kueche" status=bound server=dhcp1\n'
    ),
    "/interface wireless print terse": "",
    "/interface wifi print terse": "",
    "/interface pppoe-client print terse": (
        '0 R name="pppoe-out1" interface=ether1 user="isp-user" service-name="" '
        'add-default-route=true use-peer-dns=true\n'
    ),
    '/interface wireless print terse where name="wlan-haupt"': (
        '0  name="wlan-haupt" ssid="Home-Net" security-profile="default"\n'
    ),
    '/interface wireless print terse where name="wlan-gast"': (
        '0 X name="wlan-gast" ssid="Home-Guest"\n'
    ),
    ':put [/interface wireless security-profiles get [find name="default"] wpa2-pre-shared-key]': (
        "alt-passwort-1\n"
    ),
    ':put [/interface wireless security-profiles get [find name="default"] wpa-pre-shared-key]': (
        "alt-passwort-1\n"
    ),
    '/ip firewall nat print terse where comment~"^cockpit-pf:"': (
        '0  chain=dstnat protocol=tcp dst-port=8080 to-addresses=192.168.178.60 to-ports=80 '
        'comment="cockpit-pf:pf-aaaa1111:Kamera Einfahrt"\n'
    ),
    "/system package update print": (
        '  channel: stable\n  installed-version: 7.22.2\n  latest-version: 7.24.1\n'
    ),
    '/interface wireguard print terse where name="wg-vpn"': (
        '0  name="wg-vpn" public-key="serverPublicKeyXYZ=" listen-port=13231\n'
    ),
    '/ip address print terse where interface="wg-vpn"': (
        '0 address=10.10.10.1/24 interface=wg-vpn\n'
    ),
    '/interface wireguard peers print terse where interface="wg-vpn" and comment~"^cockpit-wg:"': (
        '0  interface=wg-vpn public-key="clientkey1=" comment="cockpit-wg:wg-aaaa1111:Homeoffice Laptop"\n'
    ),
    '/ip firewall nat print terse where chain=dstnat and protocol="tcp" and dst-port="8080"': (
        '0  chain=dstnat protocol=tcp dst-port=8080 comment="cockpit-pf:pf-aaaa1111:Kamera Einfahrt"\n'
    ),
    '/ip dhcp-server lease print terse where address="192.168.178.70"': "",
    '/ip dhcp-server lease print terse where mac-address="24:0a:c4:11:22:33"': (
        '0  address=192.168.178.65 mac-address=24:0A:C4:11:22:33 server=dhcp1\n'
    ),
    '/ip dhcp-server lease print terse where mac-address="aa:bb:cc:11:22:33"': "",
    "/ip address print terse": (
        ' 0  address="192.168.88.1/24" interface="ether1"\n'
        ' 1  address="192.168.20.1/24" interface="vlan20-buero"\n'
    ),
    ":put [/ip dns get servers]": "1.1.1.1;8.8.8.8\n",
    "/ip dhcp-client print terse": ' 0  interface=ether1 status=bound address=203.0.113.7/24\n',
    '/ip address print terse where interface="ether5"': (
        ' 0  address="192.168.88.1/24" interface="ether5"\n'
    ),
    '/ip address print terse where interface="ether2"': "",
    '/ip dhcp-client print terse where interface="ether1"': (
        ' 0  interface=ether1 status=bound\n'
    ),
    '/ip dhcp-client print terse where interface="ether2"': "",
    '/ip dhcp-client print terse where interface="ether3"': "",
    # RouterOS haengt bei einem Interface ohne Link-Status eigenen Text vor den Kommentar --
    # bewusst so in den Fixtures nachgebildet, das war ein echter Live-Fund am 08.09.
    '/ip dhcp-server print terse where name~"^cockpit-dhcp-"': (
        '0  name="cockpit-dhcp-dhcp-aaaa1111" interface=vlan20-buero '
        'address-pool="cockpit-dhcp-pool-dhcp-aaaa1111" lease-time=1d '
        'comment="Interface not running,cockpit-dhcp:dhcp-aaaa1111:vlan20-buero"\n'
    ),
    '/ip pool print terse where name="cockpit-dhcp-pool-dhcp-aaaa1111"': (
        '0  name="cockpit-dhcp-pool-dhcp-aaaa1111" ranges="192.168.20.100-192.168.20.200"\n'
    ),
    '/ip dhcp-server network print terse where comment~"cockpit-dhcp:dhcp-aaaa1111:vlan20-buero"': (
        '0  address="192.168.20.0/24" gateway="192.168.20.1" dns-server="192.168.20.1"\n'
    ),
    '/ip dhcp-server print terse where interface="vlan20-buero"': "",
    '/ip dhcp-server print terse where interface="vlan99-belegt"': (
        '0  name="bestehend" interface=vlan99-belegt\n'
    ),
    '/ip address print terse where interface="vlan20-buero"': (
        ' 0  address="192.168.20.1/24" interface="vlan20-buero"\n'
    ),
    '/ip address print terse where interface="vlan30-ohne-ip"': "",
    '/ip dhcp-server print terse where interface="vlan40-router-in-range"': "",
    '/ip address print terse where interface="vlan40-router-in-range"': (
        ' 0  address="192.168.40.1/24" interface="vlan40-router-in-range"\n'
    ),
    "/interface pppoe-client print terse": (
        '0 R name="pppoe-out1" interface=ether1 user="kunde@provider" running=true disabled=false '
        'add-default-route=true use-peer-dns=true local-address=203.0.113.7 remote-address=203.0.113.1\n'
    ),
    '/interface pppoe-client print terse where name="pppoe-out1"': (
        '0 R name="pppoe-out1" interface=ether1 user="kunde@provider" running=true disabled=false\n'
    ),
    '/interface pppoe-client print terse where name="pppoe-neu"': "",
    '/interface list print terse where name="WAN"': '0 name=WAN\n',
    '/interface pppoe-client print terse where name="pppoe-loeschen"': (
        '0  name="pppoe-loeschen" interface=ether2\n'
    ),
    '/interface pppoe-client print terse where name="pppoe-unbekannt"': "",
    '/interface vlan print terse where name="cockpit-pppoe-vlan-20"': "",
    '/interface vlan print terse where name="cockpit-pppoe-vlan-30"': (
        '0  name="cockpit-pppoe-vlan-30" interface=ether1 vlan-id=30\n'
    ),
    '/interface vlan print terse where name="cockpit-pppoe-vlan-40"': (
        '0  name="cockpit-pppoe-vlan-40" interface=ether5 vlan-id=40\n'
    ),
    '/interface pppoe-client print terse where name="pppoe-vlan-solo"': (
        '0  name="pppoe-vlan-solo" interface=cockpit-pppoe-vlan-50\n'
    ),
    '/interface pppoe-client print terse where interface="cockpit-pppoe-vlan-50"': (
        '0  name="pppoe-vlan-solo" interface=cockpit-pppoe-vlan-50\n'
    ),
    '/interface pppoe-client print terse where name="pppoe-vlan-shared-a"': (
        '0  name="pppoe-vlan-shared-a" interface=cockpit-pppoe-vlan-60\n'
    ),
    '/interface pppoe-client print terse where interface="cockpit-pppoe-vlan-60"': (
        '0  name="pppoe-vlan-shared-a" interface=cockpit-pppoe-vlan-60\n'
        '1  name="pppoe-vlan-shared-b" interface=cockpit-pppoe-vlan-60\n'
    ),
    '/ip dhcp-server print terse where name="cockpit-dhcp-dhcp-aaaa1111"': (
        '0  name="cockpit-dhcp-dhcp-aaaa1111" address-pool="cockpit-dhcp-pool-dhcp-aaaa1111" '
        'comment="Interface not running,cockpit-dhcp:dhcp-aaaa1111:vlan20-buero"\n'
    ),
    # Firewall (neu, 09.09.): "print as-value" statt "print terse" fuer die Listen-Abfrage --
    # liefert Eigenschaften UND ".id" in einer einzigen Abfrage (Audit A05, 09.09.: zwei
    # getrennte Abfragen konnten IDs falsch zuordnen). Format ist ";"-getrennt und quotet
    # ebenso nichts, live gegen den hAP bestaetigt.
    ':put [/ip firewall filter print as-value where chain="forward"]': (
        '.id=*A;chain=forward;action=drop;connection-state=invalid;'
        'comment=defconf: drop invalid;disabled=false;'
        '.id=*B;chain=forward;action=drop;connection-nat-state=!dstnat;in-interface-list=WAN;'
        'comment=defconf: drop all from WAN not DSTNATed;disabled=false'
    ),
    ':foreach i in=[/ip firewall filter find where chain="forward"] do={:put $i}': '*A\n*B\n',
    ':put [/ip firewall filter print as-value where chain="input"]': "",
    ':foreach i in=[/ip firewall filter find where chain="input"] do={:put $i}': "",
    ':put [/ip firewall nat print as-value where chain="dstnat"]': (
        '.id=*1;chain=dstnat;action=dst-nat;protocol=tcp;dst-port=8080;'
        'to-addresses=192.168.178.60;to-ports=80;comment=cockpit-fw: Portfreigabe Test;disabled=false'
    ),
    ':foreach i in=[/ip firewall nat find where chain="dstnat"] do={:put $i}': '*1\n',
    ':put [/ip firewall nat print as-value where chain="srcnat"]': (
        '.id=*2;chain=srcnat;action=masquerade;out-interface-list=WAN;'
        'comment=defconf: masquerade;disabled=false'
    ),
    ':foreach i in=[/ip firewall nat find where chain="srcnat"] do={:put $i}': '*2\n',
    '/ip firewall filter print terse where .id="*A"': (
        '0 comment=defconf: drop invalid chain=forward action=drop connection-state=invalid\n'
    ),
    '/ip firewall filter print terse where .id="*99"': "",
    # IP-Services (neu, 09.09.): "where dynamic=no" filtert auf RouterOS 7.x aktive
    # Verbindungen und interne Zusatzdienste (resolver, discover, ...) heraus -- live
    # gegen den hAP bestaetigt.
    "/ip service print terse where dynamic=no": (
        '0  name=ftp port=21 proto=tcp\n'
        '1  name=ssh port=22 proto=tcp\n'
        '2 X name=www-ssl port=443 proto=tcp\n'
    ),
    '/ip service print terse where name="ftp" and dynamic=no': '0  name=ftp port=21 proto=tcp\n',
    '/ip service print terse where name="unbekannt" and dynamic=no': "",
}


def fake_router(command):
    return FAKE_OUTPUT.get(command, "")


class ApiTest(unittest.TestCase):
    def setUp(self):
        app_module.app.testing = True
        self.client = app_module.app.test_client()
        # Verbinden-Modell (siehe dem Verbinden-Modell): keine feste
        # Konfiguration mehr, sondern eine Sitzung, die "/connect" normalerweise anlegt.
        # Für Tests, die nicht selbst den Connect-Ablauf prüfen, wird sie direkt gesetzt.
        self.session_id = "test-session"
        core_module.SESSIONS[self.session_id] = {
            "host": "test-host", "user": "admin", "password": "test-pass", "ssh_port": 22,
        }
        self.headers = {"X-Cockpit-Session": self.session_id}

    def tearDown(self):
        core_module.SESSIONS.clear()
        # Device-Rooms-Verzeichnis wird ueber die ganze Testklasse geteilt (Muster wie
        # COCKPIT_BACKUP_DIR oben) -- ohne Aufraeumen wuerde eine in einem Test gesetzte
        # Raum-Zuordnung fuer "test-host" in einen anderen Test durchsickern.
        rooms_dir = app_module.cfg.device_rooms_dir
        if os.path.isdir(rooms_dir):
            for fname in os.listdir(rooms_dir):
                try:
                    os.remove(os.path.join(rooms_dir, fname))
                except OSError:
                    pass

    def test_status_requires_session(self):
        resp = self.client.get("/api/v1/status")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"], "not_connected")

    def test_status_rejects_unknown_session(self):
        resp = self.client.get("/api/v1/status", headers={"X-Cockpit-Session": "does-not-exist"})
        self.assertEqual(resp.status_code, 401)

    def test_frontend_index_does_not_require_session(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"MikroTik Cockpit", resp.data)

    def test_cors_preflight_bypasses_session(self):
        resp = self.client.options("/api/v1/status")
        self.assertNotEqual(resp.status_code, 401)
        self.assertIn("Access-Control-Allow-Origin", resp.headers)

    @patch("core.router", side_effect=fake_router)
    def test_cors_headers_on_real_request(self, _mock):
        resp = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(
            resp.headers.get("Access-Control-Allow-Origin"), "http://127.0.0.1:8787",
        )

    @patch("routes_basis.ensure_host_key_trusted")
    @patch("routes_basis.run_command")
    def test_connect_success(self, mock_run_command, _host_key):
        mock_run_command.side_effect = (
            lambda host, user, password, port, command, known_hosts_path=None: FAKE_OUTPUT.get(command, "")
        )
        resp = self.client.post(
            "/api/v1/connect",
            json={"host": "192.168.99.230", "user": "admin", "password": "geheim"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["session"])
        self.assertEqual(data["router_identity"], "L009")
        # Die frisch erzeugte Sitzung muss sofort fuer weitere Aufrufe nutzbar sein.
        self.assertIn(data["session"], core_module.SESSIONS)

    @patch("routes_basis.ensure_host_key_trusted")
    @patch("routes_basis.run_command")
    def test_connect_does_not_strip_password_whitespace(self, mock_run_command, _host_key):
        # Audit Runde 5, 09.09.: ein Passwort mit fuehrenden/abschliessenden Leerzeichen ist
        # ein gueltiges RouterOS-Passwort -- .strip() haette es unbemerkt veraendert und den
        # Nutzer trotz korrekter Eingabe ausgesperrt.
        mock_run_command.side_effect = (
            lambda host, user, password, port, command, known_hosts_path=None: FAKE_OUTPUT.get(command, "")
        )
        resp = self.client.post(
            "/api/v1/connect",
            json={"host": "192.168.99.230", "user": "admin", "password": " geheim "},
        )
        self.assertEqual(resp.status_code, 200)
        session_id = resp.get_json()["session"]
        self.assertEqual(core_module.SESSIONS[session_id]["password"], " geheim ")
        used_passwords = {call.args[2] for call in mock_run_command.call_args_list}
        self.assertEqual(used_passwords, {" geheim "})

    @patch("routes_basis.ensure_host_key_trusted")
    def test_connect_sets_session_activity_timestamp(self, _host_key):
        with patch("routes_basis.run_command", side_effect=lambda *args, **kwargs: FAKE_OUTPUT.get(args[-1], "")):
            resp = self.client.post(
                "/api/v1/connect",
                json={"host": "192.168.99.230", "user": "admin", "password": "geheim"},
            )
        self.assertIn("last_activity", core_module.SESSIONS[resp.get_json()["session"]])

    def test_session_expires_after_idle_timeout(self):
        core_module.SESSIONS[self.session_id]["last_activity"] = time.monotonic() - 61
        with patch.object(core_module, "SESSION_IDLE_TIMEOUT_SECONDS", 60), patch("core.router") as router:
            resp = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"], "session_expired")
        router.assert_not_called()

    def test_connect_requires_host_and_password(self):
        resp = self.client.post("/api/v1/connect", json={"host": "192.168.99.230"})
        self.assertEqual(resp.status_code, 400)

    def test_connect_rejects_wrong_json_types_before_router_access(self):
        payloads = [
            {"host": 12345, "user": "admin", "password": "geheim"},
            {"host": "192.168.99.230", "user": [], "password": "geheim"},
            {"host": "192.168.99.230", "user": "admin", "password": None},
            ["192.168.99.230", "admin", "geheim"],
        ]
        for payload in payloads:
            with self.subTest(payload=payload), patch("routes_basis.run_command") as run_command:
                resp = self.client.post("/api/v1/connect", json=payload)
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(resp.get_json()["error"], "bad_request")
            run_command.assert_not_called()

    def test_connect_rejects_out_of_range_or_boolean_port(self):
        for port in (0, 65536, True):
            with self.subTest(port=port), patch("routes_basis.run_command") as run_command:
                resp = self.client.post(
                    "/api/v1/connect",
                    json={"host": "192.168.99.230", "user": "admin", "password": "geheim", "ssh_port": port},
                )
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(resp.get_json()["error"], "bad_request")
            run_command.assert_not_called()

    def test_connect_rejects_non_json_content_type(self):
        # Audit Runde 4, 09.09.: /connect ist von der Sitzungspruefung ausgenommen und hat damit
        # keinen "X-Cockpit-Session"-Header, der sonst jeden Cross-Origin-Aufruf zu einem
        # CORS-Preflight zwingt. Ohne diese Pruefung koennte eine fremde Webseite per
        # fetch(url, {method:"POST", headers:{"Content-Type":"text/plain"}, body:"..."}) --
        # eine CORS-"simple request" ganz ohne Preflight -- den lokalen Cockpit-Prozess blind
        # zu einer SSH-Verbindung mit fremden Zugangsdaten zwingen. Live gegen den lokal
        # laufenden Prozess nachgewiesen (siehe den Projektnotizen); dieser Test haelt den Fix nach.
        with patch("routes_basis.run_command") as run_command:
            resp = self.client.post(
                "/api/v1/connect",
                data='{"host": "10.255.255.1", "user": "admin", "password": "x"}',
                content_type="text/plain",
            )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "bad_request")
        run_command.assert_not_called()

    def test_routeros_value_allows_long_interface_names_but_keeps_ssid_limit(self):
        interface = "vlan120-buero-gebaeude2-og3"
        self.assertEqual(core_module._routeros_value(interface, "interface"), interface)
        with self.assertRaises(ValueError):
            core_module._routeros_value("x" * 65, "interface")
        with self.assertRaises(ValueError):
            core_module._routeros_value("x" * 33, "ssid", maximum=32)

    @patch("core._wireless_driver", return_value="wireless")
    @patch("core.router", return_value='0 name="wlan-gast" ssid="Gast" disabled=true\n')
    def test_guest_row_does_not_validate_interface_twice(self, _router, wireless_driver):
        result = core_module._guest_row(r"wlan\$gast")
        self.assertEqual(result[0], "wireless")
        wireless_driver.assert_called_once_with(r"wlan\$gast", validated=True)
        _router.assert_any_call(r'/interface wireless print terse where name="wlan\$gast"')
        _router.assert_any_call('/ip firewall filter print terse where chain=forward')
        self.assertEqual(_router.call_count, 2)

    @patch("routes_basis.ensure_host_key_trusted")
    @patch("routes_basis.run_command", side_effect=RouterAuthFailed("Permission denied"))
    def test_connect_auth_failed(self, _mock, _host_key):
        resp = self.client.post(
            "/api/v1/connect",
            json={"host": "192.168.99.230", "user": "admin", "password": "falsch"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"], "auth_failed")

    @patch("routes_basis.ensure_host_key_trusted")
    @patch("routes_basis.run_command", side_effect=RouterUnreachable("No route to host"))
    def test_connect_unreachable(self, _mock, _host_key):
        resp = self.client.post(
            "/api/v1/connect",
            json={"host": "10.0.0.1", "user": "admin", "password": "irgendwas"},
        )
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.get_json()["error"], "router_unreachable")

    @patch("routes_basis.ensure_host_key_trusted", side_effect=HostKeyUnknown("SHA256:abc123", "ssh-ed25519", "host ssh-ed25519 AAAA"))
    def test_connect_rejects_unknown_host_key_without_confirmation(self, _host_key):
        with patch("routes_basis.run_command") as run_command:
            resp = self.client.post(
                "/api/v1/connect",
                json={"host": "192.168.99.230", "user": "admin", "password": "geheim"},
            )
        self.assertEqual(resp.status_code, 428)
        data = resp.get_json()
        self.assertEqual(data["error"], "host_key_unknown")
        self.assertEqual(data["fingerprint"], "SHA256:abc123")
        self.assertEqual(data["key_type"], "ssh-ed25519")
        run_command.assert_not_called()

    @patch("routes_basis.trust_host_key")
    @patch(
        "routes_basis.ensure_host_key_trusted",
        side_effect=HostKeyUnknown("SHA256:abc123", "ssh-ed25519", "host ssh-ed25519 AAAA"),
    )
    def test_connect_trusts_host_key_with_matching_confirmation(self, _host_key, mock_trust):
        with patch("routes_basis.run_command", side_effect=lambda *args, **kwargs: FAKE_OUTPUT.get(args[-1], "")):
            resp = self.client.post(
                "/api/v1/connect",
                json={
                    "host": "192.168.99.230", "user": "admin", "password": "geheim",
                    "confirm_fingerprint": "SHA256:abc123",
                },
            )
        self.assertEqual(resp.status_code, 200)
        mock_trust.assert_called_once_with(app_module.cfg.known_hosts_path, "host ssh-ed25519 AAAA")

    @patch(
        "routes_basis.ensure_host_key_trusted",
        side_effect=HostKeyUnknown("SHA256:abc123", "ssh-ed25519", "host ssh-ed25519 AAAA"),
    )
    def test_connect_rejects_mismatched_confirmation(self, _host_key):
        with patch("routes_basis.run_command") as run_command:
            resp = self.client.post(
                "/api/v1/connect",
                json={
                    "host": "192.168.99.230", "user": "admin", "password": "geheim",
                    "confirm_fingerprint": "SHA256:andererwert",
                },
            )
        self.assertEqual(resp.status_code, 428)
        self.assertEqual(resp.get_json()["error"], "host_key_unknown")
        run_command.assert_not_called()

    @patch("routes_basis.ensure_host_key_trusted", side_effect=HostKeyChanged("SHA256:neu999", "ssh-ed25519"))
    def test_connect_rejects_changed_host_key_with_no_override(self, _host_key):
        with patch("routes_basis.run_command") as run_command:
            resp = self.client.post(
                "/api/v1/connect",
                json={
                    "host": "192.168.99.230", "user": "admin", "password": "geheim",
                    "confirm_fingerprint": "SHA256:neu999",
                },
            )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["error"], "host_key_changed")
        run_command.assert_not_called()

    def test_disconnect_clears_session(self):
        resp = self.client.post("/api/v1/disconnect", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(self.session_id, core_module.SESSIONS)
        # Sitzung ist jetzt weg -- ein weiterer Aufruf mit demselben Header muss abgelehnt werden.
        follow_up = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(follow_up.status_code, 401)

    def test_disconnect_without_session_is_idempotent(self):
        resp = self.client.post("/api/v1/disconnect")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": True})

    @patch("core.router", side_effect=fake_router)
    def test_session_status(self, _mock):
        resp = self.client.get("/api/v1/session", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["session"], self.session_id)
        self.assertEqual(data["router_identity"], "L009")

    @patch("core.router", side_effect=fake_router)
    def test_status(self, _mock):
        resp = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["internet"], "up")
        self.assertEqual(data["internet_detail"], "ok")
        self.assertEqual(data["wan_ip"], "203.0.113.7")
        self.assertEqual(data["connected_devices"], 1)
        self.assertEqual(data["router_identity"], "L009")

    @patch("core.router")
    def test_status_down_without_link(self, mock_router):
        # Audit A16: Link tot -- der offensichtlichste der drei Ausfallgruende.
        def fake(command):
            if command == '/interface print terse where name="ether1"':
                return ' 0 X name="ether1" running=false\n'
            return fake_router(command)
        mock_router.side_effect = fake
        resp = self.client.get("/api/v1/status", headers=self.headers)
        data = resp.get_json()
        self.assertEqual(data["internet"], "down")
        self.assertEqual(data["internet_detail"], "no_link")

    @patch("core.router")
    def test_status_down_without_wan_address(self, mock_router):
        # Audit A16: Kabel drin und Link oben, aber keine Adresse (z.B. DHCP haengt) --
        # bisher haette das faelschlich "internet up" ergeben.
        def fake(command):
            if command == '/ip address print terse where interface="ether1"':
                return ""
            return fake_router(command)
        mock_router.side_effect = fake
        resp = self.client.get("/api/v1/status", headers=self.headers)
        data = resp.get_json()
        self.assertEqual(data["internet"], "down")
        self.assertEqual(data["internet_detail"], "no_address")
        self.assertIsNone(data["wan_ip"])

    @patch("core.router")
    def test_status_down_without_default_route(self, mock_router):
        # Audit A16: Adresse da, aber keine aktive Default-Route (z.B. ISP down, Gateway tot) --
        # der eigentliche Kernfund des Audits: reiner Linkstatus haette das nicht erkannt.
        def fake(command):
            if command == '/ip route print terse where dst-address="0.0.0.0/0" and active=yes':
                return ""
            return fake_router(command)
        mock_router.side_effect = fake
        resp = self.client.get("/api/v1/status", headers=self.headers)
        data = resp.get_json()
        self.assertEqual(data["internet"], "down")
        self.assertEqual(data["internet_detail"], "no_default_route")

    @patch("core.router")
    def test_capabilities_report_configured_features(self, mock_router):
        outputs = {
            "/interface wireless print terse": '0 R name="wlan-haupt"\n',
            "/interface wifi print terse": "",
            '/interface print terse where type="wlan"': '0 R name="wlan-haupt" type=wlan\n',
            "/interface wireguard print terse": '0 R name="wg-vpn" listen-port=13231\n',
            "/ip route print terse": '0 A dst-address=0.0.0.0/0 gateway=192.168.88.1\n',
        }
        mock_router.side_effect = lambda command: outputs[command]
        resp = self.client.get("/api/v1/capabilities", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {
            "tier": app_module.app.config["COCKPIT_TIER"],
            "wifi": {"supported": True, "configured": True, "drivers": ["wireless"]},
            "wireguard": {"supported": True, "configured": True},
            "routing": {"supported": True, "configured": True},
        })

    @patch("core.router")
    def test_capabilities_report_unconfigured_features_without_error(self, mock_router):
        def fake(command):
            if command == "/interface wifi print terse":
                raise RouterUnreachable("")
            return ""
        mock_router.side_effect = fake
        resp = self.client.get("/api/v1/capabilities", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {
            "tier": app_module.app.config["COCKPIT_TIER"],
            "wifi": {"supported": False, "configured": False, "drivers": []},
            "wireguard": {"supported": True, "configured": False},
            "routing": {"supported": True, "configured": False},
        })

    @patch("core.router", side_effect=fake_router)
    def test_router_identity_put(self, mock_router):
        resp = self.client.put(
            "/api/v1/router-identity",
            json={"name": "L009 Hauptrouter"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": True, "router_identity": "L009 Hauptrouter"})
        mock_router.assert_called_once_with('/system identity set name="L009 Hauptrouter"')

    @patch("core.router", side_effect=fake_router)
    def test_router_identity_put_rejects_unsafe_name(self, mock_router):
        resp = self.client.put(
            "/api/v1/router-identity",
            json={"name": 'L009"; /system reboot'}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_router_identity_put_escapes_dollar_sign(self, mock_router):
        # Abschlussrunde, 10.09.2026: router_identity_put() rief bisher nie _routeros_text()/
        # _routeros_escape() auf -- ein "$" im Namen ging unescaped in den RouterOS-Befehl.
        # RouterOS interpretiert ein unmaskiertes "$" in einem String als Variablenreferenz
        # und ersetzt es still durch deren (leeren) Wert, siehe _routeros_escape()-Kommentar.
        resp = self.client.put(
            "/api/v1/router-identity",
            json={"name": "L009 $HOSTNAME"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        mock_router.assert_called_once_with('/system identity set name="L009 \\$HOSTNAME"')
        # Die Antwort zeigt weiter den vom Nutzer eingegebenen Klartext -- nur der an
        # RouterOS gesendete Befehl muss escaped sein.
        self.assertEqual(resp.get_json()["router_identity"], "L009 $HOSTNAME")

    @patch("core.router", side_effect=fake_router)
    def test_router_identity_put_rejects_control_characters(self, mock_router):
        # "\t"/"\x00" etc. am Rand werden von .strip() im Endpunkt entfernt -- deshalb hier in
        # der Namensmitte platziert, wo nur die Steuerzeichen-Pruefung selbst greifen kann.
        for name in ("Te\x00st", "Te\tst", "Te\x7fst"):
            with self.subTest(name=name):
                resp = self.client.put(
                    "/api/v1/router-identity",
                    json={"name": name}, headers=self.headers,
                )
                self.assertEqual(resp.status_code, 400)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_devices(self, _mock):
        resp = self.client.get("/api/v1/devices", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["mac"], "b8:27:eb:12:34:56")
        self.assertEqual(data[0]["hostname"], "shelly-kueche")
        self.assertTrue(data[0]["active"])

    @patch("core.router", side_effect=fake_router)
    def test_devices_room_defaults_to_null_without_mapping(self, _mock):
        # Phase B, 10.09.2026: frisches/leeres Mapping (noch keine Datei angelegt) darf nicht
        # crashen -- "room" muss einfach null sein.
        resp = self.client.get("/api/v1/devices", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.get_json()[0]["room"])

    def test_device_room_set_then_appears_in_devices(self):
        resp = self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": "Wohnzimmer"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["mac"], "b8:27:eb:12:34:56")
        self.assertEqual(data["room"], "Wohnzimmer")
        with patch("core.router", side_effect=fake_router):
            devices_resp = self.client.get("/api/v1/devices", headers=self.headers)
        self.assertEqual(devices_resp.get_json()[0]["room"], "Wohnzimmer")

    def test_device_room_accepts_uppercase_mac(self):
        # Gleiche Grossschreibungstoleranz wie device_connection_delete(); intern immer
        # kleingeschrieben gespeichert, damit es zu row.get("mac-address", "").lower() passt.
        resp = self.client.put(
            "/api/v1/devices/B8:27:EB:12:34:56/room",
            json={"room": "Buero"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["mac"], "b8:27:eb:12:34:56")

    def test_device_room_clear_with_null(self):
        self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": "Büro"}, headers=self.headers,
        )
        resp = self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": None}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.get_json()["room"])
        with patch("core.router", side_effect=fake_router):
            devices_resp = self.client.get("/api/v1/devices", headers=self.headers)
        self.assertIsNone(devices_resp.get_json()[0]["room"])

    def test_device_room_clear_with_empty_string(self):
        self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": "Küche"}, headers=self.headers,
        )
        resp = self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": ""}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.get_json()["room"])

    def test_device_room_clear_missing_body_key_treated_as_null(self):
        self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": "Flur"}, headers=self.headers,
        )
        resp = self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.get_json()["room"])

    def test_device_room_rejects_invalid_mac(self):
        for bad_mac in ("not-a-mac", "b8:27:eb:12:34", "b8:27:eb:12:34:56:78", "zz:27:eb:12:34:56"):
            with self.subTest(bad_mac=bad_mac):
                resp = self.client.put(
                    f"/api/v1/devices/{bad_mac}/room",
                    json={"room": "Wohnzimmer"}, headers=self.headers,
                )
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(resp.get_json()["error"], "bad_request")

    def test_device_room_rejects_too_long(self):
        resp = self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": "x" * 41}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "bad_request")

    def test_device_room_accepts_exactly_forty_bytes(self):
        resp = self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": "x" * 40}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)

    def test_device_room_rejects_control_characters(self):
        for bad_room in ("Wohnzimmer\tKueche", "Buero\r\n", "Kel\x00ler", "Flur\x7f"):
            with self.subTest(bad_room=repr(bad_room)):
                resp = self.client.put(
                    "/api/v1/devices/b8:27:eb:12:34:56/room",
                    json={"room": bad_room}, headers=self.headers,
                )
                self.assertEqual(resp.status_code, 400)

    def test_device_room_allows_quotes_and_semicolons(self):
        # Anders als bei _routeros_text() sind Anfuehrungszeichen/Semikolon hier unbedenklich --
        # der Wert geht nie in einen RouterOS-Befehl, nur in eine JSON-Datei (json.dump()
        # maskiert korrekt). Nur Steuerzeichen sind gesperrt.
        resp = self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room",
            json={"room": 'Annas "Büro"; Flur'}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["room"], 'Annas "Büro"; Flur')

    def test_device_room_rejects_non_string(self):
        for bad_value in (123, ["Wohnzimmer"], {"x": 1}, True):
            with self.subTest(bad_value=bad_value):
                resp = self.client.put(
                    "/api/v1/devices/b8:27:eb:12:34:56/room",
                    json={"room": bad_value}, headers=self.headers,
                )
                self.assertEqual(resp.status_code, 400)

    def test_device_room_requires_session(self):
        resp = self.client.put(
            "/api/v1/devices/b8:27:eb:12:34:56/room", json={"room": "Wohnzimmer"},
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"], "not_connected")

    def test_device_room_is_isolated_per_router(self):
        # Gleiches Muster wie die Backup-Ordner-Isolation (Audit A13): zwei Router mit
        # demselben Hostnamen, aber unterschiedlichem SSH-Port, teilen sich die Zuordnung nicht.
        other_session = "other-router-session"
        core_module.SESSIONS[other_session] = {
            "host": "test-host", "user": "admin", "password": "test-pass", "ssh_port": 2222,
        }
        try:
            self.client.put(
                "/api/v1/devices/b8:27:eb:12:34:56/room",
                json={"room": "Wohnzimmer"}, headers=self.headers,
            )
            with patch("core.router", side_effect=fake_router):
                own_resp = self.client.get("/api/v1/devices", headers=self.headers)
                other_resp = self.client.get(
                    "/api/v1/devices", headers={"X-Cockpit-Session": other_session},
                )
            self.assertEqual(own_resp.get_json()[0]["room"], "Wohnzimmer")
            self.assertIsNone(other_resp.get_json()[0]["room"])
        finally:
            core_module.SESSIONS.pop(other_session, None)

    @patch("core.router", side_effect=fake_router)
    def test_device_rooms_file_corrupted_does_not_crash(self, _mock):
        # Anforderung 6 aus dem Auftrag: ein frisches/leeres Mapping darf nie abstuerzen --
        # das gilt auch, wenn die Datei durch einen Absturz mittendrin kaputt zurueckblieb.
        first = self.client.get("/api/v1/devices", headers=self.headers)
        self.assertEqual(first.status_code, 200)
        rooms_path = os.path.join(app_module.cfg.device_rooms_dir, "test-host_22.json")
        with open(rooms_path, "w", encoding="utf-8") as fh:
            fh.write("{kaputtes json, kein gueltiges Objekt")
        resp = self.client.get("/api/v1/devices", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.get_json()[0]["room"])

    def test_device_rooms_dir_default_is_not_under_tmp(self):
        had_env = "COCKPIT_DEVICE_ROOMS_DIR" in os.environ
        saved = os.environ.pop("COCKPIT_DEVICE_ROOMS_DIR", None)
        try:
            default_dir = config_module.Config().device_rooms_dir
        finally:
            if had_env:
                os.environ["COCKPIT_DEVICE_ROOMS_DIR"] = saved
        self.assertFalse(default_dir.startswith("/tmp"))
        self.assertIn(".config/mikrotik-cockpit", default_dir)

    def test_device_rooms_dir_rejects_insecure_existing_directory(self):
        # Gleiches Muster wie test_backup_dir_rejects_insecure_existing_directory: ein anderer
        # lokaler Nutzer koennte das Verzeichnis vor dem ersten Cockpit-Start selbst anlegen.
        insecure_base = tempfile.mkdtemp(prefix="cockpit-test-insecure-rooms-")
        os.chmod(insecure_base, 0o777)
        original = app_module.cfg.device_rooms_dir
        app_module.cfg.device_rooms_dir = insecure_base
        try:
            resp = self.client.put(
                "/api/v1/devices/b8:27:eb:12:34:56/room",
                json={"room": "Wohnzimmer"}, headers=self.headers,
            )
            self.assertEqual(resp.status_code, 500)
            self.assertEqual(resp.get_json()["error"], "device_rooms_storage_unsafe")
        finally:
            app_module.cfg.device_rooms_dir = original
            os.chmod(insecure_base, 0o700)

    def test_device_disconnect_targets_both_wifi_drivers(self):
        for driver in ("wireless", "wifi"):
            with self.subTest(driver=driver):
                path = f"/interface {driver} registration-table"
                def reply(command):
                    if command == f'{path} print terse where mac-address="AA:BB:CC:DD:EE:FF"':
                        return '0 interface=wlan1 mac-address=AA:BB:CC:DD:EE:FF'
                    return ""
                with patch("core.router", side_effect=reply) as router:
                    response = self.client.delete("/api/v1/devices/aa:bb:cc:dd:ee:ff/connection", headers=self.headers)
                self.assertEqual(response.status_code, 202)
                self.assertTrue(response.get_json()["may_reconnect"])
                self.assertEqual(router.call_args.args[0], f'{path} remove [find where mac-address="AA:BB:CC:DD:EE:FF" and interface="wlan1"]')
                self.assertEqual(router.call_count, 3)

    def test_device_disconnect_missing_driver_and_unexpected_remove_output(self):
        for remove_output, expected in (("", 202), ("bad command name remove", 502)):
            with self.subTest(remove_output=remove_output):
                def reply(command):
                    if command.startswith("/interface wireless"):
                        return "bad command name wireless (line 1 column 12)"
                    if " print " in command:
                        return "0 interface=wifi1 mac-address=AA:BB:CC:DD:EE:FF"
                    return remove_output
                with patch("core.router", side_effect=reply):
                    response = self.client.delete("/api/v1/devices/aa:bb:cc:dd:ee:ff/connection", headers=self.headers)
                self.assertEqual(response.status_code, expected)

    @patch("core.router")
    def test_device_disconnect_rejects_invalid_mac(self, router):
        response = self.client.delete("/api/v1/devices/invalid/connection", headers=self.headers)
        self.assertEqual(response.status_code, 400)
        router.assert_not_called()

    def test_device_disconnect_never_deletes_leases_or_ambiguous_clients(self):
        for output, expected in (("", 409), ("unreadable", 502),
                                 ("0 interface=wlan1 mac-address=AA:BB:CC:DD:EE:FF", 409),
                                 ("0 interface=wlan1 mac-address=11:22:33:44:55:66", 502)):
            with self.subTest(output=output), patch("core.router", return_value=output) as router:
                response = self.client.delete("/api/v1/devices/aa:bb:cc:dd:ee:ff/connection", headers=self.headers)
                self.assertEqual(response.status_code, expected)
                self.assertTrue(all(" print " in call.args[0] for call in router.call_args_list))

    @patch("core.router", side_effect=RouterUnreachable("transport failed"))
    def test_device_disconnect_transport_failure_is_not_success(self, router):
        response = self.client.delete("/api/v1/devices/aa:bb:cc:dd:ee:ff/connection", headers=self.headers)
        self.assertGreaterEqual(response.status_code, 500)
        self.assertEqual(router.call_count, 1)

    @patch("core.router", side_effect=fake_router)
    def test_wifi_list_empty_on_router_without_wireless(self, _mock):
        resp = self.client.get("/api/v1/wifi", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), [])

    def test_wifi_list_falls_back_when_wireless_package_missing(self):
        # Live-Fund an einem L009 (10.09.2026): Geraete mit nur dem neueren
        # wifi-Treiber lassen "/interface wireless print terse" mit "bad command name wireless"
        # scheitern -- das ist RouterCommandFailed, nicht RouterUnreachable. Ohne den Fang
        # brach GET /wifi mit einem Serverfehler ab, obwohl der wifi-Treiber-Zweig laengst
        # existierte.
        def reply(command):
            if command == "/interface wireless print terse":
                raise RouterCommandFailed("bad command name wireless (line 1 column 12)")
            if command == "/interface wifi print terse":
                return "0 name=wifi1 configuration.ssid=Heimnetz running=true"
            return ""
        with patch("core.router", side_effect=reply):
            response = self.client.get("/api/v1/wifi", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        rows = response.get_json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["driver"], "wifi")
        self.assertEqual(rows[0]["ssid"], "Heimnetz")

    def test_wireless_driver_falls_back_to_wifi_when_wireless_package_missing(self):
        # Gleicher Live-Fund, diesmal fuer _wireless_driver() (wifi_ssid()/wifi_password()):
        # ohne den Fang von RouterCommandFailed wurde der "wifi"-Zweig nie erreicht, WLAN-Name/
        # -Passwort waren auf reinen wifi-Treiber-Geraeten komplett unbedienbar.
        def reply(command):
            if command.startswith("/interface wireless print terse"):
                raise RouterCommandFailed("bad command name wireless (line 1 column 12)")
            if command.startswith("/interface wifi print terse"):
                return "0 name=wifi1"
            return ""
        with patch("core.router", side_effect=reply):
            response = self.client.put(
                "/api/v1/wifi/wifi1/ssid", headers=self.headers, json={"ssid": "Heimnetz"}
            )
        self.assertEqual(response.status_code, 200)

    def test_wifi_list_reports_status_for_both_drivers(self):
        for driver in ("wireless", "wifi"):
            for output, running, disabled in (
                ('0 R name=wlan-test', True, False),
                ('0 X name=wlan-test', False, True),
                ('0 name=wlan-test', False, False),
                ('0 name=wlan-test running=true disabled=false', True, False),
                ('0 name=wlan-test running=false disabled=true', False, True),
            ):
                with self.subTest(driver=driver, output=output):
                    command = f"/interface {driver} print terse"
                    with patch("core.router", side_effect=lambda cmd: output if cmd == command else ""):
                        response = self.client.get("/api/v1/wifi", headers=self.headers)
                    self.assertEqual(response.status_code, 200)
                    rows = response.get_json()
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["driver"], driver)
                    self.assertIs(rows[0]["running"], running)
                    self.assertIs(rows[0]["disabled"], disabled)

    @patch("core.router", side_effect=fake_router)
    def test_wifi_ssid_put(self, mock_router):
        resp = self.client.put(
            "/api/v1/wifi/wlan-haupt/ssid",
            json={"ssid": "Neues Home-Net"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["ssid"], "Neues Home-Net")
        mock_router.assert_any_call(
            '/interface wireless set [find name="wlan-haupt"] ssid="Neues Home-Net"'
        )

    @patch("core.router")
    def test_wifi_ssid_rejects_invalid_value(self, mock_router):
        resp = self.client.put(
            "/api/v1/wifi/wlan-haupt/ssid",
            json={"ssid": 'unsafe; /system reboot'}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "invalid_ssid")
        mock_router.assert_not_called()

    @patch("core.router")
    def test_wifi_ssid_escapes_dollar_sign_in_interface_name(self, mock_router):
        # Audit Runde 4, 09.09.: wifi_ssid() maskierte den Interface-Namen bisher per Hand nur
        # fuer Backslashes ("interface.replace('\\\\', '\\\\\\\\')"), nicht ueber die sonst
        # ueberall genutzte _routeros_value() -- ein Dollarzeichen im Namen waere unmaskiert im
        # Set-Befehl gelandet. Dieser Test haelt fest, dass jetzt konsequent escaped wird.
        mock_router.side_effect = [
            '0  name="wlan\\$test" ssid="Alt"\n',  # Treiber-Erkennung (wireless, Treffer)
            "",  # set-Befehl
        ]
        resp = self.client.put(
            "/api/v1/wifi/wlan$test/ssid", json={"ssid": "Neu"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        mock_router.assert_any_call(
            '/interface wireless set [find name="wlan\\$test"] ssid="Neu"'
        )

    @patch("core.router")
    def test_guest_isolation_only_accepts_explicit_drop_before_allow(self, mock_router):
        cases = [
            ('0 action=drop in-interface=wlan-gast out-interface-list=LAN disabled=false\n', True),
            ('0 action=accept in-interface=wlan-gast out-interface-list=LAN disabled=false\n'
             '1 action=drop in-interface=wlan-gast out-interface-list=LAN disabled=false\n', False),
            ('0 action=drop in-interface=wlan-gast out-interface-list=WAN disabled=false\n', None),
        ]
        for output, expected in cases:
            with self.subTest(expected=expected):
                mock_router.reset_mock(return_value=True)
                mock_router.return_value = output
                self.assertIs(core_module._guest_isolation("wlan-gast"), expected)

    @patch("core.router")
    def test_guest_isolation_earlier_general_accept_without_out_interface_list_wins(self, mock_router):
        # Audit Runde 5, Befund 2a: eine FRUEHERE, allgemeinere Accept-Regel ohne gesetzte
        # "out-interface-list" (matcht in RouterOS trotzdem JEDES Zielinterface, auch LAN)
        # wurde bisher uebersehen, weil die alte Pruefung nur Regeln mit exakt
        # "out-interface-list=LAN" ueberhaupt betrachtete. Die spaetere, praezise Drop-Regel
        # greift dadurch nie, RouterOS wertet die frueher stehende Accept-Regel zuerst aus.
        mock_router.return_value = (
            '0 action=accept in-interface=wlan-gast disabled=false\n'
            '1 action=drop in-interface=wlan-gast out-interface-list=LAN disabled=false\n'
        )
        self.assertIs(core_module._guest_isolation("wlan-gast"), False)

    @patch("core.router")
    def test_guest_isolation_requires_full_protocol_coverage(self, mock_router):
        # Audit Runde 5, Befund 2b: eine Drop-Regel, die nur ein einzelnes Protokoll/Port
        # sperrt (hier TCP Port 80), darf nicht als vollstaendige Isolation gelten -- jeder
        # andere Port/jedes andere Protokoll bleibt offen.
        mock_router.return_value = (
            '0 action=drop in-interface=wlan-gast out-interface-list=LAN protocol=tcp '
            'dst-port=80 disabled=false\n'
        )
        self.assertIsNone(core_module._guest_isolation("wlan-gast"))

    @patch("core.router")
    def test_guest_isolation_ignores_established_related_accept(self, mock_router):
        # Eine Standardregel wie "accept established,related,untracked" darf eine spaeter
        # folgende, vollstaendige Drop-Regel nicht entwerten -- sie kann keine NEUE
        # Verbindung vom Gastnetz ins Hausnetz eroeffnen.
        mock_router.return_value = (
            '0 action=accept connection-state=established,related,untracked disabled=false\n'
            '1 action=drop in-interface=wlan-gast out-interface-list=LAN disabled=false\n'
        )
        self.assertIs(core_module._guest_isolation("wlan-gast"), True)

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_list(self, _mock):
        resp = self.client.get("/api/v1/port-forwards", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], "pf-aaaa1111")
        self.assertEqual(data[0]["name"], "Kamera Einfahrt")

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_create_conflict(self, _mock):
        resp = self.client.post(
            "/api/v1/port-forwards",
            json={"name": "x", "protocol": "tcp", "external_port": 8080,
                  "internal_ip": "192.168.178.61", "internal_port": 80},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 409)

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_create_success(self, _mock):
        resp = self.client.post(
            "/api/v1/port-forwards",
            json={"name": "NAS", "protocol": "tcp", "external_port": 9090,
                  "internal_ip": "192.168.178.62", "internal_port": 5001},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(resp.get_json()["id"].startswith("pf-"))

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_delete_not_found(self, _mock):
        resp = self.client.delete("/api/v1/port-forwards/pf-doesnotexist", headers=self.headers)
        self.assertEqual(resp.status_code, 404)

    @patch("core.router", side_effect=fake_router)
    def test_backup_create_and_list(self, mock_router):
        def fake_download(host, user, password, port, remote_name, local_path, timeout=20, known_hosts_path=None):
            open(local_path, "wb").close()

        with patch("routes_basis.download_file", side_effect=fake_download) as mock_download:
            resp = self.client.post("/api/v1/backup", headers=self.headers)
        self.assertEqual(resp.status_code, 201)
        backup_id = resp.get_json()["id"]
        mock_download.assert_called_once()

        list_resp = self.client.get("/api/v1/backup", headers=self.headers)
        ids = [item["id"] for item in list_resp.get_json()]
        self.assertIn(backup_id, ids)

    @patch("core.router", side_effect=fake_router)
    def test_backup_download_not_found(self, _mock):
        resp = self.client.get("/api/v1/backup/does-not-exist/download", headers=self.headers)
        self.assertEqual(resp.status_code, 404)

    @patch("core.router", side_effect=fake_router)
    def test_backups_are_separated_per_router(self, mock_router):
        # Audit A13: Backups von unterschiedlichen Routern duerfen sich nicht in einer
        # gemeinsamen Liste vermischen.
        def fake_download(host, user, password, port, remote_name, local_path, timeout=20, known_hosts_path=None):
            open(local_path, "wb").close()

        with patch("routes_basis.download_file", side_effect=fake_download):
            resp_a = self.client.post("/api/v1/backup", headers=self.headers)
        backup_id_a = resp_a.get_json()["id"]

        other_session = "test-session-router-b"
        core_module.SESSIONS[other_session] = {
            "host": "192.168.99.99", "user": "admin", "password": "andere-pass", "ssh_port": 22,
        }
        with patch("routes_basis.download_file", side_effect=fake_download):
            self.client.post("/api/v1/backup", headers={"X-Cockpit-Session": other_session})

        list_router_a = self.client.get("/api/v1/backup", headers=self.headers).get_json()
        list_router_b = self.client.get(
            "/api/v1/backup", headers={"X-Cockpit-Session": other_session}
        ).get_json()
        self.assertIn(backup_id_a, [item["id"] for item in list_router_a])
        self.assertNotIn(backup_id_a, [item["id"] for item in list_router_b])

    @patch("core.router", side_effect=fake_router)
    def test_backups_are_separated_per_port_on_same_host(self, mock_router):
        # Audit Runde 5, Befund 5a: derselbe Host mit unterschiedlichem SSH-Port (z.B. zwei
        # Router hinter derselben IP per Portweiterleitung) darf sich keinen Backup-Ordner
        # teilen -- bisher zaehlte ausschliesslich der Host.
        def fake_download(host, user, password, port, remote_name, local_path, timeout=20, known_hosts_path=None):
            open(local_path, "wb").close()

        with patch("routes_basis.download_file", side_effect=fake_download):
            resp_a = self.client.post("/api/v1/backup", headers=self.headers)
        backup_id_a = resp_a.get_json()["id"]

        other_port_session = "test-session-same-host-other-port"
        core_module.SESSIONS[other_port_session] = {
            "host": "test-host", "user": "admin", "password": "test-pass", "ssh_port": 2222,
        }
        with patch("routes_basis.download_file", side_effect=fake_download):
            self.client.post("/api/v1/backup", headers={"X-Cockpit-Session": other_port_session})

        list_port_22 = self.client.get("/api/v1/backup", headers=self.headers).get_json()
        list_port_2222 = self.client.get(
            "/api/v1/backup", headers={"X-Cockpit-Session": other_port_session}
        ).get_json()
        self.assertIn(backup_id_a, [item["id"] for item in list_port_22])
        self.assertNotIn(backup_id_a, [item["id"] for item in list_port_2222])

    @patch("core.router", side_effect=fake_router)
    def test_backup_download_rejects_symlink(self, mock_router):
        # Audit Runde 5, Befund 5b: send_file() folgt anstandslos einem symbolischen Link --
        # landet je eine praeparierte Datei mit passendem Namen im Backup-Ordner, koennte
        # darueber beliebiger Dateiinhalt ausgeliefert werden.
        def fake_download(host, user, password, port, remote_name, local_path, timeout=20, known_hosts_path=None):
            open(local_path, "wb").write(b"echtes backup")

        with patch("routes_basis.download_file", side_effect=fake_download):
            resp = self.client.post("/api/v1/backup", headers=self.headers)
        backup_id = resp.get_json()["id"]

        # Pfad ohne aktiven Request-Kontext nachbauen (gleiche Regel wie
        # _backup_dir_for_current_router(): Host "test-host", Port 22 aus self.headers).
        backup_dir = os.path.join(app_module.cfg.backup_dir, "test-host_22")
        real_path = os.path.join(backup_dir, f"{backup_id}.backup")
        outside_secret = os.path.join(tempfile.mkdtemp(prefix="cockpit-test-outside-"), "secret.txt")
        with open(outside_secret, "wb") as fh:
            fh.write(b"geheime daten, die nicht ausgeliefert werden duerfen")
        os.remove(real_path)
        os.symlink(outside_secret, real_path)

        download_resp = self.client.get(f"/api/v1/backup/{backup_id}/download", headers=self.headers)
        self.assertEqual(download_resp.status_code, 404)
        self.assertNotIn(b"geheime daten", download_resp.data)

    def test_backup_dir_default_is_not_under_tmp(self):
        # Abschlussrunde, 10.09.2026: der Default von COCKPIT_BACKUP_DIR lag bisher unter
        # /tmp -- world-lesbares/-betretbares Verzeichnis mit vorhersehbarem Namen (gleiches
        # Muster wie der known_hosts-Fund aus Runde 3). Jetzt ein privates ~/.config-Verzeichnis.
        had_env = "COCKPIT_BACKUP_DIR" in os.environ
        saved = os.environ.pop("COCKPIT_BACKUP_DIR", None)
        try:
            default_backup_dir = config_module.Config().backup_dir
        finally:
            if had_env:
                os.environ["COCKPIT_BACKUP_DIR"] = saved
        self.assertFalse(default_backup_dir.startswith("/tmp"))
        self.assertIn(".config/mikrotik-cockpit", default_backup_dir)

    @patch("core.router", side_effect=fake_router)
    def test_backup_dir_rejects_insecure_existing_directory(self, mock_router):
        # Abschlussrunde, 10.09.2026: der bisherige /tmp-Default von COCKPIT_BACKUP_DIR (jetzt
        # ~/.config/mikrotik-cockpit/backups) war das gleiche Muster wie der known_hosts-Fund aus
        # Runde 3 -- ein anderer lokaler Nutzer koennte den Ordner vorab anlegen. _ensure_private_dir()
        # verweigert deshalb jedem schon vorhandenen, fuer Gruppe/Andere zugaenglichen Verzeichnis
        # das Vertrauen, unabhaengig vom konkreten Pfad (auch bei frei konfiguriertem COCKPIT_BACKUP_DIR).
        insecure_base = tempfile.mkdtemp(prefix="cockpit-test-insecure-backups-")
        os.chmod(insecure_base, 0o777)
        original = app_module.cfg.backup_dir
        app_module.cfg.backup_dir = insecure_base
        try:
            resp = self.client.get("/api/v1/backup", headers=self.headers)
            self.assertEqual(resp.status_code, 500)
            self.assertEqual(resp.get_json()["error"], "backup_storage_unsafe")
        finally:
            app_module.cfg.backup_dir = original
            os.chmod(insecure_base, 0o700)

    @patch("core.router", side_effect=fake_router)
    def test_backup_download_rejects_malformed_id(self, mock_router):
        resp = self.client.get(
            "/api/v1/backup/../../etc/passwd/download", headers=self.headers,
        )
        self.assertIn(resp.status_code, (404, 301))

    @patch("core.router", side_effect=fake_router)
    def test_backup_restore_rejects_malformed_id(self, _mock):
        with patch("routes_basis.upload_file") as mock_upload:
            resp = self.client.post(
                "/api/v1/backup/../../etc/passwd/restore",
                headers=self.headers, json={"confirm": True},
            )
        # Werkzeug normalisiert "../.." teils schon beim Routing (301-Redirect oder 405 auf
        # einer anderen, dabei getroffenen Regel) -- entscheidend ist einzig, dass unser
        # eigener Handler nie mit dem Pfad-Traversal-String aufgerufen wird (siehe unten).
        self.assertIn(resp.status_code, (404, 301, 405))
        mock_upload.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_backup_restore_requires_confirmation(self, mock_router):
        def fake_download(host, user, password, port, remote_name, local_path, timeout=20, known_hosts_path=None):
            open(local_path, "wb").close()

        with patch("routes_basis.download_file", side_effect=fake_download):
            create_resp = self.client.post("/api/v1/backup", headers=self.headers)
        backup_id = create_resp.get_json()["id"]
        mock_router.reset_mock()

        with patch("routes_basis.upload_file") as mock_upload:
            resp = self.client.post(f"/api/v1/backup/{backup_id}/restore", headers=self.headers)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "confirmation_required")
        mock_upload.assert_not_called()
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_backup_restore_rejects_non_object_json_without_router_access(self, mock_router):
        backup_id = "bkp-2026-01-01-000000-abcd"
        with patch("routes_basis.upload_file") as mock_upload:
            for body in ([], True, "confirm"):
                with self.subTest(body=body):
                    resp = self.client.post(
                        f"/api/v1/backup/{backup_id}/restore",
                        headers=self.headers, json=body,
                    )
                    self.assertEqual(resp.status_code, 400)
                    self.assertEqual(resp.get_json()["error"], "bad_request")
            mock_upload.assert_not_called()
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_backup_restore_not_found_for_unknown_backup(self, mock_router):
        with patch("routes_basis.upload_file") as mock_upload:
            resp = self.client.post(
                "/api/v1/backup/bkp-2026-01-01-000000-abcd/restore",
                headers=self.headers, json={"confirm": True},
            )
        self.assertEqual(resp.status_code, 404)
        mock_upload.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_backup_restore_uploads_and_loads_backup(self, mock_router):
        def fake_download(host, user, password, port, remote_name, local_path, timeout=20, known_hosts_path=None):
            open(local_path, "wb").close()

        with patch("routes_basis.download_file", side_effect=fake_download):
            create_resp = self.client.post("/api/v1/backup", headers=self.headers)
        backup_id = create_resp.get_json()["id"]
        mock_router.reset_mock()

        with patch("routes_basis.upload_file") as mock_upload:
            resp = self.client.post(
                f"/api/v1/backup/{backup_id}/restore",
                headers=self.headers, json={"confirm": True},
            )
        self.assertEqual(resp.status_code, 202)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "restoring")
        self.assertTrue(data["expect_reboot"])
        mock_upload.assert_called_once()
        upload_args = mock_upload.call_args[0]
        self.assertEqual(upload_args[0], "test-host")
        self.assertTrue(upload_args[4].endswith(f"{backup_id}.backup"))
        self.assertEqual(upload_args[5], f"{backup_id}.backup")
        # Live-Fund 09.09.: RouterOS verlangt "password" als Pflichtargument, auch bei einem
        # unverschluesselten Backup -- ohne den Parameter lief der Befehl mit Exitcode 0 und
        # "Script Error: missing value(s)..." durch, ohne den Router tatsaechlich neu zu laden.
        mock_router.assert_called_once_with(f'/system backup load name="{backup_id}" password=""')

    @patch("core.router", side_effect=fake_router)
    def test_security_check_warns_and_excludes_unrated_from_score(self, _mock):
        # Kein Override -- die globalen Test-Fixtures liefern absichtlich einen aktiven FTP-
        # Dienst, keine Input-Drop-Regel und eine veraltete Firmware-Version (siehe FAKE_OUTPUT).
        # Kein Gastnetz-Interface in dieser Sitzung ausgewählt und kein Backup für diesen
        # frischen Testhost -> beide "unknown", duerfen den Score nicht verfaelschen.
        session_id = "security-check-warn-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-warn-host", "user": "admin", "password": "x", "ssh_port": 22,
        }
        resp = self.client.get("/api/v1/security-check", headers={"X-Cockpit-Session": session_id})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        by_id = {c["id"]: c for c in data["checks"]}
        self.assertEqual(by_id["services"]["status"], "warn")
        self.assertEqual(by_id["input_firewall"]["status"], "warn")
        self.assertEqual(by_id["firmware"]["status"], "warn")
        self.assertEqual(by_id["guest_isolation"]["status"], "unknown")
        self.assertEqual(by_id["backup"]["status"], "warn")
        self.assertEqual(by_id["default_user"]["status"], "warn")
        self.assertIn("einzige Vollzugang", by_id["default_user"]["detail"])
        self.assertEqual(data["score"], 0)
        # Alltagssprache-Feld (Punkt 5 des Sieben-Punkte-Urteils, 10.09.2026): jeder Check
        # bekommt zusaetzlich zum Fachtext "detail" ein "plain"-Feld. "Kein falsches Gruen":
        # bei warn muss die Empfehlung konkret sein, bei unknown darf der Satz nicht wie eine
        # Sicherheitsbestaetigung klingen.
        for check in data["checks"]:
            self.assertIn("plain", check)
            self.assertTrue(check["plain"])
        self.assertIn("Schalte", by_id["services"]["plain"])
        self.assertIn("Lege", by_id["input_firewall"]["plain"])
        self.assertIn("Erstelle", by_id["backup"]["plain"])
        self.assertIn("Lege", by_id["default_user"]["plain"])
        self.assertNotIn("ist sicher", by_id["guest_isolation"]["plain"].lower())
        self.assertIn("nicht geprüft", by_id["guest_isolation"]["plain"])

    def test_security_check_all_good_scores_100(self):
        session_id = "security-check-good-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-good-host", "user": "admin", "password": "x", "ssh_port": 22,
        }
        headers = {"X-Cockpit-Session": session_id}

        def fake_download(host, user, password, port, remote_name, local_path, timeout=20, known_hosts_path=None):
            # Audit Runde 5: ein echtes RouterOS-Backup hat immer Inhalt -- eine 0-Byte-Datei
            # zaehlt seit dem Fix nicht mehr als "good", die Fixture muss das widerspiegeln.
            open(local_path, "wb").write(b"routeros-backup-fixture-content")

        def good_router(command):
            if command == "/ip service print terse where dynamic=no":
                return "0 X name=ftp port=21 proto=tcp\n1 X name=telnet port=23 proto=tcp\n"
            if command.startswith("/ip firewall filter print terse where chain=input"):
                return "0  chain=input action=drop disabled=false\n"
            if command == "/ipv6 settings print":
                # IPv6 bewusst aus, damit dieser "alles gruen"-Fixture-Router nicht ueber
                # eine unbekannte IPv6-Erreichbarkeit stolpert (Audit "IPv6 Router-
                # Selbstschutz", 10.09.2026) -- separat getestet in test_security_evidence.py.
                return "  disable-ipv6: yes\n"
            if command == "/system package update check-for-updates":
                return ""
            if command == "/system package update print":
                return "  installed-version: 7.24.1\n  latest-version: 7.24.1\n"
            if command == "/user print terse":
                return (
                    " 0 X comment=system default user name=admin group=full inactivity-timeout=10m "
                    "inactivity-policy=none address=\n"
                    " 1   name=marco group=full inactivity-timeout=10m inactivity-policy=none address= "
                    "last-logged-in=2026-09-18 06:10:00\n"
                )
            return fake_router(command)

        with patch("core.router", side_effect=good_router):
            with patch("routes_basis.download_file", side_effect=fake_download):
                self.client.post("/api/v1/backup", headers=headers)
            resp = self.client.get("/api/v1/security-check", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        by_id = {c["id"]: c for c in data["checks"]}
        self.assertEqual(by_id["services"]["status"], "good")
        self.assertEqual(by_id["input_firewall"]["status"], "good")
        self.assertEqual(by_id["firmware"]["status"], "good")
        self.assertEqual(by_id["backup"]["status"], "good")
        self.assertEqual(by_id["default_user"]["status"], "good")
        self.assertEqual(by_id["guest_isolation"]["status"], "unknown")
        self.assertEqual(data["score"], 100)
        for check in data["checks"]:
            self.assertIn("plain", check)
            self.assertTrue(check["plain"])
        # Auch bei durchweg gruenem Ergebnis darf "guest_isolation" (hier unknown, weil kein
        # Gastnetz-Interface gewaehlt ist) nicht wie eine Bestaetigung klingen.
        self.assertNotIn("ist sicher", by_id["guest_isolation"]["plain"].lower())

    def test_security_check_default_user_admin_active_beside_own_full_user_warns(self):
        session_id = "security-check-admin-beside-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-admin-beside-host", "user": "marco", "password": "x", "ssh_port": 22,
        }

        def both_active(command):
            if command == "/user print terse":
                return (
                    " 0   comment=system default user name=admin group=full inactivity-timeout=10m "
                    "inactivity-policy=none address=\n"
                    " 1   name=marco group=full inactivity-timeout=10m inactivity-policy=none address= "
                    "last-logged-in=2026-09-18 06:10:00\n"
                )
            return fake_router(command)

        with patch("core.router", side_effect=both_active):
            resp = self.client.get("/api/v1/security-check", headers={"X-Cockpit-Session": session_id})
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["default_user"]["status"], "warn")
        self.assertIn("noch aktiv", by_id["default_user"]["detail"])
        self.assertIn("Schalte admin", by_id["default_user"]["plain"])

    def test_security_check_default_user_unknown_when_users_unreadable(self):
        session_id = "security-check-users-unknown-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-users-unknown-host", "user": "admin", "password": "x", "ssh_port": 22,
        }

        def failing_users(command):
            if command == "/user print terse":
                raise RouterCommandFailed("not enough permissions (9)")
            return fake_router(command)

        with patch("core.router", side_effect=failing_users):
            resp = self.client.get("/api/v1/security-check", headers={"X-Cockpit-Session": session_id})
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["default_user"]["status"], "unknown")
        self.assertNotIn("ist sicher", by_id["default_user"]["plain"].lower())

    def test_security_check_input_firewall_drop_invalid_only_is_not_good(self):
        # Audit Runde 5, Befund 1: die RouterOS-Standardregel "drop invalid" (nur
        # technisch kaputte Pakete, connection-state=invalid) schuetzt nicht generell
        # gegen unautorisierten Zugriff -- sie darf den Check nicht auf "good" heben.
        session_id = "security-check-invalid-only-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-invalid-only-host", "user": "admin", "password": "x", "ssh_port": 22,
        }
        headers = {"X-Cockpit-Session": session_id}

        def router_with_drop_invalid_only(command):
            if command.startswith("/ip firewall filter print terse where chain=input"):
                return "0  chain=input action=drop connection-state=invalid disabled=false\n"
            return fake_router(command)

        with patch("core.router", side_effect=router_with_drop_invalid_only):
            resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["input_firewall"]["status"], "warn")

    def test_security_check_firmware_unknown_without_version_data(self):
        # Audit Runde 5, Befund 1: fehlende Versionsdaten galten bisher faelschlich als
        # "good" -- ein Router, der noch nie erfolgreich auf Updates geprueft hat, darf
        # nicht als "aktuell" durchgehen.
        session_id = "security-check-no-version-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-no-version-host", "user": "admin", "password": "x", "ssh_port": 22,
        }
        headers = {"X-Cockpit-Session": session_id}

        def router_without_version_data(command):
            if command == "/system package update check-for-updates":
                return ""
            if command == "/system package update print":
                return "  channel: stable\n"
            return fake_router(command)

        with patch("core.router", side_effect=router_without_version_data):
            resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["firmware"]["status"], "unknown")

    @patch("core.router", side_effect=fake_router)
    def test_security_check_backup_empty_file_is_not_good(self, _mock):
        # Audit Runde 5, Befund 1: eine 0-Byte-Backup-Datei (z.B. abgebrochener Download)
        # darf nicht als gueltiges Backup gelten.
        session_id = "security-check-empty-backup-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-empty-backup-host", "user": "admin", "password": "x", "ssh_port": 22,
        }
        headers = {"X-Cockpit-Session": session_id}

        def fake_download_empty(host, user, password, port, remote_name, local_path, timeout=20, known_hosts_path=None):
            open(local_path, "wb").close()

        with patch("routes_basis.download_file", side_effect=fake_download_empty):
            self.client.post("/api/v1/backup", headers=headers)
        resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["backup"]["status"], "warn")

    def test_security_check_guest_isolation_warns_on_bridge_bypass(self):
        # Gastnetz und Hausnetz liegen auf derselben Bridge, "use-ip-firewall" ist aus
        # (RouterOS-Default) -- die Forward-Chain-Pruefung greift fuer diesen Verkehr gar
        # nicht, unabhaengig davon, wie eine etwaige Drop-Regel aussieht.
        session_id = "security-check-bridge-bypass-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-bridge-host", "user": "admin", "password": "x", "ssh_port": 22,
            "guest_interface": "guest",
        }
        headers = {"X-Cockpit-Session": session_id}

        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=bridge\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == "/interface bridge settings print":
                return "  use-ip-firewall: no\n"
            return fake_router(command)

        with patch("core.router", side_effect=router_stub):
            resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["guest_isolation"]["status"], "warn")
        self.assertIn("Bridge", by_id["guest_isolation"]["detail"])
        # Alltagssprache muss bei warn eine konkrete Handlungsempfehlung enthalten, nicht nur
        # den Fachtext wiederholen -- Punkt 5 des Sieben-Punkte-Urteils, 10.09.2026.
        self.assertIn("NICHT", by_id["guest_isolation"]["plain"])
        self.assertIn("Richte", by_id["guest_isolation"]["plain"])

    def test_security_check_guest_isolation_good_when_bridge_filter_closes_the_bypass(self):
        # Nachtrag "Bridge-Filter/VLAN-Isolation", 10.09.2026: derselbe Bridge-Bypass wie oben,
        # aber eine aktive Bridge-Firewall-Filter-Regel schliesst die Luecke tatsaechlich --
        # das muss jetzt "good" statt pauschal "warn" liefern.
        session_id = "security-check-bridge-filter-closes-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-bridge-filter-host", "user": "admin", "password": "x", "ssh_port": 22,
            "guest_interface": "guest",
        }
        headers = {"X-Cockpit-Session": session_id}

        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=bridge\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == "/interface bridge settings print":
                return "  use-ip-firewall: no\n"
            if command == '/interface bridge port print terse where bridge="bridge"':
                return "0 interface=guest bridge=bridge\n1 interface=ether2 bridge=bridge\n"
            if command == "/interface bridge filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest disabled=false\n"
            return fake_router(command)

        with patch("core.router", side_effect=router_stub):
            resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["guest_isolation"]["status"], "good")
        self.assertIn("Bridge-Firewall-Filter", by_id["guest_isolation"]["detail"])

    def test_security_check_guest_isolation_good_when_vlan_closes_the_bypass(self):
        session_id = "security-check-vlan-closes-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-vlan-host", "user": "admin", "password": "x", "ssh_port": 22,
            "guest_interface": "guest",
        }
        headers = {"X-Cockpit-Session": session_id}

        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return "0 interface=guest bridge=bridge pvid=20\n"
            if command == '/interface list member print terse where list="LAN"':
                return "0 list=LAN interface=bridge\n"
            if command == "/interface bridge settings print":
                return "  use-ip-firewall: no\n"
            if command == '/interface bridge port print terse where bridge="bridge"':
                return "0 interface=guest bridge=bridge\n1 interface=ether2 bridge=bridge\n"
            if command == "/interface bridge filter print terse where chain=forward":
                return ""
            if command == '/interface bridge print terse where name="bridge"':
                return "0 name=bridge vlan-filtering=yes\n"
            if command == '/interface bridge vlan print terse where bridge="bridge"':
                return "0 bridge=bridge vlan-ids=20 current-untagged=guest\n"
            return fake_router(command)

        with patch("core.router", side_effect=router_stub):
            resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["guest_isolation"]["status"], "good")
        self.assertIn("VLAN", by_id["guest_isolation"]["detail"])

    def test_security_check_guest_isolation_warns_on_ipv6_leak_even_if_ipv4_good(self):
        # Eine saubere IPv4-Sperre allein reicht nicht -- IPv6 hat eine eigene, komplett
        # getrennte Firewall-Chain und kann das Gastnetz unabhaengig davon oeffnen.
        session_id = "security-check-ipv6-leak-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-ipv6-leak-host", "user": "admin", "password": "x", "ssh_port": 22,
            "guest_interface": "guest",
        }
        headers = {"X-Cockpit-Session": session_id}

        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return ""
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=LAN disabled=false\n"
            if command == "/ipv6 settings print":
                return "  disable-ipv6: no\n"
            if command == "/ipv6 firewall filter print terse where chain=forward":
                return "0 chain=forward action=accept in-interface=guest out-interface-list=LAN disabled=false\n"
            return fake_router(command)

        with patch("core.router", side_effect=router_stub):
            resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["guest_isolation"]["status"], "warn")
        self.assertIn("IPv6", by_id["guest_isolation"]["detail"])

    def test_security_check_guest_isolation_good_when_ipv6_disabled(self):
        session_id = "security-check-ipv6-off-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-ipv6-off-host", "user": "admin", "password": "x", "ssh_port": 22,
            "guest_interface": "guest",
        }
        headers = {"X-Cockpit-Session": session_id}

        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return ""
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=LAN disabled=false\n"
            if command == "/ipv6 settings print":
                return "  disable-ipv6: yes\n"
            return fake_router(command)

        with patch("core.router", side_effect=router_stub):
            resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["guest_isolation"]["status"], "good")

    def test_security_check_guest_isolation_downgrades_when_ipv6_status_unclear(self):
        # Weder "sicher aktiv" noch "sicher aus" -- ein "good" allein auf Basis von IPv4
        # waere hier ein falsches Gruen.
        session_id = "security-check-ipv6-unclear-session"
        core_module.SESSIONS[session_id] = {
            "host": "secheck-ipv6-unclear-host", "user": "admin", "password": "x", "ssh_port": 22,
            "guest_interface": "guest",
        }
        headers = {"X-Cockpit-Session": session_id}

        def router_stub(command):
            if command == '/interface bridge port print terse where interface="guest"':
                return ""
            if command == "/ip firewall filter print terse where chain=forward":
                return "0 chain=forward action=drop in-interface=guest out-interface-list=LAN disabled=false\n"
            if command == "/ipv6 settings print":
                return ""
            return fake_router(command)

        with patch("core.router", side_effect=router_stub):
            resp = self.client.get("/api/v1/security-check", headers=headers)
        by_id = {c["id"]: c for c in resp.get_json()["checks"]}
        self.assertEqual(by_id["guest_isolation"]["status"], "unknown")

    @patch("core.router", side_effect=fake_router)
    def test_webui_suggestion_known_vendor(self, _mock):
        resp = self.client.get(
            "/api/v1/devices/24:0a:c4:11:22:33/webui-suggestion", headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["suggested"])
        self.assertEqual(data["default_port"], 80)

    @patch("core.router", side_effect=fake_router)
    def test_webui_suggestion_unknown_vendor(self, _mock):
        resp = self.client.get(
            "/api/v1/devices/aa:bb:cc:11:22:33/webui-suggestion", headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"suggested": False})

    @patch("core.router", side_effect=fake_router)
    def test_reservation_requires_known_lease(self, _mock):
        resp = self.client.put(
            "/api/v1/devices/aa:bb:cc:11:22:33/reservation",
            json={"ip": "192.168.178.99"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 404)

    @patch("core.router", side_effect=fake_router)
    def test_reservation_success(self, _mock):
        resp = self.client.put(
            "/api/v1/devices/24:0a:c4:11:22:33/reservation",
            json={"ip": "192.168.178.70", "has_webui": True, "webui_port": 80},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": True})

    @patch("core.router", side_effect=fake_router)
    def test_network_get(self, _mock):
        resp = self.client.get("/api/v1/network", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data["addresses"]), 2)
        self.assertEqual(data["dns_servers"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(data["dhcp_clients"][0]["interface"], "ether1")

    def test_wan_interfaces_can_be_selected(self):
        output = '0 interface=pppoe-wan status=bound\n'
        with patch("core.router", return_value=output):
            listed = self.client.get("/api/v1/network/wan-interfaces", headers=self.headers)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.get_json()[0]["interface"], "pppoe-wan")

        with patch("core.router", return_value='0 name=pppoe-wan running=true\n'):
            selected = self.client.put(
                "/api/v1/network/wan-interface", json={"interface": "pppoe-wan"}, headers=self.headers,
            )
        self.assertEqual(selected.status_code, 200)
        self.assertEqual(core_module.SESSIONS[self.session_id]["wan_interface"], "pppoe-wan")

    @patch("core.router", side_effect=fake_router)
    def test_network_ip_address_rejects_bad_format(self, _mock):
        resp = self.client.put(
            "/api/v1/network/ip-address/ether1",
            json={"address": "nicht-valide"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "invalid_address")

    @patch("core.router", side_effect=fake_router)
    def test_network_ip_address_updates_existing(self, mock_router):
        resp = self.client.put(
            "/api/v1/network/ip-address/ether5",
            json={"address": "192.168.88.2/24"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        mock_router.assert_any_call(
            '/ip address set [find interface="ether5"] address="192.168.88.2/24"'
        )

    @patch("core.router")
    def test_network_ip_address_rejects_multiple_existing_addresses(self, mock_router):
        # Audit A11: "set [find interface=X]" traefe sonst ALLE Adressen dieses Interfaces --
        # bei mehr als einer bestehenden Adresse lieber ablehnen als etwas Falsches treffen.
        mock_router.return_value = (
            ' 0  address="192.168.88.1/24" interface="ether5"\n'
            ' 1  address="192.168.88.2/24" interface="ether5"\n'
        )
        resp = self.client.put(
            "/api/v1/network/ip-address/ether5",
            json={"address": "192.168.88.3/24"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["error"], "multiple_addresses")
        mock_router.assert_called_once()  # nur die Nachfrage, kein "set"

    @patch("core.router", side_effect=fake_router)
    def test_network_ip_address_adds_when_missing(self, mock_router):
        resp = self.client.put(
            "/api/v1/network/ip-address/ether2",
            json={"address": "10.0.0.1/24"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        mock_router.assert_any_call('/ip address add interface="ether2" address="10.0.0.1/24"')

    @patch("core.router", side_effect=fake_router)
    def test_network_dns_rejects_invalid(self, _mock):
        resp = self.client.put(
            "/api/v1/network/dns", json={"servers": ["nicht-valide"]}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)

    @patch("core.router", side_effect=fake_router)
    def test_network_dns_success(self, mock_router):
        resp = self.client.put(
            "/api/v1/network/dns", json={"servers": ["9.9.9.9"]}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": True, "dns_servers": ["9.9.9.9"]})

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_client_create_success(self, mock_router):
        resp = self.client.post(
            "/api/v1/network/dhcp-client", json={"interface": "ether2"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 201)
        mock_router.assert_any_call('/ip dhcp-client add interface="ether2" disabled=no')

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_client_create_conflict(self, _mock):
        resp = self.client.post(
            "/api/v1/network/dhcp-client", json={"interface": "ether1"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 409)

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_client_delete_not_found(self, _mock):
        resp = self.client.delete("/api/v1/network/dhcp-client/ether3", headers=self.headers)
        self.assertEqual(resp.status_code, 404)

    @patch("core.router")
    def test_dhcp_client_delete_rejects_injection_payload(self, mock_router):
        # Audit B02, 09.09.: live gegen den Test-hAP bestaetigte Command Injection --
        # derselbe Payload wie im Audit-Nachweis. Muss jetzt 404 liefern, OHNE den Router
        # ueberhaupt zu erreichen (vorher lief der erste router()-Aufruf trotzdem durch).
        payload = 'x"; log info message="COCKPIT-AUDIT-PROOF'
        resp = self.client.delete(f"/api/v1/network/dhcp-client/{quote(payload, safe='')}", headers=self.headers)
        self.assertEqual(resp.status_code, 404)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_ranges_list(self, _mock):
        resp = self.client.get("/api/v1/network/dhcp-ranges", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], "dhcp-aaaa1111")
        self.assertEqual(data[0]["interface"], "vlan20-buero")
        self.assertEqual(data[0]["range_start"], "192.168.20.100")
        self.assertEqual(data[0]["range_end"], "192.168.20.200")
        self.assertEqual(data[0]["gateway"], "192.168.20.1")

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_ranges_create_requires_interface_address(self, _mock):
        resp = self.client.post(
            "/api/v1/network/dhcp-ranges",
            json={
                "interface": "vlan30-ohne-ip", "network": "192.168.30.0/24",
                "range_start": "192.168.30.100", "range_end": "192.168.30.200",
            },
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "interface_no_address")

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_ranges_create_conflict(self, _mock):
        resp = self.client.post(
            "/api/v1/network/dhcp-ranges",
            json={
                "interface": "vlan99-belegt", "network": "192.168.99.0/24",
                "range_start": "192.168.99.100", "range_end": "192.168.99.200",
            },
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 409)

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_ranges_create_success_defaults_gateway_and_dns(self, mock_router):
        resp = self.client.post(
            "/api/v1/network/dhcp-ranges",
            json={
                "interface": "vlan20-buero", "network": "192.168.20.0/24",
                "range_start": "192.168.20.100", "range_end": "192.168.20.200",
            },
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["gateway"], "192.168.20.1")
        self.assertEqual(data["dns_servers"], ["192.168.20.1"])
        mock_router.assert_any_call(
            '/ip pool add name="cockpit-dhcp-pool-' + data["id"] + '" '
            'ranges="192.168.20.100-192.168.20.200"'
        )

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_ranges_create_rejects_inconsistent_pool_before_writing(self, mock_router):
        cases = [
            ({"range_start": "192.168.21.100", "range_end": "192.168.21.200"}, "range_outside_network"),
            ({"range_start": "192.168.20.200", "range_end": "192.168.20.100"}, "invalid_range"),
            ({"range_start": "192.168.20.0", "range_end": "192.168.20.100"}, "invalid_range"),
            ({"range_start": "192.168.20.100", "range_end": "192.168.20.200", "gateway": "192.168.21.1"}, "invalid_gateway"),
            # Audit Runde 5, Befund 3: ein explizit gewaehltes Gateway INNERHALB des
            # eigenen Pools erzeugt genauso einen Adresskonflikt wie die Router-IP selbst.
            ({"range_start": "192.168.20.100", "range_end": "192.168.20.200", "gateway": "192.168.20.150"}, "invalid_gateway"),
        ]
        for overrides, error in cases:
            with self.subTest(error=error):
                payload = {
                    "interface": "vlan20-buero", "network": "192.168.20.0/24",
                    "range_start": "192.168.20.100", "range_end": "192.168.20.200",
                    **overrides,
                }
                mock_router.reset_mock()
                response = self.client.post(
                    "/api/v1/network/dhcp-ranges", json=payload, headers=self.headers,
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.get_json()["error"], error)
                self.assertFalse(any("/ip pool add" in call.args[0] for call in mock_router.call_args_list))

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_ranges_create_rejects_range_containing_router_address(self, mock_router):
        # Audit Runde 5, Befund 3: Router-Adresse .1, Pool .1-.100 wurde bisher als Erfolg
        # akzeptiert -- das erzeugt einen sofortigen IP-Konflikt mit dem ersten per DHCP
        # versorgten Client. Nichts darf am Router angelegt werden.
        resp = self.client.post(
            "/api/v1/network/dhcp-ranges",
            json={
                "interface": "vlan40-router-in-range", "network": "192.168.40.0/24",
                "range_start": "192.168.40.1", "range_end": "192.168.40.100",
            },
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "range_conflicts_with_router")
        self.assertFalse(any("/ip pool add" in call.args[0] for call in mock_router.call_args_list))

    @patch("core.router")
    def test_dhcp_ranges_create_rolls_back_pool_and_server_if_network_add_fails(self, mock_router):
        # Audit Runde 5, Befund 4: schlaegt der letzte Schritt (DHCP-Netzwerk-Eintrag) fehl,
        # duerfen weder der zuvor angelegte Pool noch der DHCP-Server-Eintrag zurueckbleiben
        # (gleiches Rueckbau-Muster wie bei port_forwards_create, Audit A06).
        created_pool_name = {}

        def side_effect(command):
            if command.startswith("/ip pool add name="):
                created_pool_name["name"] = command.split('name="')[1].split('"')[0]
                return ""
            if command.startswith("/ip dhcp-server add name="):
                return ""
            if command.startswith("/ip dhcp-server network add"):
                raise RouterCommandFailed("failure: not enough permissions")
            if command.startswith("/ip dhcp-server remove") or command.startswith("/ip pool remove"):
                return ""
            return fake_router(command)

        mock_router.side_effect = side_effect
        resp = self.client.post(
            "/api/v1/network/dhcp-ranges",
            json={
                "interface": "vlan20-buero", "network": "192.168.20.0/24",
                "range_start": "192.168.20.100", "range_end": "192.168.20.200",
            },
            headers=self.headers,
        )
        # "not enough permissions" wird seit 18.09. als 403 router_permission_denied uebersetzt
        # (Audit Befund 3); der Rollback muss davon unabhaengig laufen.
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json()["error"], "router_permission_denied")
        calls = [c.args[0] for c in mock_router.call_args_list]
        self.assertTrue(any(c.startswith("/ip pool remove") for c in calls))
        self.assertTrue(any(c.startswith("/ip dhcp-server remove") for c in calls))
        # Reihenfolge: Rueckbau nach dem gescheiterten Schritt, nicht davor.
        network_add_index = next(i for i, c in enumerate(calls) if c.startswith("/ip dhcp-server network add"))
        self.assertTrue(all(
            i > network_add_index
            for i, c in enumerate(calls)
            if c.startswith("/ip pool remove") or c.startswith("/ip dhcp-server remove")
        ))

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_ranges_delete_not_found(self, _mock):
        resp = self.client.delete("/api/v1/network/dhcp-ranges/dhcp-doesnotexist", headers=self.headers)
        self.assertEqual(resp.status_code, 404)

    @patch("core.router")
    def test_dhcp_ranges_delete_rejects_injection_payload(self, mock_router):
        # Audit B03, 09.09.: live gegen den Test-hAP bestaetigte Command Injection --
        # derselbe Payload wie im Audit-Nachweis. Muss jetzt 404 liefern, OHNE den Router
        # ueberhaupt zu erreichen.
        payload = 'x"; log info message="COCKPIT-AUDIT-PROOF-2'
        resp = self.client.delete(f"/api/v1/network/dhcp-ranges/{quote(payload, safe='')}", headers=self.headers)
        self.assertEqual(resp.status_code, 404)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_ranges_delete_success(self, mock_router):
        resp = self.client.delete("/api/v1/network/dhcp-ranges/dhcp-aaaa1111", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        mock_router.assert_any_call(
            '/ip pool remove [find name="cockpit-dhcp-pool-dhcp-aaaa1111"]'
        )

    @patch("core.router", side_effect=fake_router)
    def test_dhcp_leases(self, _mock):
        resp = self.client.get("/api/v1/network/dhcp-leases", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["mac"], "b8:27:eb:12:34:56")
        self.assertNotIn("vendor_guess", data[0])

    def test_routeros_escape_masks_dollar_sign(self):
        # A02: RouterOS interpretiert ein unmaskiertes "$" als Variablenreferenz und ersetzt
        # es stillschweigend (meist durch Leerstring) -- live am 09.09. gegen den hAP
        # bestaetigt ("test$var" wurde zu "test"). "\$" reproduziert das literale Zeichen.
        self.assertEqual(core_module._routeros_escape("test$var"), "test\\$var")
        self.assertEqual(core_module._routeros_escape("a\\$b"), "a\\\\\\$b")

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_rejects_quote_injection(self, mock_router):
        # A01: Ein Passwort mit schliessendem Anfuehrungszeichen konnte zusaetzliche
        # RouterOS-Befehle einschleusen, weil nur die Mindestlaenge geprueft wurde.
        resp = self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": 'geheim12"; /system reboot; :put "'},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "invalid_password")
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_rejects_non_ascii(self, mock_router):
        # 18.09.2026, live am hAP: RouterOS verwirft Umlaute per SSH still. Der Router haette
        # dann eine andere Passphrase als der Nutzer glaubt; WPA-Passphrasen sind ohnehin nur als
        # druckbares ASCII definiert.
        resp = self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "Familie-Müller-2026"},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "invalid_password")
        self.assertIn("Umlaute", resp.get_json()["message"])
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_escapes_dollar_sign(self, mock_router):
        resp = self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "geheim$12345"},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        mock_router.assert_any_call(
            '/interface wireless security-profiles set [find name="default"] '
            'wpa2-pre-shared-key="geheim\\$12345" wpa-pre-shared-key="geheim\\$12345"'
        )

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_reports_undo_available(self, _mock):
        resp = self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "neues-geheim-1"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": True, "undo_available": True})
        # Undo-Zustand lebt ausschliesslich im Session-Speicher, nie auf Platte.
        self.assertIn("wlan-haupt", core_module.SESSIONS[self.session_id]["wifi_password_undo"])

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_undo_restores_old_value_and_consumes_itself(self, mock_router):
        put_resp = self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "neues-geheim-1"}, headers=self.headers,
        )
        self.assertEqual(put_resp.status_code, 200)

        undo_resp = self.client.post(
            "/api/v1/wifi/wlan-haupt/password/undo", headers=self.headers,
        )
        self.assertEqual(undo_resp.status_code, 200)
        self.assertEqual(undo_resp.get_json(), {"ok": True})
        mock_router.assert_any_call(
            '/interface wireless security-profiles set [find name="default"] '
            'wpa2-pre-shared-key="alt-passwort-1" wpa-pre-shared-key="alt-passwort-1"'
        )
        # Kein Klartext-Passwort in der Undo-Antwort -- weder der Alt- noch (analog zum PUT)
        # der zwischenzeitliche neue Wert.
        undo_body = undo_resp.get_data(as_text=True)
        self.assertNotIn("alt-passwort-1", undo_body)
        self.assertNotIn("neues-geheim-1", undo_body)
        # Verbraucht: ein zweites Undo direkt danach findet nichts mehr.
        second_resp = self.client.post(
            "/api/v1/wifi/wlan-haupt/password/undo", headers=self.headers,
        )
        self.assertEqual(second_resp.status_code, 404)
        self.assertEqual(second_resp.get_json()["error"], "undo_unavailable")

    def test_wifi_password_undo_requires_session(self):
        resp = self.client.post("/api/v1/wifi/wlan-haupt/password/undo")
        self.assertEqual(resp.status_code, 401)

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_undo_without_prior_change_returns_404_not_500(self, _mock):
        resp = self.client.post(
            "/api/v1/wifi/wlan-haupt/password/undo", headers=self.headers,
        )
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.get_json()["error"], "undo_unavailable")

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_undo_expired_window_returns_404(self, _mock):
        self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "neues-geheim-1"}, headers=self.headers,
        )
        # Zeitfenster manuell ablaufen lassen, statt Minuten in einem Test zu warten.
        undo_store = core_module.SESSIONS[self.session_id]["wifi_password_undo"]
        undo_store["wlan-haupt"]["expires_at"] = time.monotonic() - 1
        resp = self.client.post(
            "/api/v1/wifi/wlan-haupt/password/undo", headers=self.headers,
        )
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.get_json()["error"], "undo_unavailable")
        self.assertNotIn("wlan-haupt", undo_store)

    @patch("core.router")
    def test_wifi_password_undo_unavailable_when_old_value_could_not_be_read(self, mock_router):
        # Der Lesezugriff auf den Altwert schlaegt fehl (z.B. Router kurzzeitig nicht
        # erreichbar) -- der eigentliche Passwortwechsel MUSS trotzdem durchlaufen, nur ohne
        # Undo-Versprechen.
        def side_effect(command):
            if command.startswith(":put ["):
                raise RouterCommandFailed("no such item")
            return FAKE_OUTPUT.get(command, "")

        mock_router.side_effect = side_effect
        resp = self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "neues-geheim-1"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": True, "undo_available": False})
        mock_router.assert_any_call(
            '/interface wireless security-profiles set [find name="default"] '
            'wpa2-pre-shared-key="neues-geheim-1" wpa-pre-shared-key="neues-geheim-1"'
        )
        undo_resp = self.client.post(
            "/api/v1/wifi/wlan-haupt/password/undo", headers=self.headers,
        )
        self.assertEqual(undo_resp.status_code, 404)

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_undo_rejects_invalid_interface(self, _mock):
        resp = self.client.post(
            "/api/v1/wifi/wlan%3Bhaupt/password/undo", headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_second_change_replaces_pending_undo(self, mock_router):
        # Zwei Passwortwechsel auf demselben Interface hintereinander: der Undo-Stand aus dem
        # ersten Wechsel wird durch den zweiten ersetzt, nicht daneben aufbewahrt -- Undo
        # bringt danach zum Zwischenwert zurueck, nicht zum allerersten Altwert.
        self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "erster-wechsel-1"}, headers=self.headers,
        )
        self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "zweiter-wechsel-1"}, headers=self.headers,
        )
        undo_store = core_module.SESSIONS[self.session_id]["wifi_password_undo"]
        self.assertEqual(len(undo_store), 1)
        undo_resp = self.client.post(
            "/api/v1/wifi/wlan-haupt/password/undo", headers=self.headers,
        )
        self.assertEqual(undo_resp.status_code, 200)
        mock_router.assert_any_call(
            '/interface wireless security-profiles set [find name="default"] '
            'wpa2-pre-shared-key="alt-passwort-1" wpa-pre-shared-key="alt-passwort-1"'
        )

    @patch("core.router")
    def test_wifi_password_undo_wifi_driver(self, mock_router):
        # Neuerer wifiwave2/wifi-Treiber: Passphrase liegt inline am Interface. NICHT live
        # gegen echte Hardware verifiziert (siehe den Projektnotizen), hier nur Mock-Abdeckung fuer die
        # Undo-Logik selbst.
        mock_router.side_effect = [
            "",  # Treibererkennung: klassischer "wireless" nicht gefunden
            '0  name="wlan-ax" configuration.ssid="Home-Ax"\n',  # Treibererkennung "wifi", Treffer
            "alt-passphrase-1\n",  # Lesezugriff auf den Altwert
            "",  # set-Befehl (Passwortwechsel)
        ]
        put_resp = self.client.put(
            "/api/v1/wifi/wlan-ax/password",
            json={"new_password": "neues-geheim-1"}, headers=self.headers,
        )
        self.assertEqual(put_resp.status_code, 200)
        self.assertEqual(put_resp.get_json(), {"ok": True, "undo_available": True})

        mock_router.side_effect = None
        mock_router.reset_mock()
        mock_router.return_value = ""
        undo_resp = self.client.post(
            "/api/v1/wifi/wlan-ax/password/undo", headers=self.headers,
        )
        self.assertEqual(undo_resp.status_code, 200)
        mock_router.assert_any_call(
            '/interface wifi set [find name="wlan-ax"] '
            'security.passphrase="alt-passphrase-1"'
        )

    @patch("core.router", side_effect=fake_router)
    def test_wifi_password_undo_fails_cleanly_when_old_value_empty(self, mock_router):
        # Randfall: das Sicherheitsprofil hatte nie einen Schluessel gesetzt (leerer String).
        # RouterOS selbst lehnt einen leeren WPA2-Schluessel beim Set ab -- Undo muss das als
        # sauberen 409 melden, nicht als 500 crashen.
        self.client.put(
            "/api/v1/wifi/wlan-haupt/password",
            json={"new_password": "neues-geheim-1"}, headers=self.headers,
        )
        undo_store = core_module.SESSIONS[self.session_id]["wifi_password_undo"]
        undo_store["wlan-haupt"]["old_value"]["wpa2"] = ""
        undo_store["wlan-haupt"]["old_value"]["wpa"] = ""
        resp = self.client.post(
            "/api/v1/wifi/wlan-haupt/password/undo", headers=self.headers,
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["error"], "undo_failed")

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_create_rejects_invalid_port(self, mock_router):
        resp = self.client.post(
            "/api/v1/port-forwards",
            json={"name": "Test", "protocol": "tcp", "external_port": 99999,
                  "internal_ip": "192.168.178.60", "internal_port": 80},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_create_rejects_whitespace_padded_port(self, mock_router):
        # Audit Runde 4, 09.09.: "int(value)" akzeptiert stillschweigend fuehrende/
        # abschliessende Leerzeichen und Zeilenumbrueche (z.B. int(" 8080\n") == 8080).
        # Der ROHE String landete bisher unquotiert im RouterOS-Befehl -- ein eingebauter
        # Zeilenumbruch/Leerzeichen im Portfeld haette den sonst einzeiligen Befehl an
        # unerwarteter Stelle aufbrechen koennen. _valid_single_port() verlangt jetzt reine
        # Ziffern, bevor ueberhaupt in int() konvertiert wird.
        for bad_port in (" 8080", "8080\n", "1_000", "8080.0"):
            with self.subTest(bad_port=bad_port):
                resp = self.client.post(
                    "/api/v1/port-forwards",
                    json={"name": "Test", "protocol": "tcp", "external_port": bad_port,
                          "internal_ip": "192.168.178.60", "internal_port": 80},
                    headers=self.headers,
                )
                self.assertEqual(resp.status_code, 400)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_create_rejects_invalid_ip(self, mock_router):
        resp = self.client.post(
            "/api/v1/port-forwards",
            json={"name": "Test", "protocol": "tcp", "external_port": 8080,
                  "internal_ip": "nicht-valide", "internal_port": 80},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_delete_rejects_malformed_id(self, mock_router):
        resp = self.client.delete(
            "/api/v1/port-forwards/pf-not-hex-and-too-long", headers=self.headers,
        )
        self.assertEqual(resp.status_code, 404)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_port_forwards_create_scopes_to_wan_interface(self, mock_router):
        resp = self.client.post(
            "/api/v1/port-forwards",
            json={"name": "NAS", "protocol": "tcp", "external_port": 9090,
                  "internal_ip": "192.168.178.62", "internal_port": 5001},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 201)
        calls = [c.args[0] for c in mock_router.call_args_list]
        add_calls = [c for c in calls if c.startswith("/ip firewall nat add") or c.startswith("/ip firewall filter add")]
        self.assertEqual(len(add_calls), 2)
        for call in add_calls:
            self.assertIn('in-interface="ether1"', call)

    @patch("core.router")
    def test_port_forwards_create_rolls_back_nat_rule_if_filter_add_fails(self, mock_router):
        # Audit A06: schlaegt die zweite (Filter-)Regel fehl, darf keine verwaiste,
        # wirkungslose NAT-Regel zurueckbleiben.
        def side_effect(command):
            if command == '/interface print terse where name="ether1"':
                return '0 name=ether1 running=true\n'
            if command.startswith("/ip firewall nat print terse where chain=dstnat"):
                return ""  # kein Konflikt
            if command.startswith(":foreach"):
                return ""  # keine bestehenden forward-Regeln
            if command.startswith("/ip firewall nat add"):
                return ""  # NAT-Regel erfolgreich angelegt
            if command.startswith("/ip firewall filter add"):
                raise RouterUnreachable("SSH-Verbindung abgebrochen")
            if command.startswith("/ip firewall nat remove"):
                return ""  # Rueckbau
            raise AssertionError(f"unerwarteter Aufruf: {command}")

        mock_router.side_effect = side_effect
        resp = self.client.post(
            "/api/v1/port-forwards",
            json={"name": "NAS", "protocol": "tcp", "external_port": 9090,
                  "internal_ip": "192.168.178.62", "internal_port": 5001},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 502)
        calls = [c.args[0] for c in mock_router.call_args_list]
        self.assertTrue(any(c.startswith("/ip firewall nat remove") for c in calls))

    @patch("core.router", side_effect=fake_router)
    def test_reservation_rejects_invalid_mac(self, mock_router):
        resp = self.client.put(
            "/api/v1/devices/not-a-mac/reservation",
            json={"ip": "192.168.178.70"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        mock_router.assert_not_called()

    @patch("core.router", side_effect=fake_router)
    def test_reservation_rejects_invalid_ip(self, mock_router):
        resp = self.client.put(
            "/api/v1/devices/24:0a:c4:11:22:33/reservation",
            json={"ip": "nicht-valide"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        mock_router.assert_not_called()

    @patch("core.router")
    def test_reservation_adds_before_removing_old_lease(self, mock_router):
        # A10: Reihenfolge muss "neu anlegen, dann alte entfernen" sein, nicht umgekehrt --
        # sonst geht bei einem Fehler beim Anlegen die bisherige, funktionierende Lease
        # ersatzlos verloren.
        mock_router.side_effect = [
            "",  # ip_owner-Check: Ziel-IP noch frei
            '0  address=192.168.178.65 mac-address=24:0A:C4:11:22:33 server=dhcp1\n',  # alte Lease
            "",  # add der neuen Lease
            "",  # remove der alten Lease
        ]
        resp = self.client.put(
            "/api/v1/devices/24:0a:c4:11:22:33/reservation",
            json={"ip": "192.168.178.70"}, headers=self.headers,
        )
        self.assertEqual(resp.status_code, 200)
        calls = [c.args[0] for c in mock_router.call_args_list]
        add_index = next(i for i, c in enumerate(calls) if c.startswith("/ip dhcp-server lease add"))
        remove_index = next(i for i, c in enumerate(calls) if c.startswith("/ip dhcp-server lease remove"))
        self.assertLess(add_index, remove_index, "Anlegen muss vor dem Entfernen der alten Lease passieren")


class BuildHeaderTest(unittest.TestCase):
    def test_every_response_carries_build_id(self):
        app_module.app.testing = True
        client = app_module.app.test_client()
        for resp in (client.get("/"), client.get("/api/v1/status")):
            self.assertEqual(resp.headers.get("X-Cockpit-Build"), app_module.BUILD_ID)
            self.assertIn("X-Cockpit-Build", resp.headers.get("Access-Control-Expose-Headers", ""))
        self.assertRegex(app_module.BUILD_ID, r"^\d+-\d+$")


class SecurityCheckDefaultUserErrorsTest(unittest.TestCase):
    # Audit 18.09., fehlender Testfall 11: Timeout und Auth-Fehler beim Lesen der Benutzerliste
    # muessen als 504/401 beim Client ankommen, nicht als 500.
    def setUp(self):
        app_module.app.testing = True
        self.client = app_module.app.test_client()
        core_module.SESSIONS["sc-err"] = {"host": "test-host", "user": "admin", "password": "x", "ssh_port": 22}
        self.headers = {"X-Cockpit-Session": "sc-err"}

    def tearDown(self):
        core_module.SESSIONS.clear()

    def test_timeout_and_auth_failure_propagate_cleanly(self):
        from routeros import RouterAuthFailed, RouterTimeout
        for exc, code, error in ((RouterTimeout("t"), 504, "router_timeout"), (RouterAuthFailed("a"), 401, "auth_failed")):
            def failing(command, exc=exc):
                if "/user print" in command:
                    raise exc
                return fake_router(command)
            with patch("core.router", side_effect=failing):
                resp = self.client.get("/api/v1/security-check", headers=self.headers)
            self.assertEqual(resp.status_code, code)
            self.assertEqual(resp.get_json()["error"], error)

