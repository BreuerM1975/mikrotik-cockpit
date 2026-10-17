import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import routeros
from routeros import (
    HostKeyChanged,
    HostKeyUnknown,
    RouterCommandFailed,
    RouterUnreachable,
    close_connection,
    download_file,
    ensure_host_key_trusted,
    parse_colon,
    parse_terse,
    run_command,
    trust_host_key,
    upload_file,
)


class ParseColonTest(unittest.TestCase):
    def test_basic(self):
        output = "                   uptime: 1m5s                                      \n                  version: 7.24.1 (stable)                           \n"
        result = parse_colon(output)
        self.assertEqual(result["uptime"], "1m5s")
        self.assertEqual(result["version"], "7.24.1 (stable)")

    def test_mac_address_value_keeps_colons(self):
        result = parse_colon("  mac-address: BC:24:11:4A:8F:4A\n")
        self.assertEqual(result["mac-address"], "BC:24:11:4A:8F:4A")


class ParseTerseTest(unittest.TestCase):
    def test_basic(self):
        output = ' 0   name="ether1" running=true type=ether\n 1   name="ether2" running=false type=ether\n'
        rows = parse_terse(output)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["name"], "ether1")
        self.assertTrue(rows[0]["running"])
        self.assertEqual(rows[1]["name"], "ether2")

    def test_running_flag_without_explicit_key(self):
        # RouterOS-Realfall: "running" steht nur als Flag-Buchstabe "R" vor dem ersten
        # key=value, nicht als eigenes Feld.
        line = '0 R name=ether1 default-name=ether1 type=ether mac-address=BC:24:11:4A:8F:4A\n'
        rows = parse_terse(line)
        self.assertTrue(rows[0]["running"])

    def test_disabled_flag(self):
        line = '0 X name=ether2 type=ether\n'
        rows = parse_terse(line)
        self.assertTrue(rows[0]["disabled"])
        self.assertFalse(rows[0]["running"])

    def test_empty(self):
        self.assertEqual(parse_terse(""), [])
        self.assertEqual(parse_terse("\n\n"), [])

    def test_dhcp_lease(self):
        line = ' 0  address=192.168.178.42 mac-address=B8:27:EB:12:34:56 host-name="shelly-kueche" status=bound server=dhcp1\n'
        rows = parse_terse(line)
        self.assertEqual(rows[0]["mac-address"], "B8:27:EB:12:34:56")
        self.assertEqual(rows[0]["host-name"], "shelly-kueche")
        self.assertEqual(rows[0]["status"], "bound")

    def test_unquoted_multiword_value_runs_to_next_key(self):
        # RouterOS-Realfall (09.09., live gegen den hAP gefunden): "print terse" quotet
        # ueberhaupt keine Werte, auch nicht mehrwortige wie Kommentare oder
        # Interface-Bezeichnungen. Ein "bis zum ersten Leerzeichen" brach damit jeden
        # Kommentar mit Leerzeichen -- betraf auch die schon laufende Portweiterleitung
        # (z. B. "Kamera Einfahrt" wurde zu "Kamera").
        line = (
            '0 comment=defconf: accept established,related,untracked chain=input '
            'action=accept connection-state=established,related,untracked\n'
        )
        rows = parse_terse(line)
        self.assertEqual(rows[0]["comment"], "defconf: accept established,related,untracked")
        self.assertEqual(rows[0]["chain"], "input")
        self.assertEqual(rows[0]["action"], "accept")
        self.assertEqual(rows[0]["connection-state"], "established,related,untracked")

    def test_unquoted_multiword_value_at_end_of_line(self):
        line = '0 name=wlan2 interface-type=Atheros AR9888 radio-name=D401C39B5032\n'
        rows = parse_terse(line)
        self.assertEqual(rows[0]["interface-type"], "Atheros AR9888")
        self.assertEqual(rows[0]["radio-name"], "D401C39B5032")

    def test_unquoted_multiword_value_with_no_following_key(self):
        line = '0 chain=dstnat action=dst-nat comment=Kamera Einfahrt\n'
        rows = parse_terse(line)
        self.assertEqual(rows[0]["comment"], "Kamera Einfahrt")


def _fake_completed(stdout: str, returncode: int = 0):
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = ""
    return result


class RunCommandErrorDetectionTest(unittest.TestCase):
    # Audit A14, 09.09.: RouterOS meldet manche Fehler trotz Exitcode 0 nur im Ausgabetext --
    # live gegen den hAP bestaetigt ("/ip pool add ... ranges=nicht-valide" liefert Exitcode 0
    # mit "value of range must have ip address before '-' (...)").

    @patch("routeros.subprocess.run")
    def test_detects_value_error_despite_exit_zero(self, mock_run):
        mock_run.return_value = _fake_completed(
            "value of range must have ip address before '-' (/ip/pool/add (range); line 1)\n"
        )
        with self.assertRaises(RouterCommandFailed):
            run_command("host", "user", "pass", 22, "/ip pool add name=x ranges=y")

    @patch("routeros.subprocess.run")
    def test_detects_failure_prefix(self, mock_run):
        mock_run.return_value = _fake_completed("failure: not enough permissions (9)\n")
        with self.assertRaises(RouterCommandFailed):
            run_command("host", "user", "pass", 22, "/some/restricted/command")

    @patch("routeros.subprocess.run")
    def test_normal_query_output_not_flagged(self, mock_run):
        mock_run.return_value = _fake_completed(
            '.id=*1;chain=input;action=accept;comment=defconf: accept;disabled=false'
        )
        self.assertIn("chain=input", run_command("host", "user", "pass", 22, "print"))

    @patch("routeros.subprocess.run")
    def test_silent_success_not_flagged(self, mock_run):
        mock_run.return_value = _fake_completed("")
        self.assertEqual(run_command("host", "user", "pass", 22, "/ip pool add name=x ranges=1.2.3.4-1.2.3.5"), "")

    @patch("routeros.subprocess.run")
    def test_bad_command_name_detected_at_exitcode_1(self, mock_run):
        # Audit Runde 3, Befund 2: RouterOS liefert "bad command name" ueberwiegend mit
        # Exitcode 1 -- ohne die Regex-Ergaenzung wuerde das als RouterUnreachable statt
        # RouterCommandFailed durchgehen.
        mock_run.return_value = _fake_completed(
            "bad command name fakemenuxyz (line 1 column 12)\n", returncode=1,
        )
        with self.assertRaises(RouterCommandFailed):
            run_command("host", "user", "pass", 22, "/interface fakemenuxyz print terse")

    @patch("routeros.subprocess.run")
    def test_bad_command_name_detected_at_exitcode_0(self, mock_run):
        # Live am 09.09. gegen den Test-hAP beobachtet: derselbe Fehlertext kam bei einem von
        # acht Durchlaeufen mit Exitcode 0 statt 1 -- die Erkennung darf sich nicht auf den
        # Exitcode verlassen, nur auf den Text.
        mock_run.return_value = _fake_completed(
            "bad command name fakemenuxyz (line 1 column 12)\n", returncode=0,
        )
        with self.assertRaises(RouterCommandFailed):
            run_command("host", "user", "pass", 22, "/interface fakemenuxyz print terse")

    @patch("routeros.subprocess.run")
    def test_script_error_missing_argument_detected(self, mock_run):
        # Live am 09.09. beim Restore-Test gefunden: "/system backup load" ohne "password"
        # liefert diesen Text mit Exitcode 0 -- vorher unerkannt, der Aufruf galt faelschlich
        # als erfolgreich (Router startete nie neu).
        mock_run.return_value = _fake_completed(
            "Script Error: missing value(s) of argument(s) password (/system/backup/load; line 1)\n",
            returncode=0,
        )
        with self.assertRaises(RouterCommandFailed):
            run_command("host", "user", "pass", 22, '/system backup load name="x"')

    @patch("routeros.subprocess.run")
    def test_uses_accept_new_without_known_hosts_path(self, mock_run):
        mock_run.return_value = _fake_completed("")
        run_command("host", "user", "pass", 22, "/system identity print")
        ssh_cmd = mock_run.call_args[0][0]
        self.assertIn("StrictHostKeyChecking=accept-new", ssh_cmd)
        self.assertNotIn("StrictHostKeyChecking=yes", ssh_cmd)

    @patch("routeros.subprocess.run")
    def test_uses_strict_checking_against_own_known_hosts_file(self, mock_run):
        mock_run.return_value = _fake_completed("")
        run_command("host", "user", "pass", 22, "/system identity print", known_hosts_path="/tmp/kh")
        ssh_cmd = mock_run.call_args[0][0]
        self.assertIn("StrictHostKeyChecking=yes", ssh_cmd)
        self.assertIn("UserKnownHostsFile=/tmp/kh", ssh_cmd)
        self.assertNotIn("StrictHostKeyChecking=accept-new", ssh_cmd)


# Audit A18: Erstkontakt zu einem Router darf nicht mehr still (wie bisher via
# "accept-new") vertraut werden -- ensure_host_key_trusted() muss den Fingerprint zur
# Bestaetigung zurueckgeben, statt ihn selbst zu uebernehmen.
class HostKeyTrustTest(unittest.TestCase):
    RAW_LINE = "192.168.99.230 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVuZDI1NTE5a2V5"

    def _mock_subprocess(self, known_hosts_result=""):
        def fake_run(cmd, **kwargs):
            if cmd[0] == "ssh-keyscan":
                return _fake_completed(self.RAW_LINE + "\n")
            if cmd[0] == "ssh-keygen" and "-F" in cmd:
                return _fake_completed(known_hosts_result)
            if cmd[0] == "ssh-keygen" and "-lf" in cmd:
                return _fake_completed("256 SHA256:testFingerprintValue host (ED25519)\n")
            raise AssertionError(f"unerwarteter Aufruf: {cmd}")
        return fake_run

    @patch("routeros.subprocess.run")
    def test_raises_unknown_on_first_contact(self, mock_run):
        mock_run.side_effect = self._mock_subprocess(known_hosts_result="")
        with self.assertRaises(HostKeyUnknown) as ctx:
            ensure_host_key_trusted("192.168.99.230", 22, "/tmp/does-not-exist-kh")
        self.assertEqual(ctx.exception.fingerprint, "SHA256:testFingerprintValue")
        self.assertEqual(ctx.exception.key_type, "ssh-ed25519")
        self.assertEqual(ctx.exception.known_hosts_line, self.RAW_LINE)

    @patch("routeros.subprocess.run")
    def test_returns_none_when_key_already_matches(self, mock_run):
        mock_run.side_effect = self._mock_subprocess(known_hosts_result=self.RAW_LINE + "\n")
        with tempfile.TemporaryDirectory() as tmp:
            known_hosts_path = os.path.join(tmp, "known-hosts")
            open(known_hosts_path, "w").close()
            os.chmod(known_hosts_path, 0o600)  # eigener, vertrauenswuerdiger Eintrag
            self.assertIsNone(ensure_host_key_trusted("192.168.99.230", 22, known_hosts_path))

    @patch("routeros.subprocess.run")
    def test_raises_changed_on_mismatch(self, mock_run):
        stored_line = "192.168.99.230 ssh-ed25519 AAAAAndererAltSchluessel"
        mock_run.side_effect = self._mock_subprocess(known_hosts_result=stored_line + "\n")
        with tempfile.TemporaryDirectory() as tmp:
            known_hosts_path = os.path.join(tmp, "known-hosts")
            open(known_hosts_path, "w").close()
            os.chmod(known_hosts_path, 0o600)  # eigener, vertrauenswuerdiger Eintrag
            with self.assertRaises(HostKeyChanged) as ctx:
                ensure_host_key_trusted("192.168.99.230", 22, known_hosts_path)
        self.assertEqual(ctx.exception.fingerprint, "SHA256:testFingerprintValue")

    @patch("routeros.subprocess.run")
    def test_ignores_group_or_world_writable_known_hosts_file(self, mock_run):
        # Audit Runde 3, Befund 1 (P0): eine Datei, die ein Dritter VOR dem ersten echten
        # Connect anlegen konnte (z.B. weil COCKPIT_KNOWN_HOSTS_FILE auf einen geteilten Pfad
        # zeigt), darf nicht blind uebernommen werden -- auch wenn ihr Inhalt zufaellig zum
        # echten Schluessel passt. Live nachgewiesen: das haette den ganzen Fingerprint-Dialog
        # unsichtbar umgangen.
        mock_run.side_effect = self._mock_subprocess(known_hosts_result=self.RAW_LINE + "\n")
        with tempfile.TemporaryDirectory() as tmp:
            known_hosts_path = os.path.join(tmp, "known-hosts")
            open(known_hosts_path, "w").close()
            os.chmod(known_hosts_path, 0o644)  # fuer Gruppe/Andere lesbar -- unerwartet unsicher
            with self.assertRaises(HostKeyUnknown):
                ensure_host_key_trusted("192.168.99.230", 22, known_hosts_path)

    @patch("routeros.os.getuid", return_value=999999)
    @patch("routeros.subprocess.run")
    def test_ignores_known_hosts_file_owned_by_other_user(self, mock_run, _mock_getuid):
        mock_run.side_effect = self._mock_subprocess(known_hosts_result=self.RAW_LINE + "\n")
        with tempfile.TemporaryDirectory() as tmp:
            known_hosts_path = os.path.join(tmp, "known-hosts")
            open(known_hosts_path, "w").close()
            os.chmod(known_hosts_path, 0o600)
            # Eigene Datei, aber os.getuid() ist gemockt auf eine andere (fremde) UID --
            # simuliert eine Datei, die nicht dem eigenen Prozess gehoert.
            with self.assertRaises(HostKeyUnknown):
                ensure_host_key_trusted("192.168.99.230", 22, known_hosts_path)

    @patch("routeros.subprocess.run")
    def test_raises_unreachable_when_keyscan_finds_nothing(self, mock_run):
        def fake_run(cmd, **kwargs):
            return _fake_completed("", returncode=1)
        mock_run.side_effect = fake_run
        with self.assertRaises(RouterUnreachable):
            ensure_host_key_trusted("10.0.0.1", 22, "/tmp/kh")

    def test_trust_host_key_appends_and_locks_down_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            known_hosts_path = os.path.join(tmp, "sub", "known-hosts")
            trust_host_key(known_hosts_path, self.RAW_LINE)
            with open(known_hosts_path) as handle:
                self.assertEqual(handle.read().strip(), self.RAW_LINE)
            self.assertEqual(os.stat(known_hosts_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.dirname(known_hosts_path)).st_mode & 0o777, 0o700)


class SshMultiplexingTest(unittest.TestCase):
    """Schritt 0 des Multisession-Umbaus.

    Der Kontrollsocket ist, solange er lebt, ein passwortfreier Zugang zum Router -- die
    Pruefungen hier sind deshalb nicht Kosmetik, sondern derselbe Schutz wie bei known_hosts
    und dem Backup-Verzeichnis (Audit Runde 3, Befund 1).
    """

    def _options_of(self, mock_run):
        return mock_run.call_args[0][0]

    def _control_path_from(self, options):
        for entry in options:
            if entry.startswith("ControlPath="):
                return entry.split("=", 1)[1]
        return None

    @patch("routeros.subprocess.run")
    def test_run_command_multiplexes_by_default(self, mock_run):
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            control_dir = os.path.join(tmp, "ssh")
            with patch("routeros._CONTROL_DIR", control_dir):
                run_command("192.0.2.230", "zweitkonto", "pass", 22, "/system identity print")
            options = self._options_of(mock_run)
            # Der Befehl selbst benutzt den Socket, wird aber nie selbst Master -- siehe
            # test_parallel_calls_build_exactly_one_master.
            self.assertIn("ControlMaster=no", options)
            self.assertNotIn("ControlMaster=auto", options)
            self.assertIsNotNone(self._control_path_from(options))
            # Das Verzeichnis muss privat angelegt werden, nicht mit Standardrechten.
            self.assertEqual(os.stat(control_dir).st_mode & 0o777, 0o700)

    @patch("routeros.subprocess.run")
    def test_builds_master_connection_before_the_command(self, mock_run):
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("routeros._CONTROL_DIR", os.path.join(tmp, "ssh")):
                run_command("10.0.0.1", "admin", "pass", 22, "print")
            aufrufe = [call[0][0] for call in mock_run.call_args_list]
        master = [c for c in aufrufe if "-M" in c]
        self.assertEqual(len(master), 1, "genau ein Master-Aufbau erwartet")
        self.assertEqual(master[0][:5], ["sshpass", "-e", "ssh", "-M", "-N"])
        self.assertIn("-f", master[0])
        self.assertIn(f"ControlPersist={routeros._CONTROL_PERSIST}", master[0])
        # Der Master muss VOR dem eigentlichen Befehl aufgebaut werden, sonst findet ihn
        # der Befehl nicht.
        self.assertLess(aufrufe.index(master[0]), len(aufrufe) - 1)

    @patch("routeros.subprocess.run")
    def test_running_master_is_not_rebuilt(self, mock_run):
        mock_run.return_value = _fake_completed("")  # returncode 0 => "-O check" sagt: laeuft
        with tempfile.TemporaryDirectory() as tmp:
            control_dir = os.path.join(tmp, "ssh")
            os.makedirs(control_dir, mode=0o700)
            with patch("routeros._CONTROL_DIR", control_dir):
                open(routeros._control_path("10.0.0.1", "admin", 22), "w").close()
                run_command("10.0.0.1", "admin", "pass", 22, "print")
            aufrufe = [call[0][0] for call in mock_run.call_args_list]
        self.assertEqual([c for c in aufrufe if "-M" in c], [])
        self.assertTrue(any("-O" in c and "check" in c for c in aufrufe))

    def test_parallel_calls_build_exactly_one_master(self):
        """Der Fehler, der diese Umstellung ausgeloest hat.

        Die Oberflaeche schickt die rund zwoelf Abfragen eines Durchlaufs gleichzeitig. Mit
        `ControlMaster=auto` fand keiner der Prozesse einen Socket, alle wurden selbst Master,
        und am Router standen zwoelf Sitzungen statt einer -- live am 2026-10-17 gemessen
        (5,75 s gegen 5,00 s, zehn gleichzeitige Sitzungen in beiden Faellen). Der Master wird
        deshalb unter einem Lock je Ziel von genau einem Thread aufgebaut.
        """
        import threading
        from concurrent.futures import ThreadPoolExecutor

        aufrufe = []
        aufrufe_lock = threading.Lock()
        bereit = threading.Barrier(12)

        def fake_run(command, *args, **kwargs):
            with aufrufe_lock:
                aufrufe.append(list(command))
            if "-M" in command:
                # Master-Aufbau: Socket anlegen, wie es ssh tun wuerde.
                path = next(a.split("=", 1)[1] for a in command if a.startswith("ControlPath="))
                open(path, "w").close()
                time.sleep(0.05)  # Aufbau dauert, waehrenddessen draengen die anderen nach
            return _fake_completed("")

        with tempfile.TemporaryDirectory() as tmp:
            with patch("routeros._CONTROL_DIR", os.path.join(tmp, "ssh")), \
                 patch("routeros.subprocess.run", side_effect=fake_run):
                def arbeiter(_):
                    bereit.wait(timeout=5)
                    run_command("10.0.0.1", "admin", "pass", 22, "print")
                with ThreadPoolExecutor(max_workers=12) as pool:
                    list(pool.map(arbeiter, range(12)))

        master = [c for c in aufrufe if "-M" in c]
        self.assertEqual(len(master), 1, f"genau ein Master erwartet, waren {len(master)}")
        befehle = [c for c in aufrufe if "print" in c]
        self.assertEqual(len(befehle), 12)
        for c in befehle:
            self.assertIn("ControlMaster=no", c)

    @patch("routeros.subprocess.run")
    def test_control_path_does_not_leak_hostname(self, mock_run):
        # Im Dateisystem soll nicht ablesbar sein, welche Router hier verwaltet werden.
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("routeros._CONTROL_DIR", os.path.join(tmp, "ssh")):
                run_command("192.0.2.230", "zweitkonto", "pass", 22, "print")
            path = self._control_path_from(self._options_of(mock_run))
            self.assertNotIn("192.0.2.230", path)
            self.assertNotIn("zweitkonto", os.path.basename(path))

    @patch("routeros.subprocess.run")
    def test_same_target_shares_path_and_different_targets_do_not(self, mock_run):
        mock_run.return_value = _fake_completed("")
        paths = {}
        with tempfile.TemporaryDirectory() as tmp:
            with patch("routeros._CONTROL_DIR", os.path.join(tmp, "ssh")):
                for label, (host, user, port) in {
                    "a": ("10.0.0.1", "admin", 22),
                    "a_again": ("10.0.0.1", "admin", 22),
                    "other_user": ("10.0.0.1", "zweitkonto", 22),
                    "other_port": ("10.0.0.1", "admin", 2223),
                    "other_host": ("10.0.0.2", "admin", 22),
                }.items():
                    run_command(host, user, "pass", port, "print")
                    paths[label] = self._control_path_from(self._options_of(mock_run))
        self.assertEqual(paths["a"], paths["a_again"])
        # Zwei Routerbenutzer am gleichen Geraet duerfen sich keinen Socket teilen, sonst
        # liefen Befehle mit den Rechten des falschen Kontos.
        self.assertNotEqual(paths["a"], paths["other_user"])
        self.assertNotEqual(paths["a"], paths["other_port"])
        self.assertNotEqual(paths["a"], paths["other_host"])

    @patch("routeros.subprocess.run")
    def test_env_switch_disables_multiplexing(self, mock_run):
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("routeros._CONTROL_DIR", os.path.join(tmp, "ssh")), \
                 patch.dict(os.environ, {"COCKPIT_SSH_MULTIPLEXING": "0"}):
                run_command("10.0.0.1", "admin", "pass", 22, "print")
            options = self._options_of(mock_run)
            self.assertNotIn("ControlMaster=auto", options)
            self.assertIsNone(self._control_path_from(options))

    @patch("routeros.subprocess.run")
    def test_group_writable_directory_disables_multiplexing(self, mock_run):
        # Fail-safe: ein Verzeichnis, das ein Dritter vorbereitet haben koennte, wird nicht
        # benutzt. Der Rueckfall ist das bisherige Verhalten, nicht ein Fehler.
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            control_dir = os.path.join(tmp, "ssh")
            os.makedirs(control_dir, mode=0o777)
            os.chmod(control_dir, 0o777)
            with patch("routeros._CONTROL_DIR", control_dir):
                run_command("10.0.0.1", "admin", "pass", 22, "print")
            self.assertIsNone(self._control_path_from(self._options_of(mock_run)))

    @patch("routeros.subprocess.run")
    def test_symlinked_directory_disables_multiplexing(self, mock_run):
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "elsewhere")
            os.makedirs(target, mode=0o700)
            link = os.path.join(tmp, "ssh")
            os.symlink(target, link)
            with patch("routeros._CONTROL_DIR", link):
                run_command("10.0.0.1", "admin", "pass", 22, "print")
            self.assertIsNone(self._control_path_from(self._options_of(mock_run)))

    @patch("routeros.subprocess.run")
    def test_overlong_path_disables_multiplexing(self, mock_run):
        # Unix-Sockets haben eine Pfadgrenze; ohne diese Pruefung wuerde ssh mit
        # "ControlPath too long" scheitern -- und damit jeder Routerbefehl.
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            deep = os.path.join(tmp, "x" * 120)
            with patch("routeros._CONTROL_DIR", deep):
                run_command("10.0.0.1", "admin", "pass", 22, "print")
            self.assertIsNone(self._control_path_from(self._options_of(mock_run)))

    @patch("routeros.subprocess.run")
    def test_file_transfers_multiplex_too(self, mock_run):
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("routeros._CONTROL_DIR", os.path.join(tmp, "ssh")):
                download_file("10.0.0.1", "admin", "pass", 22, "x.backup", os.path.join(tmp, "x"))
                self.assertIn("ControlMaster=no", self._options_of(mock_run))
                self.assertIsNotNone(self._control_path_from(self._options_of(mock_run)))
                upload_file("10.0.0.1", "admin", "pass", 22, os.path.join(tmp, "x"), "x.backup")
                self.assertIn("ControlMaster=no", self._options_of(mock_run))
                self.assertIsNotNone(self._control_path_from(self._options_of(mock_run)))

    def test_close_connection_without_socket_is_a_no_op(self):
        # Trennen muss idempotent bleiben und darf nie werfen.
        with tempfile.TemporaryDirectory() as tmp:
            with patch("routeros._CONTROL_DIR", os.path.join(tmp, "ssh")):
                self.assertFalse(close_connection("10.0.0.1", "admin", 22))

    @patch("routeros.subprocess.run")
    def test_close_connection_sends_exit_for_existing_socket(self, mock_run):
        mock_run.return_value = _fake_completed("")
        with tempfile.TemporaryDirectory() as tmp:
            control_dir = os.path.join(tmp, "ssh")
            os.makedirs(control_dir, mode=0o700)
            with patch("routeros._CONTROL_DIR", control_dir):
                path = routeros._control_path("10.0.0.1", "admin", 22)
                open(path, "w").close()  # Socket-Platzhalter
                self.assertTrue(close_connection("10.0.0.1", "admin", 22))
            command = self._options_of(mock_run)
            self.assertEqual(command[:3], ["ssh", "-O", "exit"])
            self.assertIn(f"ControlPath={path}", command)
            # Ein "-O exit" redet nur mit dem Socket und braucht kein Passwort.
            self.assertNotIn("sshpass", command)


if __name__ == "__main__":
    unittest.main()
