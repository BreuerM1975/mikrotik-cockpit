import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import app
import core
import routes_basis
from test_app import zaehlende_sperre


class CreateConcurrencyTests(unittest.TestCase):
    def test_parallel_create_checks_observe_completed_first_write(self):
        # Abschlussrunde, 10.09.2026: die Basis-Erstell-Endpunkte serialisieren ueber dasselbe
        # core._router_create_lock()-Muster -- vorher gab es dort ueberhaupt keine Sperre gegen
        # zwei zeitgleiche Anfragen. Die Pro-Firewall-Endpunkte (gleiches Muster) werden analog
        # in test_app_pro.py::CreateConcurrencyProTests geprueft.
        for endpoint, worker in (("/api/v1/port-forwards", "_port_forwards_create"),
                                 ("/api/v1/network/dhcp-ranges", "_dhcp_ranges_create")):
            with self.subTest(endpoint=endpoint):
                first_entered = threading.Event()
                release_first = threading.Event()
                second_started = threading.Event()
                second_entered = threading.Event()
                sperrversuche = threading.Semaphore(0)
                records = []

                def create():
                    if first_entered.is_set():
                        second_entered.set()
                    if records:
                        return {"error": "already_exists"}, 409
                    first_entered.set()
                    if not release_first.wait(3):
                        raise RuntimeError("test release timeout")
                    records.append("created")
                    return {"ok": True}, 201

                def request(session, second=False):
                    if second:
                        second_started.set()
                    with app.app.test_client() as client:
                        return client.post(endpoint, headers={"X-Cockpit-Session": session}, json={}).status_code

                sessions = {name: {"host": "audit.invalid", "ssh_port": 22}
                            for name in ("concurrency-a", "concurrency-b")}
                with patch.dict(core.SESSIONS, sessions), \
                        patch.object(routes_basis, worker, side_effect=create), \
                        patch.object(core, "_router_create_lock",
                                     side_effect=zaehlende_sperre(sperrversuche)):
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        first = pool.submit(request, "concurrency-a")
                        try:
                            self.assertTrue(first_entered.wait(2))
                            second = pool.submit(request, "concurrency-b", True)
                            self.assertTrue(second_started.wait(2))
                            # 2026-10-20: harte Bedingung statt Wartefenster. Vorher stand
                            # hier `assertFalse(second_entered.wait(.1))` -- unter Last kommt
                            # die zweite Anfrage in dieser Zeit nicht bis zur Sperre, und der
                            # Test war gruen, auch ohne `with`-Statement im Endpunkt. Jetzt
                            # wird gewartet, bis sie nachweislich dort angekommen ist.
                            self.assertTrue(
                                sperrversuche.acquire(timeout=3),
                                "Die zweite Anfrage ist nie an der Sperre angekommen",
                            )
                            self.assertFalse(second_entered.is_set())
                        finally:
                            release_first.set()
                        self.assertEqual(first.result(timeout=3), 201)
                        self.assertEqual(second.result(timeout=3), 409)
                        self.assertEqual(len(records), 1)
