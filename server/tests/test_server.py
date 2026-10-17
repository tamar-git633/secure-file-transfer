import logging
import socket
import tempfile
import threading
import unittest

from storage import ClientStore

from server import Server
from tests.fake_client import FakeClient

GENERAL_ERROR = 1607
SERVER_VERSION = 3


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.store = ClientStore(self.tmp_dir.name)
        self.server = Server(0, self.store)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.stop()
        self.thread.join()
        self.tmp_dir.cleanup()
        logging.disable(logging.NOTSET)

    def connect(self):
        return FakeClient(port=self.server.port)


class SessionBasicsTest(ServerTestCase):
    def test_unknown_code_returns_general_error(self):
        with self.connect() as client:
            version, code, payload = client.request(999)
            self.assertEqual(version, SERVER_VERSION)
            self.assertEqual(code, GENERAL_ERROR)
            self.assertEqual(payload, b"")

    def test_connection_stays_open_after_error(self):
        with self.connect() as client:
            for _ in range(3):
                self.assertEqual(client.request(999)[1], GENERAL_ERROR)

    def test_unread_payload_is_skipped(self):
        with self.connect() as client:
            self.assertEqual(client.request(999, b"x" * 100_000)[1],
                             GENERAL_ERROR)
            self.assertEqual(client.request(999)[1], GENERAL_ERROR)

    def test_other_version_is_handled(self):
        with self.connect() as client:
            self.assertEqual(client.request(999, version=2)[1],
                             GENERAL_ERROR)

    def test_client_drops_in_middle_of_header(self):
        raw = socket.create_connection(("127.0.0.1", self.server.port))
        raw.sendall(b"\x00" * 5)
        raw.close()
        with self.connect() as client:
            self.assertEqual(client.request(999)[1], GENERAL_ERROR)

    def test_client_drops_in_middle_of_payload(self):
        with self.connect() as client:
            client.send(999, b"x" * 10, payload_size=1000)
        with self.connect() as client:
            self.assertEqual(client.request(999)[1], GENERAL_ERROR)

    def test_several_clients_at_once(self):
        clients = [self.connect() for _ in range(5)]
        try:
            for client in clients:
                client.send(999)
            for client in clients:
                self.assertEqual(client.receive()[1], GENERAL_ERROR)
        finally:
            for client in clients:
                client.close()


if __name__ == "__main__":
    unittest.main()
