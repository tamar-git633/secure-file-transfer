import logging
import socket
import tempfile
import threading
import unittest

from storage import ClientStore

from server import Server
from tests.fake_client import (
    AES_KEY,
    RECONNECT,
    RECONNECT_OK,
    REGISTER,
    REGISTER_OK,
    SEND_PUBLIC_KEY,
    FakeClient,
    generate_rsa_key,
    name_field,
)

RSA_KEY = generate_rsa_key()
REGISTER_FAILED = 1601
RECONNECT_DENIED = 1606
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
            self.assertEqual(client.request(999, b"x" * 60_000)[1],
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


class RegisterTest(ServerTestCase):
    def test_register_success(self):
        with self.connect() as client:
            version, code, payload = client.register("alice")
            self.assertEqual(version, SERVER_VERSION)
            self.assertEqual(code, REGISTER_OK)
            self.assertEqual(len(payload), 16)
            self.assertEqual(self.store.get_by_name("alice").id, payload)

    def test_duplicate_name(self):
        with self.connect() as client:
            client.register("alice")
        with self.connect() as client:
            _, code, payload = client.register("alice")
            self.assertEqual(code, REGISTER_FAILED)
            self.assertEqual(payload, b"")

    def test_two_names_get_different_ids(self):
        with self.connect() as first, self.connect() as second:
            id1 = first.register("alice")[2]
            id2 = second.register("bob")[2]
            self.assertNotEqual(id1, id2)

    def test_client_id_in_header_is_ignored(self):
        with self.connect() as client:
            client.client_id = b"\xff" * 16
            code = client.register("alice")[1]
            self.assertEqual(code, REGISTER_OK)
            self.assertNotEqual(client.client_id, b"\xff" * 16)

    def test_name_not_null_terminated(self):
        with self.connect() as client:
            code = client.request(REGISTER, b"a" * 255)[1]
            self.assertEqual(code, REGISTER_FAILED)

    def test_empty_name(self):
        with self.connect() as client:
            code = client.request(REGISTER, bytes(255))[1]
            self.assertEqual(code, REGISTER_FAILED)

    def test_wrong_payload_size(self):
        with self.connect() as client:
            code = client.request(REGISTER, name_field("alice")[:100])[1]
            self.assertEqual(code, GENERAL_ERROR)
            self.assertEqual(client.register("alice")[1], REGISTER_OK)


class PublicKeyTest(ServerTestCase):
    def test_public_key_returns_encrypted_aes_key(self):
        with self.connect() as client:
            client.register("alice")
            _, code, payload = client.send_public_key("alice", RSA_KEY)
            self.assertEqual(code, AES_KEY)
            self.assertEqual(payload[:16], client.client_id)
            self.assertEqual(len(payload), 16 + 128)
            self.assertEqual(len(client.aes_key), 32)
            stored = self.store.get_by_name("alice")
            self.assertEqual(stored.aes_key, client.aes_key)
            self.assertEqual(stored.public_key,
                             RSA_KEY.public_key().export_key("DER"))

    def test_on_new_connection_with_saved_id(self):
        with self.connect() as client:
            client.register("alice")
            client_id = client.client_id
        with self.connect() as client:
            client.client_id = client_id
            self.assertEqual(client.send_public_key("alice", RSA_KEY)[1],
                             AES_KEY)

    def test_new_aes_key_every_time(self):
        with self.connect() as client:
            client.register("alice")
            client.send_public_key("alice", RSA_KEY)
            first = client.aes_key
            client.send_public_key("alice", RSA_KEY)
            self.assertNotEqual(first, client.aes_key)

    def test_unregistered_client(self):
        with self.connect() as client:
            client.client_id = b"\x01" * 16
            self.assertEqual(client.send_public_key("alice", RSA_KEY)[1],
                             GENERAL_ERROR)

    def test_name_does_not_match_id(self):
        with self.connect() as client:
            client.register("alice")
            self.assertEqual(client.send_public_key("bob", RSA_KEY)[1],
                             GENERAL_ERROR)

    def test_invalid_key_is_not_saved(self):
        with self.connect() as client:
            client.register("alice")
            payload = name_field("alice") + b"\x00" * 160
            self.assertEqual(client.request(SEND_PUBLIC_KEY, payload)[1],
                             GENERAL_ERROR)
            stored = self.store.get_by_name("alice")
            self.assertIsNone(stored.public_key)
            self.assertIsNone(stored.aes_key)


class ReconnectTest(ServerTestCase):
    def register_with_key(self, name):
        with self.connect() as client:
            client.register(name)
            client.send_public_key(name, RSA_KEY)
            return client.client_id, client.aes_key

    def test_reconnect_success(self):
        client_id, first_key = self.register_with_key("alice")
        with self.connect() as client:
            client.client_id = client_id
            _, code, payload = client.reconnect("alice", RSA_KEY)
            self.assertEqual(code, RECONNECT_OK)
            self.assertEqual(payload[:16], client_id)
            self.assertEqual(len(payload), 16 + 128)
            self.assertEqual(len(client.aes_key), 32)
            self.assertNotEqual(client.aes_key, first_key)
            self.assertEqual(self.store.get_by_id(client_id).aes_key,
                             client.aes_key)

    def test_unknown_name(self):
        with self.connect() as client:
            client.client_id = b"\x07" * 16
            _, code, payload = client.reconnect("nobody", RSA_KEY)
            self.assertEqual(code, RECONNECT_DENIED)
            self.assertEqual(payload, b"\x07" * 16)

    def test_registered_without_public_key(self):
        with self.connect() as client:
            client.register("alice")
            self.assertEqual(client.reconnect("alice", RSA_KEY)[1],
                             RECONNECT_DENIED)

    def test_id_does_not_match_name(self):
        self.register_with_key("alice")
        with self.connect() as client:
            client.client_id = b"\x01" * 16
            self.assertEqual(client.reconnect("alice", RSA_KEY)[1],
                             RECONNECT_DENIED)

    def test_register_after_denied(self):
        with self.connect() as client:
            self.assertEqual(client.reconnect("alice", RSA_KEY)[1],
                             RECONNECT_DENIED)
            self.assertEqual(client.register("alice")[1], REGISTER_OK)
            self.assertEqual(client.send_public_key("alice", RSA_KEY)[1],
                             AES_KEY)

    def test_bad_name_field(self):
        with self.connect() as client:
            self.assertEqual(client.request(RECONNECT, b"a" * 255)[1],
                             GENERAL_ERROR)


if __name__ == "__main__":
    unittest.main()
