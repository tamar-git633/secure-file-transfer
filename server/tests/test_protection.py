import logging
import time
import unittest
from unittest import mock

import client_session

from tests.fake_client import (
    REGISTER,
    REGISTER_OK,
    SEND_FILE,
    build_file_packets,
    name_field,
)
from tests.test_file_transfer import FileTestCase, change_header
from tests.test_server import GENERAL_ERROR, ServerTestCase

HUGE_SIZE = 4_000_000_000


class ConnectionLimitsTest(ServerTestCase):
    def test_huge_declared_payload_closes_connection(self):
        with self.connect() as client:
            client.send(REGISTER, payload_size=HUGE_SIZE)
            self.assertEqual(client.receive()[1], GENERAL_ERROR)
            with self.assertRaises(ConnectionError):
                client.receive()

    @mock.patch.object(client_session, "INACTIVITY_TIMEOUT", 0.5)
    def test_idle_client_is_disconnected(self):
        with self.connect() as client:
            start = time.time()
            with self.assertRaises(ConnectionError):
                client.receive()
            self.assertLess(time.time() - start, 5)

    def test_other_version_logs_warning_and_works(self):
        logging.disable(logging.NOTSET)
        with self.assertLogs("client_session", level="WARNING") as logs, \
                self.connect() as client:
            response = client.request(REGISTER, name_field("alice"),
                                      version=2)
        self.assertEqual(response[1], REGISTER_OK)
        self.assertTrue(any("version is 2" in line for line in logs.output))


class FilePacketLimitsTest(FileTestCase):
    def first_packet(self, data=b"x" * 100):
        return build_file_packets(data, "a.bin", self.client.aes_key)[0]

    def assert_rejected(self, packet):
        self.assertEqual(self.client.send_packets([packet])[1], GENERAL_ERROR)
        self.assertEqual(self.files_on_disk(), [])

    def test_file_too_large(self):
        orig_size = 2 ** 31
        self.assert_rejected(change_header(self.first_packet(),
                                           orig_size=orig_size,
                                           content_size=orig_size + 16))

    def test_zero_total_packets(self):
        self.assert_rejected(change_header(self.first_packet(), total=0))

    def test_packet_number_out_of_range(self):
        self.assert_rejected(change_header(self.first_packet(), number=7,
                                           total=3))

    def test_more_content_than_declared(self):
        packet = self.first_packet() + b"y" * 32
        self.assert_rejected(packet)

    def test_packet_smaller_than_its_header(self):
        self.assertEqual(self.client.request(SEND_FILE, b"x" * 100)[1],
                         GENERAL_ERROR)

    def test_non_ascii_file_name(self):
        packet = self.first_packet()
        name = "קובץ.txt".encode().ljust(255, b"\x00")
        self.assert_rejected(packet[:12] + name + packet[12 + 255:])

    def test_connection_usable_after_rejections(self):
        self.client.send_packets([change_header(self.first_packet(),
                                                total=0)])
        _, code, _ = self.client.send_file(b"hello", "ok.txt")
        self.assertNotEqual(code, GENERAL_ERROR)


if __name__ == "__main__":
    unittest.main()
