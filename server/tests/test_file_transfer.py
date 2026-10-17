import os
import struct
import time
import unittest
from pathlib import Path

from cksum import memcrc

from tests.fake_client import (
    CRC_ABORT,
    CRC_OK,
    CRC_RETRY,
    FILE_RECEIVED_CODE,
    SEND_FILE,
    build_file_packets,
    name_field,
    parse_file_received,
)
from tests.test_server import GENERAL_ERROR, RSA_KEY, ServerTestCase

PACKET_PREFIX = struct.Struct("<IIHH")
ACK = 1604


def change_header(packet, **fields):
    content_size, orig_size, number, total = PACKET_PREFIX.unpack(
        packet[:PACKET_PREFIX.size])
    values = {"content_size": content_size, "orig_size": orig_size,
              "number": number, "total": total}
    values.update(fields)
    prefix = PACKET_PREFIX.pack(values["content_size"], values["orig_size"],
                                values["number"], values["total"])
    return prefix + packet[PACKET_PREFIX.size:]


class FileTestCase(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.client = self.connect()
        self.addCleanup(self.client.close)
        self.client.register("alice")
        self.client.send_public_key("alice", RSA_KEY)

    def client_dir(self):
        return Path(self.tmp_dir.name) / self.client.client_id.hex()

    def files_on_disk(self):
        folder = self.client_dir()
        return sorted(p.name for p in folder.iterdir()) if folder.exists() \
            else []

    def assert_received(self, data, file_name, response):
        _, code, payload = response
        self.assertEqual(code, FILE_RECEIVED_CODE)
        client_id, size, name, crc = parse_file_received(payload)
        self.assertEqual(client_id, self.client.client_id)
        self.assertEqual(size, (len(data) // 16 + 1) * 16)
        self.assertEqual(name, file_name)
        self.assertEqual(crc, memcrc(data))
        self.assertEqual((self.client_dir() / file_name).read_bytes(), data)
        record = self.store.get_file(self.client.client_id, file_name)
        self.assertFalse(record.verified)


class FileTransferTest(FileTestCase):
    def test_various_sizes(self):
        for size in (0, 1, 15, 16, 17, 100_000, 64 * 1024 - 16, 64 * 1024,
                     200_000):
            with self.subTest(size=size):
                data = os.urandom(size)
                name = f"file_{size}.bin"
                self.assert_received(data, name,
                                     self.client.send_file(data, name))
        self.assertFalse(any(n.endswith(".tmp") for n in self.files_on_disk()))

    def test_whole_file_in_one_packet(self):
        data = os.urandom(300_000)
        response = self.client.send_file(data, "big.bin",
                                         packet_size=10 ** 6)
        self.assert_received(data, "big.bin", response)

    def test_small_packets(self):
        data = os.urandom(10_000)
        response = self.client.send_file(data, "small.bin", packet_size=1000)
        self.assert_received(data, "small.bin", response)

    def test_packets_numbered_from_zero(self):
        data = os.urandom(150_000)
        response = self.client.send_file(data, "zero.bin", first_number=0)
        self.assert_received(data, "zero.bin", response)

    def test_send_same_file_again(self):
        self.client.send_file(b"old content", "a.txt")
        response = self.client.send_file(b"new content", "a.txt")
        self.assert_received(b"new content", "a.txt", response)

    def test_full_path_name_is_saved_by_base_name(self):
        _, code, _ = self.client.send_file(b"data", r"c:\docs\report.txt")
        self.assertEqual(code, FILE_RECEIVED_CODE)
        self.assertEqual(self.files_on_disk(), ["report.txt"])

    def test_traversal_name_rejected(self):
        _, code, _ = self.client.send_file(b"data", r"..\..\evil.txt")
        self.assertEqual(code, GENERAL_ERROR)
        self.assertEqual(self.files_on_disk(), [])

    def test_before_key_exchange(self):
        with self.connect() as other:
            other.register("bob")
            other.aes_key = b"k" * 32
            self.assertEqual(other.send_file(b"data", "a.txt")[1],
                             GENERAL_ERROR)

    def test_client_id_mismatch(self):
        self.client.client_id = b"\x01" * 16
        self.assertEqual(self.client.send_file(b"data", "a.txt")[1],
                         GENERAL_ERROR)

    def test_content_size_does_not_fit_orig_size(self):
        packet = build_file_packets(b"x" * 100, "a.txt", self.client.aes_key)
        bad = change_header(packet[0], orig_size=5000)
        self.assertEqual(self.client.send_packets([bad])[1], GENERAL_ERROR)
        self.assertEqual(self.files_on_disk(), [])

    def test_orig_size_wrong_inside_last_block(self):
        packet = build_file_packets(b"x" * 100, "a.txt", self.client.aes_key)
        bad = change_header(packet[0], orig_size=101)
        self.assertEqual(self.client.send_packets([bad])[1], GENERAL_ERROR)
        self.assertEqual(self.files_on_disk(), [])

    def test_missing_packet(self):
        data = os.urandom(3 * 1000)
        packets = build_file_packets(data, "a.bin", self.client.aes_key,
                                     packet_size=1008)
        self.assertEqual(len(packets), 3)
        response = self.client.send_packets([packets[0], packets[2]])
        self.assertEqual(response[1], GENERAL_ERROR)
        self.assertEqual(self.files_on_disk(), [])
        retry = self.client.send_file(data, "a.bin")
        self.assert_received(data, "a.bin", retry)

    def test_middle_packet_error_reported_once(self):
        data = os.urandom(3 * 1000)
        packets = build_file_packets(data, "a.bin", self.client.aes_key,
                                     packet_size=1008)
        packets[1] = change_header(packets[1], content_size=99999)
        response = self.client.send_packets(packets)
        self.assertEqual(response[1], GENERAL_ERROR)
        retry = self.client.send_file(data, "a.bin")
        self.assert_received(data, "a.bin", retry)

    def test_disconnect_in_middle_removes_temp_file(self):
        data = os.urandom(5000)
        packets = build_file_packets(data, "a.bin", self.client.aes_key,
                                     packet_size=1008)
        self.client.send(SEND_FILE, packets[0])
        self.client.send(SEND_FILE, packets[1])
        time.sleep(0.3)
        self.assertEqual(self.files_on_disk(), ["a.bin.tmp"])
        self.client.close()
        deadline = time.time() + 3
        while self.files_on_disk() and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.files_on_disk(), [])


class CrcRequestTest(FileTestCase):
    def setUp(self):
        super().setUp()
        self.data = os.urandom(20_000)
        self.client.send_file(self.data, "a.bin")

    def crc(self, code, name="a.bin"):
        return self.client.request(code, name_field(name))

    def test_crc_ok(self):
        _, code, payload = self.crc(CRC_OK)
        self.assertEqual(code, ACK)
        self.assertEqual(payload, self.client.client_id)
        self.assertTrue(
            self.store.get_file(self.client.client_id, "a.bin").verified)
        self.assertEqual(self.files_on_disk(), ["a.bin"])

    def test_crc_ok_unknown_file(self):
        self.assertEqual(self.crc(CRC_OK, "other.bin")[1], GENERAL_ERROR)

    def test_crc_retry_deletes_file_without_response(self):
        self.client.send(CRC_RETRY, name_field("a.bin"))
        response = self.client.send_file(self.data, "a.bin")
        self.assertEqual(response[1], FILE_RECEIVED_CODE)
        self.assertEqual(self.crc(CRC_OK)[1], ACK)

    def test_crc_retry_removes_file_from_disk(self):
        self.client.send(CRC_RETRY, name_field("a.bin"))
        self.assertEqual(self.crc(CRC_OK)[1], GENERAL_ERROR)
        self.assertEqual(self.files_on_disk(), [])

    def test_three_retries_then_abort(self):
        for _ in range(3):
            self.client.send(CRC_RETRY, name_field("a.bin"))
            self.client.send_file(self.data, "a.bin")
        _, code, payload = self.crc(CRC_ABORT)
        self.assertEqual(code, ACK)
        self.assertEqual(payload, self.client.client_id)
        self.assertEqual(self.files_on_disk(), [])
        self.assertIsNone(self.store.get_file(self.client.client_id, "a.bin"))

    def test_abort_unknown_file(self):
        self.assertEqual(self.crc(CRC_ABORT, "other.bin")[1], ACK)
        self.assertEqual(self.files_on_disk(), ["a.bin"])

    def test_crc_with_wrong_client_id(self):
        self.client.client_id = b"\x02" * 16
        self.assertEqual(self.crc(CRC_OK)[1], GENERAL_ERROR)

    def test_crc_before_register(self):
        with self.connect() as other:
            self.assertEqual(
                other.request(CRC_OK, name_field("a.bin"))[1], GENERAL_ERROR)

    def test_crc_bad_name_field(self):
        self.assertEqual(self.client.request(CRC_OK, b"x" * 255)[1],
                         GENERAL_ERROR)


if __name__ == "__main__":
    unittest.main()
