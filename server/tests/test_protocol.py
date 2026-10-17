import struct
import unittest

import protocol
from protocol import (
    NAME_SIZE,
    ProtocolError,
    RequestCode,
    ResponseCode,
)

CLIENT_ID = bytes(range(16))


def make_name_field(text):
    return text.encode().ljust(NAME_SIZE, b"\x00")


class HeaderTest(unittest.TestCase):
    def test_request_header_layout(self):
        data = CLIENT_ID + bytes([3]) + bytes([0x39, 0x03])
        data += bytes([0xFF, 0x00, 0x00, 0x00])
        header = protocol.parse_request_header(data)
        self.assertEqual(header.client_id, CLIENT_ID)
        self.assertEqual(header.version, 3)
        self.assertEqual(header.code, RequestCode.REGISTER)
        self.assertEqual(header.payload_size, 255)

    def test_request_header_size(self):
        self.assertEqual(protocol.REQUEST_HEADER.size, 23)

    def test_short_header(self):
        with self.assertRaises(ProtocolError):
            protocol.parse_request_header(b"\x00" * 10)

    def test_response_layout(self):
        message = protocol.build_response(ResponseCode.ACK, CLIENT_ID)
        self.assertEqual(message[:7], bytes([3, 0x44, 0x06, 16, 0, 0, 0]))
        self.assertEqual(message[7:], CLIENT_ID)

    def test_empty_response(self):
        message = protocol.build_response(ResponseCode.GENERAL_ERROR)
        self.assertEqual(message, bytes([3, 0x47, 0x06, 0, 0, 0, 0]))


class PayloadSizeTest(unittest.TestCase):
    def test_fixed_sizes(self):
        protocol.validate_payload_size(RequestCode.REGISTER, 255)
        protocol.validate_payload_size(RequestCode.SEND_PUBLIC_KEY, 415)
        protocol.validate_payload_size(RequestCode.RECONNECT, 255)
        protocol.validate_payload_size(RequestCode.CRC_ABORT, 255)

    def test_wrong_fixed_size(self):
        with self.assertRaises(ProtocolError):
            protocol.validate_payload_size(RequestCode.REGISTER, 254)

    def test_file_packet_size(self):
        protocol.validate_payload_size(RequestCode.SEND_FILE, 267)
        protocol.validate_payload_size(RequestCode.SEND_FILE, 267 + 65536)
        with self.assertRaises(ProtocolError):
            protocol.validate_payload_size(RequestCode.SEND_FILE, 266)

    def test_unknown_code(self):
        with self.assertRaises(ProtocolError):
            protocol.validate_payload_size(999, 0)


class NameTest(unittest.TestCase):
    def test_round_trip(self):
        field = protocol.pack_name("Michael Jackson")
        self.assertEqual(len(field), NAME_SIZE)
        self.assertEqual(protocol.unpack_name(field), "Michael Jackson")

    def test_max_length(self):
        name = "a" * (NAME_SIZE - 1)
        self.assertEqual(protocol.unpack_name(protocol.pack_name(name)), name)

    def test_too_long(self):
        with self.assertRaises(ProtocolError):
            protocol.pack_name("a" * NAME_SIZE)

    def test_non_ascii_pack(self):
        with self.assertRaises(ProtocolError):
            protocol.pack_name("שלום")

    def test_not_null_terminated(self):
        with self.assertRaises(ProtocolError):
            protocol.unpack_name(b"a" * NAME_SIZE)

    def test_empty(self):
        with self.assertRaises(ProtocolError):
            protocol.unpack_name(b"\x00" * NAME_SIZE)

    def test_non_ascii_unpack(self):
        with self.assertRaises(ProtocolError):
            protocol.unpack_name(b"\xd7\xa9\x00".ljust(NAME_SIZE, b"\x00"))

    def test_garbage_after_null_is_ignored(self):
        field = b"bob\x00" + b"x" * (NAME_SIZE - 4)
        self.assertEqual(protocol.unpack_name(field), "bob")

    def test_wrong_field_size(self):
        with self.assertRaises(ProtocolError):
            protocol.unpack_name(b"bob\x00")


class RequestPayloadTest(unittest.TestCase):
    def test_public_key_payload(self):
        key = bytes(range(160))
        payload = make_name_field("alice") + key
        name, public_key = protocol.parse_public_key_payload(payload)
        self.assertEqual(name, "alice")
        self.assertEqual(public_key, key)

    def test_file_packet_header(self):
        data = struct.pack("<IIHH", 100016, 100000, 1, 2)
        data += make_name_field("file.bin")
        header = protocol.parse_file_packet_header(data)
        self.assertEqual(header.content_size, 100016)
        self.assertEqual(header.orig_size, 100000)
        self.assertEqual(header.packet_number, 1)
        self.assertEqual(header.total_packets, 2)
        self.assertEqual(header.file_name, "file.bin")


class ResponsePayloadTest(unittest.TestCase):
    def test_aes_key_payload(self):
        encrypted = b"k" * 128
        payload = protocol.build_aes_key_payload(CLIENT_ID, encrypted)
        self.assertEqual(payload, CLIENT_ID + encrypted)

    def test_bad_client_id(self):
        with self.assertRaises(ProtocolError):
            protocol.build_client_id_payload(b"short")

    def test_file_received_payload(self):
        payload = protocol.build_file_received_payload(
            CLIENT_ID, 100016, "file.bin", 930766865
        )
        self.assertEqual(len(payload), 16 + 4 + 255 + 4)
        self.assertEqual(payload[:16], CLIENT_ID)
        self.assertEqual(struct.unpack("<I", payload[16:20])[0], 100016)
        self.assertEqual(protocol.unpack_name(payload[20:275]), "file.bin")
        self.assertEqual(struct.unpack("<I", payload[275:])[0], 930766865)


if __name__ == "__main__":
    unittest.main()
