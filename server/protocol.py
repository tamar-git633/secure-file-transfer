import struct
from dataclasses import dataclass
from enum import IntEnum

SERVER_VERSION = 3
CLIENT_VERSION = 3

CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 32
NULL_BYTE = b"\x00"


# Request codes sent by the client
class RequestCode(IntEnum):
    REGISTER = 825
    SEND_PUBLIC_KEY = 826
    RECONNECT = 827
    SEND_FILE = 828
    CRC_OK = 900
    CRC_RETRY = 901
    CRC_ABORT = 902


# Response codes sent by the server
class ResponseCode(IntEnum):
    REGISTER_OK = 1600
    REGISTER_FAILED = 1601
    AES_KEY = 1602
    FILE_RECEIVED = 1603
    ACK = 1604
    RECONNECT_OK = 1605
    RECONNECT_DENIED = 1606
    GENERAL_ERROR = 1607


REQUEST_HEADER = struct.Struct(f"<{CLIENT_ID_SIZE}sBHI")
RESPONSE_HEADER = struct.Struct("<BHI")
PUBLIC_KEY_PAYLOAD = struct.Struct(f"<{NAME_SIZE}s{PUBLIC_KEY_SIZE}s")
FILE_PACKET_HEADER = struct.Struct(f"<IIHH{NAME_SIZE}s")
FILE_RECEIVED_PAYLOAD = struct.Struct(f"<{CLIENT_ID_SIZE}sI{NAME_SIZE}sI")

FIXED_PAYLOAD_SIZES = {
    RequestCode.REGISTER: NAME_SIZE,
    RequestCode.SEND_PUBLIC_KEY: PUBLIC_KEY_PAYLOAD.size,
    RequestCode.RECONNECT: NAME_SIZE,
    RequestCode.CRC_OK: NAME_SIZE,
    RequestCode.CRC_RETRY: NAME_SIZE,
    RequestCode.CRC_ABORT: NAME_SIZE,
}


class ProtocolError(Exception):
    pass


@dataclass
class RequestHeader:
    client_id: bytes
    version: int
    code: int
    payload_size: int


@dataclass
class FilePacketHeader:
    content_size: int
    orig_size: int
    packet_number: int
    total_packets: int
    file_name: str


# Parses the fixed size header that starts every request
def parse_request_header(data):
    if len(data) != REQUEST_HEADER.size:
        raise ProtocolError(f"Bad header size {len(data)}")
    return RequestHeader(*REQUEST_HEADER.unpack(data))


# Checks that the payload size matches the request code
def validate_payload_size(code, payload_size):
    if code == RequestCode.SEND_FILE:
        if payload_size < FILE_PACKET_HEADER.size:
            raise ProtocolError(f"File packet too small: {payload_size}")
        return
    expected = FIXED_PAYLOAD_SIZES.get(code)
    if expected is None:
        raise ProtocolError(f"Unknown request code {code}")
    if payload_size != expected:
        raise ProtocolError(
            f"Request {code} payload must be {expected} bytes, "
            f"got {payload_size}"
        )


# Builds a full response message: header followed by payload
def build_response(code, payload=b""):
    return RESPONSE_HEADER.pack(SERVER_VERSION, code, len(payload)) + payload


# Converts a string into a null terminated, zero padded field
def pack_name(name):
    try:
        raw = name.encode("ascii")
    except UnicodeEncodeError:
        raise ProtocolError("Name must be ASCII") from None
    if len(raw) >= NAME_SIZE:
        raise ProtocolError(f"Name longer than {NAME_SIZE - 1} characters")
    return raw.ljust(NAME_SIZE, NULL_BYTE)


# Extracts a string from a null terminated field
def unpack_name(field):
    if len(field) != NAME_SIZE:
        raise ProtocolError(f"Name field must be {NAME_SIZE} bytes")
    end = field.find(NULL_BYTE)
    if end == -1:
        raise ProtocolError("Name is not null terminated")
    if end == 0:
        raise ProtocolError("Name is empty")
    try:
        return field[:end].decode("ascii")
    except UnicodeDecodeError:
        raise ProtocolError("Name must be ASCII") from None


def parse_name_payload(payload):
    return unpack_name(payload)


def parse_public_key_payload(payload):
    name_field, public_key = PUBLIC_KEY_PAYLOAD.unpack(payload)
    return unpack_name(name_field), public_key


# Parses the fixed part of a file packet (828), the content follows it
def parse_file_packet_header(data):
    content_size, orig_size, packet_number, total_packets, name_field = (
        FILE_PACKET_HEADER.unpack(data)
    )
    return FilePacketHeader(
        content_size,
        orig_size,
        packet_number,
        total_packets,
        unpack_name(name_field),
    )


def build_client_id_payload(client_id):
    if len(client_id) != CLIENT_ID_SIZE:
        raise ProtocolError("Client ID must be 16 bytes")
    return client_id


def build_aes_key_payload(client_id, encrypted_aes_key):
    return build_client_id_payload(client_id) + encrypted_aes_key


# Payload of response 1603: client ID, content size, file name, cksum
def build_file_received_payload(client_id, content_size, file_name, cksum):
    return FILE_RECEIVED_PAYLOAD.pack(
        build_client_id_payload(client_id),
        content_size,
        pack_name(file_name),
        cksum,
    )
