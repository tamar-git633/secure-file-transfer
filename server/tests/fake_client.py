# Simple protocol client used to test the server
import socket
import struct
import sys

from cksum import memcrc
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

HEADER = struct.Struct("<16sBHI")
RESPONSE_HEADER = struct.Struct("<BHI")
FILE_PACKET_HEADER = struct.Struct("<IIHH")
FILE_RECEIVED = struct.Struct("<16sI255sI")
CLIENT_VERSION = 3
NAME_SIZE = 255
REGISTER = 825
SEND_PUBLIC_KEY = 826
RECONNECT = 827
SEND_FILE = 828
CRC_OK = 900
CRC_RETRY = 901
CRC_ABORT = 902
REGISTER_OK = 1600
AES_KEY = 1602
FILE_RECEIVED_CODE = 1603
RECONNECT_OK = 1605
CLIENT_ID_SIZE = 16
RSA_BITS = 1024
CRYPTOPP_RSA_EXPONENT = 17
PACKET_SIZE = 64 * 1024


def generate_rsa_key():
    return RSA.generate(RSA_BITS, e=CRYPTOPP_RSA_EXPONENT)


def name_field(name):
    return name.encode().ljust(NAME_SIZE, b"\x00")


def aes_encrypt(key, data):
    return AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(pad(data, 16))


def build_file_packets(data, file_name, aes_key, packet_size=PACKET_SIZE,
                       first_number=1):
    encrypted = aes_encrypt(aes_key, data)
    pieces = [encrypted[i:i + packet_size]
              for i in range(0, len(encrypted), packet_size)]
    packets = []
    for i, piece in enumerate(pieces):
        header = FILE_PACKET_HEADER.pack(len(encrypted), len(data),
                                         first_number + i, len(pieces))
        packets.append(header + name_field(file_name) + piece)
    return packets


def parse_file_received(payload):
    client_id, size, name, crc = FILE_RECEIVED.unpack(payload)
    return client_id, size, name.split(b"\x00")[0].decode(), crc


class FakeClient:
    def __init__(self, host="127.0.0.1", port=1234, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.client_id = bytes(CLIENT_ID_SIZE)
        self.aes_key = None

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def send(self, code, payload=b"", version=CLIENT_VERSION,
             payload_size=None):
        if payload_size is None:
            payload_size = len(payload)
        header = HEADER.pack(self.client_id, version, code, payload_size)
        self.sock.sendall(header + payload)

    def receive(self):
        version, code, size = RESPONSE_HEADER.unpack(
            self._recv_exact(RESPONSE_HEADER.size))
        return version, code, self._recv_exact(size)

    def request(self, code, payload=b"", **kwargs):
        self.send(code, payload, **kwargs)
        return self.receive()

    def register(self, name):
        response = self.request(REGISTER, name_field(name))
        if response[1] == REGISTER_OK:
            self.client_id = response[2]
        return response

    def send_public_key(self, name, rsa_key):
        public_der = rsa_key.public_key().export_key("DER")
        response = self.request(SEND_PUBLIC_KEY,
                                name_field(name) + public_der)
        self._take_aes_key(response, AES_KEY, rsa_key)
        return response

    def reconnect(self, name, rsa_key):
        response = self.request(RECONNECT, name_field(name))
        self._take_aes_key(response, RECONNECT_OK, rsa_key)
        return response

    def send_packets(self, packets):
        for packet in packets:
            self.send(SEND_FILE, packet)
        return self.receive()

    def send_file(self, data, file_name, **kwargs):
        packets = build_file_packets(data, file_name, self.aes_key, **kwargs)
        return self.send_packets(packets)

    def _take_aes_key(self, response, expected_code, rsa_key):
        if response[1] == expected_code:
            encrypted = response[2][CLIENT_ID_SIZE:]
            self.aes_key = PKCS1_OAEP.new(rsa_key).decrypt(encrypted)

    def _recv_exact(self, size):
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Server closed the connection")
            data += chunk
        return data


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1234
    name = sys.argv[2] if len(sys.argv) > 2 else "Fake Client"
    path = sys.argv[3] if len(sys.argv) > 3 else None

    with FakeClient(port=port) as client:
        print(f"Registering '{name}'")
        _, code, payload = client.register(name)
        print(f"Response {code}, payload {payload.hex() or '(empty)'}")
        if code != REGISTER_OK:
            sys.exit(1)

        print("Sending public key")
        _, code, payload = client.send_public_key(name, generate_rsa_key())
        print(f"Response {code}, AES key {client.aes_key.hex()}")

        if path:
            with open(path, "rb") as f:
                data = f.read()
            file_name = path.replace("\\", "/").split("/")[-1]
            print(f"Sending '{file_name}' ({len(data)} bytes)")
            _, code, payload = client.send_file(data, file_name)
            _, size, got_name, crc = parse_file_received(payload)
            local_crc = memcrc(data)
            print(f"Response {code}: '{got_name}', {size} bytes, "
                  f"server cksum {crc}, local cksum {local_crc}")
            if crc == local_crc:
                _, code, _ = client.request(CRC_OK, name_field(file_name))
                print(f"Sent CRC OK (900), response {code}")
            else:
                _, code, _ = client.request(CRC_ABORT, name_field(file_name))
                print(f"Sent CRC ABORT (902), response {code}")
