import socket
import struct
import sys

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

HEADER = struct.Struct("<16sBHI")
RESPONSE_HEADER = struct.Struct("<BHI")
CLIENT_VERSION = 3
NAME_SIZE = 255
REGISTER = 825
SEND_PUBLIC_KEY = 826
RECONNECT = 827
REGISTER_OK = 1600
AES_KEY = 1602
RECONNECT_OK = 1605
CLIENT_ID_SIZE = 16
RSA_BITS = 1024
CRYPTOPP_RSA_EXPONENT = 17


def generate_rsa_key():
    return RSA.generate(RSA_BITS, e=CRYPTOPP_RSA_EXPONENT)


def name_field(name):
    return name.encode().ljust(NAME_SIZE, b"\x00")


# Minimal protocol client used to test the server without the C++ client
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
    with FakeClient(port=port) as client:
        print(f"Registering '{name}'")
        _, code, payload = client.register(name)
        print(f"Response {code}, payload {payload.hex() or '(empty)'}")
        if code == REGISTER_OK:
            rsa_key = generate_rsa_key()
            print("Sending public key")
            _, code, payload = client.send_public_key(name, rsa_key)
            print(f"Response {code}, payload {len(payload)} bytes")
            print(f"Decrypted AES key: {client.aes_key.hex()}")
            client_id = client.client_id

    if code == AES_KEY:
        with FakeClient(port=port) as client:
            client.client_id = client_id
            print("Reconnecting on a new connection")
            _, code, payload = client.reconnect(name, rsa_key)
            print(f"Response {code}, payload {len(payload)} bytes")
            print(f"Decrypted AES key: {client.aes_key.hex()}")

    with FakeClient(port=port) as client:
        print("Reconnecting with an unknown name")
        _, code, payload = client.reconnect("Nobody", generate_rsa_key())
        print(f"Response {code}, payload {payload.hex()}")
