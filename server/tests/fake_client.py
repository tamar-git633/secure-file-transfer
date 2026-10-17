import socket
import struct
import sys

HEADER = struct.Struct("<16sBHI")
RESPONSE_HEADER = struct.Struct("<BHI")
CLIENT_VERSION = 3


# Minimal protocol client used to test the server without the C++ client
class FakeClient:
    def __init__(self, host="127.0.0.1", port=1234, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.client_id = bytes(16)

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
    with FakeClient(port=port) as client:
        print("Sending unknown request 999")
        print("Response (version, code, payload):", client.request(999))
