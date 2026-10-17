import logging

from crypto_utils import CryptoError, encrypt_with_public_key, generate_aes_key
from protocol import (
    CLIENT_VERSION,
    REQUEST_HEADER,
    ProtocolError,
    RequestCode,
    ResponseCode,
    build_aes_key_payload,
    build_client_id_payload,
    build_response,
    parse_name_payload,
    parse_public_key_payload,
    parse_request_header,
    validate_payload_size,
)
from storage import StorageError

INACTIVITY_TIMEOUT = 300
RECV_CHUNK_SIZE = 64 * 1024

logger = logging.getLogger(__name__)


class ConnectionClosedError(Exception):
    pass


# Handles one connected client: reads requests in a loop, dispatches them
# by request code and sends back the response. Runs in its own thread.
class ClientSession:
    def __init__(self, sock, address, store):
        self._sock = sock
        self._address = f"{address[0]}:{address[1]}"
        self._store = store
        self._unread = 0
        self._client = None
        self._handlers = {
            RequestCode.REGISTER: self._handle_register,
            RequestCode.SEND_PUBLIC_KEY: self._handle_public_key,
        }

    def run(self):
        logger.info("Client connected from %s", self._address)
        try:
            self._sock.settimeout(INACTIVITY_TIMEOUT)
            while self._handle_request():
                pass
        except TimeoutError:
            logger.warning("Client %s inactive for %d seconds, closing",
                           self._address, INACTIVITY_TIMEOUT)
        except ConnectionClosedError:
            logger.warning("Client %s disconnected in the middle of a "
                           "request", self._address)
        except OSError as e:
            logger.warning("Connection error with %s: %s", self._address, e)
        finally:
            self._close()

    def _handle_request(self):
        try:
            raw_header = self._recv_exact(REQUEST_HEADER.size)
        except ConnectionClosedError:
            logger.info("Client %s disconnected", self._address)
            return False

        header = parse_request_header(raw_header)
        self._unread = header.payload_size
        logger.info("Request %d from %s, payload %d bytes",
                    header.code, self._address, header.payload_size)
        if header.version != CLIENT_VERSION:
            logger.warning("Client version is %d, expected %d",
                           header.version, CLIENT_VERSION)

        try:
            response = self._dispatch(header)
        except (ProtocolError, StorageError, CryptoError) as e:
            logger.error("Request %d failed: %s", header.code, e)
            response = (ResponseCode.GENERAL_ERROR, b"")
        except Exception:
            logger.exception("Unexpected error in request %d", header.code)
            response = (ResponseCode.GENERAL_ERROR, b"")

        self._skip_unread()
        if response is not None:
            code, payload = response
            self._sock.sendall(build_response(code, payload))
            logger.info("Sent response %d to %s", code, self._address)
        return True

    def _dispatch(self, header):
        handler = self._handlers.get(header.code)
        if handler is None:
            raise ProtocolError(f"Unsupported request code {header.code}")
        validate_payload_size(header.code, header.payload_size)
        return handler(header)

    # Request 825: registers a new client name and returns its new UUID.
    # The client ID in the header is ignored.
    def _handle_register(self, header):
        try:
            name = parse_name_payload(self._read_payload(header.payload_size))
        except ProtocolError as e:
            logger.warning("Registration rejected: %s", e)
            return ResponseCode.REGISTER_FAILED, b""

        client = self._store.register(name)
        if client is None:
            logger.warning("Registration rejected: name '%s' already exists",
                           name)
            return ResponseCode.REGISTER_FAILED, b""

        self._client = client
        logger.info("Registered '%s' with ID %s", name, client.id.hex())
        return ResponseCode.REGISTER_OK, build_client_id_payload(client.id)

    # Request 826: saves the client's RSA public key, creates a new AES key
    # and sends it back encrypted with that public key
    def _handle_public_key(self, header):
        name, public_key = parse_public_key_payload(
            self._read_payload(header.payload_size))
        client = self._find_client(header.client_id, name)

        aes_key = generate_aes_key()
        encrypted_key = encrypt_with_public_key(public_key, aes_key)
        self._store.set_public_key(client.id, public_key)
        self._store.set_aes_key(client.id, aes_key)
        self._client = client

        logger.info("Got public key from '%s', sending encrypted AES key",
                    name)
        return ResponseCode.AES_KEY, build_aes_key_payload(client.id,
                                                           encrypted_key)

    def _find_client(self, client_id, name):
        client = self._store.get_by_id(client_id)
        if client is None:
            raise StorageError(f"Unknown client ID {client_id.hex()}")
        if client.name != name:
            raise StorageError(f"Name '{name}' does not match client ID")
        return client

    def _read_payload(self, size):
        if size > self._unread:
            raise ProtocolError("Read past the end of the payload")
        data = self._recv_exact(size)
        self._unread -= size
        return data

    def _skip_unread(self):
        while self._unread:
            size = min(self._unread, RECV_CHUNK_SIZE)
            self._recv_exact(size)
            self._unread -= size

    def _recv_exact(self, size):
        buffer = bytearray()
        while len(buffer) < size:
            chunk = self._sock.recv(min(size - len(buffer), RECV_CHUNK_SIZE))
            if not chunk:
                raise ConnectionClosedError()
            buffer += chunk
        return bytes(buffer)

    def _close(self):
        try:
            self._sock.close()
        except OSError:
            pass
        logger.info("Session with %s closed", self._address)
