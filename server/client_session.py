import logging

from crypto_utils import CryptoError, encrypt_with_public_key, generate_aes_key
from file_receiver import FIRST_PACKET_NUMBERS, FileReceiver, packet_index
from protocol import (
    CLIENT_VERSION,
    FILE_PACKET_HEADER,
    REQUEST_HEADER,
    ProtocolError,
    RequestCode,
    ResponseCode,
    build_aes_key_payload,
    build_client_id_payload,
    build_file_received_payload,
    build_response,
    parse_file_packet_header,
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
        self._aes_key = None
        self._transfer = None
        self._handlers = {
            RequestCode.REGISTER: self._handle_register,
            RequestCode.SEND_PUBLIC_KEY: self._handle_public_key,
            RequestCode.RECONNECT: self._handle_reconnect,
            RequestCode.SEND_FILE: self._handle_file_packet,
            RequestCode.CRC_OK: self._handle_crc_ok,
            RequestCode.CRC_RETRY: self._handle_crc_retry,
            RequestCode.CRC_ABORT: self._handle_crc_abort,
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
            self._abort_transfer()
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
        self._aes_key = aes_key

        logger.info("Got public key from '%s', sending encrypted AES key",
                    name)
        return ResponseCode.AES_KEY, build_aes_key_payload(client.id,
                                                           encrypted_key)

    # Request 827: a client that registered before asks to reconnect.
    # It gets a new AES key encrypted with the public key saved earlier,
    # or 1606 if it is not registered or has no public key.
    def _handle_reconnect(self, header):
        name = parse_name_payload(self._read_payload(header.payload_size))
        client = self._store.get_by_name(name)

        if client is None or client.id != header.client_id:
            logger.warning("Reconnect denied: '%s' is not registered", name)
            return self._reconnect_denied(header.client_id)
        if client.public_key is None:
            logger.warning("Reconnect denied: '%s' has no public key", name)
            return self._reconnect_denied(header.client_id)

        aes_key = generate_aes_key()
        encrypted_key = encrypt_with_public_key(client.public_key, aes_key)
        self._store.set_aes_key(client.id, aes_key)
        self._client = client
        self._aes_key = aes_key

        logger.info("Client '%s' reconnected, sending new AES key", name)
        return ResponseCode.RECONNECT_OK, build_aes_key_payload(client.id,
                                                                encrypted_key)

    def _reconnect_denied(self, client_id):
        return (ResponseCode.RECONNECT_DENIED,
                build_client_id_payload(client_id))

    # Request 828: one packet of an encrypted file. The response (1603)
    # is sent only after the last packet. If a middle packet fails the
    # transfer is dropped and the error is reported on the last packet.
    def _handle_file_packet(self, header):
        packet = parse_file_packet_header(
            self._read_payload(FILE_PACKET_HEADER.size))
        is_last = self._is_last_packet(packet)
        try:
            return self._receive_packet(header, packet)
        except (ConnectionClosedError, ConnectionError, TimeoutError):
            self._abort_transfer()
            raise
        except Exception as e:
            self._abort_transfer()
            if is_last:
                raise
            logger.error("File packet %d rejected: %s",
                         packet.packet_number, e)
            return None

    def _receive_packet(self, header, packet):
        client = self._require_aes_key(header)
        content_length = self._unread

        transfer = self._transfer
        if transfer is None or packet.packet_number != transfer.next_number:
            self._abort_transfer()
            final_path, temp_path = self._store.file_paths(client.id,
                                                           packet.file_name)
            transfer = FileReceiver(packet, final_path, temp_path,
                                    self._aes_key)
            self._transfer = transfer
            logger.info("Receiving '%s': %d bytes in %d packets",
                        packet.file_name, packet.content_size,
                        packet.total_packets)

        transfer.start_packet(packet, content_length)
        while self._unread:
            size = min(self._unread, RECV_CHUNK_SIZE)
            transfer.write(self._read_payload(size))

        if not transfer.is_last(packet):
            return None

        cksum = transfer.complete()
        self._transfer = None
        self._store.add_file(client.id, packet.file_name,
                             transfer.final_path)
        logger.info("File '%s' saved to %s, cksum %d",
                    packet.file_name, transfer.final_path, cksum)
        return ResponseCode.FILE_RECEIVED, build_file_received_payload(
            client.id, transfer.content_size, packet.file_name, cksum)

    def _is_last_packet(self, packet):
        transfer = self._transfer
        if transfer and packet.packet_number == transfer.next_number:
            return transfer.is_last(packet)
        first = packet.packet_number
        if first not in FIRST_PACKET_NUMBERS:
            first = 1
        return packet_index(packet, first) >= packet.total_packets

    def _require_aes_key(self, header):
        client = self._require_client(header)
        if self._aes_key is None:
            raise ProtocolError("No AES key yet, send public key or "
                                "reconnect first")
        return client

    # Request 900: the client's CRC matches, the file is marked as verified
    def _handle_crc_ok(self, header):
        client, file_name = self._read_crc_request(header)
        self._store.set_verified(client.id, file_name)
        logger.info("File '%s' verified by '%s'", file_name, client.name)
        return ResponseCode.ACK, build_client_id_payload(client.id)

    # Request 901: CRC mismatch, the client will send the file again.
    # The bad file is deleted and no response is sent.
    def _handle_crc_retry(self, header):
        client, file_name = self._read_crc_request(header)
        self._store.remove_file(client.id, file_name)
        logger.warning("CRC mismatch on '%s', waiting for the file again",
                       file_name)

    # Request 902: CRC failed for the fourth time, the client gives up.
    # The file is deleted from disk together with its record.
    def _handle_crc_abort(self, header):
        client, file_name = self._read_crc_request(header)
        self._store.remove_file(client.id, file_name)
        logger.error("CRC failed 4 times on '%s', file deleted", file_name)
        return ResponseCode.ACK, build_client_id_payload(client.id)

    def _read_crc_request(self, header):
        file_name = parse_name_payload(self._read_payload(header.payload_size))
        return self._require_client(header), file_name

    def _require_client(self, header):
        if self._client is None:
            raise ProtocolError("Client did not register or reconnect")
        if header.client_id != self._client.id:
            raise ProtocolError("Client ID does not match this session")
        return self._client

    def _abort_transfer(self):
        if self._transfer:
            logger.warning("Dropping unfinished transfer of '%s'",
                           self._transfer.file_name)
            self._transfer.abort()
            self._transfer = None

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
