# Receiving one encrypted file sent in 828 packets
import os
import shutil
from pathlib import Path

from cksum import Cksum
from crypto_utils import AesStreamDecryptor, encrypted_size
from protocol import ProtocolError

MAX_FILE_SIZE = 1024 * 1024 * 1024
TEMP_FILE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                   | getattr(os, "O_BINARY", 0))
FIRST_PACKET_NUMBERS = (0, 1)


class FileReceiver:
    def __init__(self, first_packet, final_path, temp_path, aes_key):
        _check_first_packet(first_packet, final_path)
        self.file_name = first_packet.file_name
        self.content_size = first_packet.content_size
        self._first = first_packet
        self._next_number = first_packet.packet_number
        self._final_path = Path(final_path)
        self._temp_path = Path(temp_path)
        self._decryptor = AesStreamDecryptor(aes_key)
        self._cksum = Cksum()
        self._received = 0
        self._plain_size = 0
        self._fd = os.open(self._temp_path, TEMP_FILE_FLAGS)

    @property
    def next_number(self):
        return self._next_number

    @property
    def final_path(self):
        return self._final_path

    def is_last(self, packet):
        index = packet_index(packet, self._first.packet_number)
        return index >= packet.total_packets

    def start_packet(self, packet, content_length):
        first = self._first
        if (packet.content_size != first.content_size
                or packet.orig_size != first.orig_size
                or packet.total_packets != first.total_packets
                or packet.file_name != first.file_name):
            raise ProtocolError("Packet does not match the first packet")
        if packet.packet_number != self._next_number:
            raise ProtocolError(
                f"Expected packet {self._next_number}, "
                f"got {packet.packet_number}")
        if self._received + content_length > self.content_size:
            raise ProtocolError("More content than the declared size")
        self._next_number += 1

    def write(self, encrypted_chunk):
        self._received += len(encrypted_chunk)
        self._write_plain(self._decryptor.update(encrypted_chunk))

    def complete(self):
        if self._received != self.content_size:
            raise ProtocolError(
                f"Got {self._received} bytes, expected {self.content_size}")
        self._write_plain(self._decryptor.finish())
        self._close()
        if self._plain_size != self._first.orig_size:
            raise ProtocolError(
                f"Decrypted size {self._plain_size} does not match "
                f"original size {self._first.orig_size}")
        os.replace(self._temp_path, self._final_path)
        return self._cksum.digest()

    def abort(self):
        self._close()
        self._temp_path.unlink(missing_ok=True)

    def _write_plain(self, data):
        view = memoryview(data)
        while view:
            view = view[os.write(self._fd, view):]
        self._cksum.update(data)
        self._plain_size += len(data)

    def _close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def packet_index(packet, first_number):
    return packet.packet_number - first_number + 1


def _check_first_packet(packet, final_path):
    if packet.packet_number not in FIRST_PACKET_NUMBERS:
        raise ProtocolError(
            f"Transfer must start with packet 0 or 1, "
            f"got {packet.packet_number}")
    if packet.total_packets < 1 or packet.total_packets > packet.content_size:
        raise ProtocolError(f"Bad total packets {packet.total_packets}")
    if packet.content_size != encrypted_size(packet.orig_size):
        raise ProtocolError(
            f"Content size {packet.content_size} does not fit "
            f"original size {packet.orig_size}")
    if packet.content_size > MAX_FILE_SIZE:
        raise ProtocolError(f"File too large: {packet.content_size}")
    free_space = shutil.disk_usage(Path(final_path).parent).free
    if packet.orig_size > free_space:
        raise ProtocolError("Not enough disk space")
