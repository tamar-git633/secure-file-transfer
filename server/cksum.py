import zlib

CRC_MASK = 0xFFFFFFFF
BYTE_MASK = 0xFF
BITS_IN_BYTE = 8
BITS_IN_CRC = 32
BYTE_VALUES = 256

_REVERSED_BYTES = bytes(
    int(f"{value:0{BITS_IN_BYTE}b}"[::-1], 2) for value in range(BYTE_VALUES)
)


def _reverse_bits(value):
    return int(f"{value:0{BITS_IN_CRC}b}"[::-1], 2)


# Incremental CRC that gives the same result as the Linux cksum command.
# cksum works on the high bit first and zlib.crc32 on the low bit first,
# so the bits of every byte are reversed before zlib (fast, written in C)
# and the bits of the result are reversed back.
class Cksum:
    def __init__(self):
        self._state = 0
        self._length = 0

    def update(self, data):
        self._feed(bytes(data))
        self._length += len(data)

    def digest(self):
        length_bytes = bytearray()
        length = self._length
        while length:
            length_bytes.append(length & BYTE_MASK)
            length >>= BITS_IN_BYTE
        state = self._state
        self._feed(bytes(length_bytes))
        result = ~_reverse_bits(self._state) & CRC_MASK
        self._state = state
        return result

    def _feed(self, data):
        reversed_data = data.translate(_REVERSED_BYTES)
        start = ~self._state & CRC_MASK
        self._state = ~zlib.crc32(reversed_data, start) & CRC_MASK


# Calculates the cksum value of a whole buffer
def memcrc(data):
    checksum = Cksum()
    checksum.update(data)
    return checksum.digest()
