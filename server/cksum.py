CRC_POLYNOMIAL = 0x04C11DB7
CRC_MASK = 0xFFFFFFFF
CRC_TOP_BIT = 0x80000000
BYTE_MASK = 0xFF
BITS_IN_BYTE = 8
TOP_BYTE_SHIFT = 24
TABLE_SIZE = 256


def _build_table():
    table = []
    for i in range(TABLE_SIZE):
        crc = i << TOP_BYTE_SHIFT
        for _ in range(BITS_IN_BYTE):
            if crc & CRC_TOP_BIT:
                crc = ((crc << 1) ^ CRC_POLYNOMIAL) & CRC_MASK
            else:
                crc = (crc << 1) & CRC_MASK
        table.append(crc)
    return table


_TABLE = _build_table()


def _crc_byte(crc, byte):
    index = (crc >> TOP_BYTE_SHIFT) ^ byte
    return ((crc << BITS_IN_BYTE) & CRC_MASK) ^ _TABLE[index]


# Incremental CRC that gives the same result as the Linux cksum command
class Cksum:
    def __init__(self):
        self._crc = 0
        self._length = 0

    def update(self, data):
        crc = self._crc
        for byte in data:
            crc = _crc_byte(crc, byte)
        self._crc = crc
        self._length += len(data)

    def digest(self):
        crc = self._crc
        length = self._length
        while length:
            crc = _crc_byte(crc, length & BYTE_MASK)
            length >>= BITS_IN_BYTE
        return ~crc & CRC_MASK


# Calculates the cksum value of a whole buffer
def memcrc(data):
    checksum = Cksum()
    checksum.update(data)
    return checksum.digest()
