// CRC calculation that matches the Linux cksum command
#include "Cksum.h"

#include <array>

namespace {

constexpr uint32_t CRC_POLYNOMIAL = 0x04C11DB7;
constexpr uint32_t CRC_TOP_BIT = 0x80000000;
constexpr unsigned int BITS_PER_BYTE = 8;
constexpr unsigned int TOP_BYTE_SHIFT = 24;
constexpr uint64_t BYTE_MASK = 0xFF;
constexpr size_t TABLE_SIZE = 256;

constexpr std::array<uint32_t, TABLE_SIZE> buildTable()
{
    std::array<uint32_t, TABLE_SIZE> table{};
    for (uint32_t i = 0; i < TABLE_SIZE; ++i) {
        uint32_t crc = i << TOP_BYTE_SHIFT;
        for (unsigned int bit = 0; bit < BITS_PER_BYTE; ++bit) {
            crc = (crc & CRC_TOP_BIT) ? (crc << 1) ^ CRC_POLYNOMIAL : crc << 1;
        }
        table[i] = crc;
    }
    return table;
}

constexpr std::array<uint32_t, TABLE_SIZE> CRC_TABLE = buildTable();

uint32_t crcByte(uint32_t crc, uint8_t byte)
{
    return (crc << BITS_PER_BYTE) ^ CRC_TABLE[((crc >> TOP_BYTE_SHIFT) ^ byte) & BYTE_MASK];
}

}

void Cksum::update(std::span<const uint8_t> data)
{
    for (uint8_t byte : data) {
        m_crc = crcByte(m_crc, byte);
    }
    m_length += data.size();
}

uint32_t Cksum::digest() const
{
    uint32_t crc = m_crc;
    for (uint64_t length = m_length; length != 0; length >>= BITS_PER_BYTE) {
        crc = crcByte(crc, static_cast<uint8_t>(length & BYTE_MASK));
    }
    return ~crc;
}

uint32_t memcrc(std::span<const uint8_t> data)
{
    Cksum checksum;
    checksum.update(data);
    return checksum.digest();
}
