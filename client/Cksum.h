#pragma once

#include <cstdint>
#include <span>

// Incremental CRC that gives the same result as the Linux cksum command
class Cksum {
public:
    void update(std::span<const uint8_t> data);
    uint32_t digest() const;

private:
    uint32_t m_crc = 0;
    uint64_t m_length = 0;
};

// Calculates the cksum value of a whole buffer
uint32_t memcrc(std::span<const uint8_t> data);
