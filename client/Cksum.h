// CRC calculation that matches the Linux cksum command
#pragma once

#include <cstdint>
#include <span>

class Cksum {
public:
    void update(std::span<const uint8_t> data);
    uint32_t digest() const;

private:
    uint32_t m_crc = 0;
    uint64_t m_length = 0;
};

uint32_t memcrc(std::span<const uint8_t> data);
