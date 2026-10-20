#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "Errors.h"

namespace endian {

inline constexpr unsigned int BITS_PER_BYTE = 8;
inline constexpr uint32_t BYTE_MASK = 0xFF;

// Appends an unsigned value to the buffer in little endian order,
// byte by byte, so the result does not depend on the CPU
template <typename T>
void appendLE(std::vector<uint8_t>& out, T value)
{
    for (size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<uint8_t>((value >> (i * BITS_PER_BYTE)) & BYTE_MASK));
    }
}

// Reads an unsigned little endian value at the given offset,
// throws ProtocolError if it does not fit in the buffer
template <typename T>
T readLE(std::span<const uint8_t> data, size_t offset)
{
    if (offset > data.size() || data.size() - offset < sizeof(T)) {
        throw ProtocolError("Read past the end of the message");
    }
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        value |= static_cast<T>(static_cast<T>(data[offset + i]) << (i * BITS_PER_BYTE));
    }
    return value;
}

inline void appendLE16(std::vector<uint8_t>& out, uint16_t value) { appendLE(out, value); }
inline void appendLE32(std::vector<uint8_t>& out, uint32_t value) { appendLE(out, value); }
inline uint16_t readLE16(std::span<const uint8_t> data, size_t offset) { return readLE<uint16_t>(data, offset); }
inline uint32_t readLE32(std::span<const uint8_t> data, size_t offset) { return readLE<uint32_t>(data, offset); }

}
