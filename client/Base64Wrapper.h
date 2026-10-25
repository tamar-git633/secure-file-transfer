// Base64 encoding and decoding
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

class Base64Wrapper {
public:
    static std::string encode(std::span<const uint8_t> data);
    static std::vector<uint8_t> decode(std::string_view text);
};
