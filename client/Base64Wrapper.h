#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Base64 encoding of binary data, used to keep the private key in text files
class Base64Wrapper {
public:
    static std::string encode(std::span<const uint8_t> data);
    static std::vector<uint8_t> decode(std::string_view text);
};
