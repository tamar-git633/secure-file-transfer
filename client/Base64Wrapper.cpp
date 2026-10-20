#include "Base64Wrapper.h"

#include <base64.h>
#include <filters.h>

#include "Errors.h"

namespace {

constexpr std::string_view BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

}

std::string Base64Wrapper::encode(std::span<const uint8_t> data)
{
    std::string encoded;
    constexpr bool insertLineBreaks = false;
    CryptoPP::ArraySource source(data.data(), data.size(), true,
        new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), insertLineBreaks));
    return encoded;
}

// Decodes Base64 text, throws CryptoError if it has characters
// that are not part of the Base64 alphabet
std::vector<uint8_t> Base64Wrapper::decode(std::string_view text)
{
    if (text.find_first_not_of(BASE64_CHARS) != std::string_view::npos) {
        throw CryptoError("Invalid Base64 text");
    }
    std::vector<uint8_t> decoded;
    CryptoPP::StringSource source(reinterpret_cast<const CryptoPP::byte*>(text.data()), text.size(), true,
        new CryptoPP::Base64Decoder(new CryptoPP::VectorSink(decoded)));
    return decoded;
}
