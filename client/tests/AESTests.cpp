#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <aes.h>
#include <filters.h>
#include <hex.h>
#include <modes.h>

#include "AESWrapper.h"
#include "Errors.h"
#include "TestFramework.h"

static std::vector<uint8_t> testKey()
{
    std::vector<uint8_t> key(32);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i);
    }
    return key;
}

static std::vector<uint8_t> pattern(size_t size)
{
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((i * 13 + 5) & 0xFF);
    }
    return data;
}

static std::vector<uint8_t> encryptInPieces(const std::vector<uint8_t>& plain, size_t piece)
{
    AesStreamEncryptor encryptor(testKey());
    std::vector<uint8_t> result;
    for (size_t pos = 0; pos < plain.size(); pos += piece) {
        const size_t size = std::min(piece, plain.size() - pos);
        const auto out = encryptor.update(std::span(plain).subspan(pos, size));
        result.insert(result.end(), out.begin(), out.end());
    }
    const auto last = encryptor.finish();
    result.insert(result.end(), last.begin(), last.end());
    return result;
}

static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipher)
{
    const auto key = testKey();
    const std::array<uint8_t, 16> iv{};
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key.data(), key.size(), iv.data());
    std::vector<uint8_t> plain;
    CryptoPP::ArraySource source(cipher.data(), cipher.size(), true,
        new CryptoPP::StreamTransformationFilter(decryption, new CryptoPP::VectorSink(plain)));
    return plain;
}

static std::string toHex(const std::vector<uint8_t>& data)
{
    std::string hex;
    CryptoPP::ArraySource source(data.data(), data.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(hex), false));
    return hex;
}

static std::vector<uint8_t> bytesOf(const std::string& text)
{
    return {text.begin(), text.end()};
}

TEST(aes_matches_python_server)
{
    CHECK(toHex(encryptInPieces({}, 16)) == "9f3b7504926f8bd36e3118e903a4cd4a");
    CHECK(toHex(encryptInPieces(bytesOf("hello"), 16)) == "91684487c34c3456eb4e901cef884a1e");
    CHECK(toHex(encryptInPieces(bytesOf("0123456789abcdef"), 16)) ==
          "d8c95758e3353e530fa52bd10e73b9864f6ba30222074c4d477c3f294f12a82f");
}

TEST(aes_size_formula_matches_output)
{
    for (size_t size : {0u, 1u, 15u, 16u, 17u, 100000u, 65536u, 65537u}) {
        CHECK(encryptInPieces(pattern(size), 4096).size() == AesStreamEncryptor::encryptedSize(size));
    }
    CHECK(AesStreamEncryptor::encryptedSize(0) == 16);
    CHECK(AesStreamEncryptor::encryptedSize(16) == 32);
    CHECK(AesStreamEncryptor::encryptedSize(100000) == 100016);
}

TEST(aes_piece_size_does_not_change_result)
{
    const auto plain = pattern(10000);
    const auto expected = encryptInPieces(plain, plain.size());
    for (size_t piece : {1u, 7u, 16u, 17u, 1000u, 65536u}) {
        CHECK(encryptInPieces(plain, piece) == expected);
    }
}

TEST(aes_decrypts_back)
{
    const auto plain = pattern(100000);
    CHECK(decrypt(encryptInPieces(plain, 65536)) == plain);
}

TEST(aes_update_returns_whole_blocks_only)
{
    AesStreamEncryptor encryptor(testKey());
    CHECK(encryptor.update(pattern(10)).empty());
    CHECK(encryptor.update(pattern(10)).size() % 16 == 0);
}

TEST(aes_bad_key_size)
{
    CHECK_THROWS(AesStreamEncryptor{std::vector<uint8_t>(16)}, CryptoError);
    CHECK_THROWS(AesStreamEncryptor{std::vector<uint8_t>{}}, CryptoError);
}

TEST(aes_use_after_finish)
{
    AesStreamEncryptor encryptor(testKey());
    encryptor.finish();
    CHECK_THROWS(encryptor.update(pattern(16)), CryptoError);
    CHECK_THROWS(encryptor.finish(), CryptoError);
}
