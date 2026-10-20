#include <cstdint>
#include <string>
#include <vector>

#include <filters.h>
#include <osrng.h>
#include <rsa.h>

#include "Base64Wrapper.h"
#include "Constants.h"
#include "Errors.h"
#include "RSAWrapper.h"
#include "TestFramework.h"

static std::vector<uint8_t> encryptWithPublicKey(const std::vector<uint8_t>& publicDer,
                                                 const std::vector<uint8_t>& plain)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PublicKey publicKey;
    CryptoPP::ArraySource keySource(publicDer.data(), publicDer.size(), true);
    publicKey.Load(keySource);
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    std::vector<uint8_t> cipher;
    CryptoPP::ArraySource source(plain.data(), plain.size(), true,
        new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::VectorSink(cipher)));
    return cipher;
}

TEST(base64_known_value)
{
    const std::string text = "hello";
    CHECK(Base64Wrapper::encode({reinterpret_cast<const uint8_t*>(text.data()), text.size()}) == "aGVsbG8=");
    const auto decoded = Base64Wrapper::decode("aGVsbG8=");
    CHECK(std::string(decoded.begin(), decoded.end()) == "hello");
}

TEST(base64_round_trip_without_line_breaks)
{
    std::vector<uint8_t> data(1000);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i);
    }
    const std::string encoded = Base64Wrapper::encode(data);
    CHECK(encoded.find('\n') == std::string::npos);
    CHECK(Base64Wrapper::decode(encoded) == data);
}

TEST(base64_empty)
{
    CHECK(Base64Wrapper::encode({}).empty());
    CHECK(Base64Wrapper::decode("").empty());
}

TEST(base64_invalid_chars)
{
    CHECK_THROWS(Base64Wrapper::decode("abc$def"), CryptoError);
    CHECK_THROWS(Base64Wrapper::decode("abc\ndef"), CryptoError);
}

TEST(rsa_public_key_is_160_bytes)
{
    RSAPrivateWrapper rsa;
    CHECK(rsa.publicKeyDer().size() == constants::PUBLIC_KEY_SIZE);
}

TEST(rsa_new_keys_are_different)
{
    RSAPrivateWrapper first;
    RSAPrivateWrapper second;
    CHECK(first.publicKeyDer() != second.publicKeyDer());
}

TEST(rsa_private_key_save_and_load)
{
    RSAPrivateWrapper original;
    const std::string saved = Base64Wrapper::encode(original.privateKeyDer());
    RSAPrivateWrapper loaded(Base64Wrapper::decode(saved));
    CHECK(loaded.publicKeyDer() == original.publicKeyDer());
    CHECK(loaded.privateKeyDer() == original.privateKeyDer());
}

TEST(rsa_decrypt_aes_key)
{
    RSAPrivateWrapper rsa;
    std::vector<uint8_t> aesKey(constants::AES_KEY_SIZE);
    for (size_t i = 0; i < aesKey.size(); ++i) {
        aesKey[i] = static_cast<uint8_t>(i * 7);
    }
    const auto cipher = encryptWithPublicKey(rsa.publicKeyDer(), aesKey);
    CHECK(cipher.size() == 128);
    CHECK(rsa.decrypt(cipher) == aesKey);
}

TEST(rsa_decrypt_with_other_key_fails)
{
    RSAPrivateWrapper owner;
    RSAPrivateWrapper other;
    const auto cipher = encryptWithPublicKey(owner.publicKeyDer(), std::vector<uint8_t>(32, 1));
    CHECK_THROWS(other.decrypt(cipher), CryptoError);
}

TEST(rsa_decrypt_bad_input)
{
    RSAPrivateWrapper rsa;
    CHECK_THROWS(rsa.decrypt(std::vector<uint8_t>(128, 0xAB)), CryptoError);
    CHECK_THROWS(rsa.decrypt(std::vector<uint8_t>(10, 0)), CryptoError);
    CHECK_THROWS(rsa.decrypt({}), CryptoError);
}

TEST(rsa_load_garbage_key)
{
    CHECK_THROWS(RSAPrivateWrapper{std::vector<uint8_t>(100, 0x30)}, CryptoError);
    CHECK_THROWS(RSAPrivateWrapper{std::vector<uint8_t>{}}, CryptoError);
}

TEST(rsa_load_wrong_key_size)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey bigKey;
    bigKey.GenerateRandomWithKeySize(rng, 2048);
    std::vector<uint8_t> der;
    CryptoPP::VectorSink sink(der);
    bigKey.Save(sink);
    CHECK_THROWS(RSAPrivateWrapper{der}, CryptoError);
}
