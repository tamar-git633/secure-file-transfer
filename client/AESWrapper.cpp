#include "AESWrapper.h"

#include <array>
#include <utility>

#include "Constants.h"
#include "Errors.h"

AesStreamEncryptor::AesStreamEncryptor(std::span<const uint8_t> key)
{
    if (key.size() != constants::AES_KEY_SIZE) {
        throw CryptoError("AES key must be 32 bytes");
    }
    const std::array<uint8_t, constants::AES_BLOCK_SIZE> zeroIv{};
    m_encryption.SetKeyWithIV(key.data(), key.size(), zeroIv.data(), zeroIv.size());
    m_filter = std::make_unique<CryptoPP::StreamTransformationFilter>(
        m_encryption, new CryptoPP::VectorSink(m_output), CryptoPP::StreamTransformationFilter::PKCS_PADDING);
}

// Encrypts the next piece and returns the encrypted bytes that are ready,
// a partial block is kept until more data or finish()
std::vector<uint8_t> AesStreamEncryptor::update(std::span<const uint8_t> plain)
{
    if (m_finished) {
        throw CryptoError("Encryptor already finished");
    }
    m_filter->Put(plain.data(), plain.size());
    return std::exchange(m_output, {});
}

// Adds the padding and returns the last encrypted block(s)
std::vector<uint8_t> AesStreamEncryptor::finish()
{
    if (m_finished) {
        throw CryptoError("Encryptor already finished");
    }
    m_finished = true;
    m_filter->MessageEnd();
    return std::exchange(m_output, {});
}

uint64_t AesStreamEncryptor::encryptedSize(uint64_t origSize)
{
    return (origSize / constants::AES_BLOCK_SIZE + 1) * constants::AES_BLOCK_SIZE;
}
