#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <aes.h>
#include <filters.h>
#include <modes.h>

// Encrypts with AES-256-CBC (zero IV, PKCS7 padding) piece by piece,
// so a big file never has to be in memory all at once
class AesStreamEncryptor {
public:
    explicit AesStreamEncryptor(std::span<const uint8_t> key);

    std::vector<uint8_t> update(std::span<const uint8_t> plain);
    std::vector<uint8_t> finish();

    static uint64_t encryptedSize(uint64_t origSize);

private:
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption m_encryption;
    std::vector<uint8_t> m_output;
    std::unique_ptr<CryptoPP::StreamTransformationFilter> m_filter;
    bool m_finished = false;
};
