#include "RSAWrapper.h"

#include <filters.h>

#include "Constants.h"
#include "Errors.h"

namespace {

constexpr unsigned int KEY_VALIDATION_LEVEL = 3;

}

RSAPrivateWrapper::RSAPrivateWrapper()
{
    m_privateKey.GenerateRandomWithKeySize(m_rng, constants::RSA_KEY_BITS);
}

// Loads a private key saved earlier, throws CryptoError if the data
// is not a valid RSA key of the expected size
RSAPrivateWrapper::RSAPrivateWrapper(std::span<const uint8_t> privateKeyDer)
{
    try {
        CryptoPP::ArraySource source(privateKeyDer.data(), privateKeyDer.size(), true);
        m_privateKey.Load(source);
    } catch (const CryptoPP::Exception& e) {
        throw CryptoError(std::string("Cannot load private key: ") + e.what());
    }
    if (m_privateKey.GetModulus().BitCount() != constants::RSA_KEY_BITS ||
        !m_privateKey.Validate(m_rng, KEY_VALIDATION_LEVEL)) {
        throw CryptoError("Private key is not a valid RSA 1024 bit key");
    }
}

std::vector<uint8_t> RSAPrivateWrapper::privateKeyDer() const
{
    std::vector<uint8_t> der;
    CryptoPP::VectorSink sink(der);
    m_privateKey.Save(sink);
    return der;
}

std::vector<uint8_t> RSAPrivateWrapper::publicKeyDer() const
{
    std::vector<uint8_t> der;
    CryptoPP::VectorSink sink(der);
    CryptoPP::RSA::PublicKey publicKey(m_privateKey);
    publicKey.Save(sink);
    return der;
}

// Decrypts data that was encrypted with our public key (RSA OAEP SHA1)
std::vector<uint8_t> RSAPrivateWrapper::decrypt(std::span<const uint8_t> cipher)
{
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(m_privateKey);
    if (cipher.size() != decryptor.FixedCiphertextLength()) {
        throw CryptoError("Encrypted key has a wrong size");
    }
    std::vector<uint8_t> plain;
    try {
        CryptoPP::ArraySource source(cipher.data(), cipher.size(), true,
            new CryptoPP::PK_DecryptorFilter(m_rng, decryptor, new CryptoPP::VectorSink(plain)));
    } catch (const CryptoPP::Exception& e) {
        throw CryptoError(std::string("RSA decryption failed: ") + e.what());
    }
    return plain;
}
