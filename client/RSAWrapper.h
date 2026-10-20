#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include <osrng.h>
#include <rsa.h>

// Holds the client's RSA private key: creates or loads it, exports the
// public key for the server and decrypts the AES key the server sends
class RSAPrivateWrapper {
public:
    RSAPrivateWrapper();
    explicit RSAPrivateWrapper(std::span<const uint8_t> privateKeyDer);

    std::vector<uint8_t> privateKeyDer() const;
    std::vector<uint8_t> publicKeyDer() const;
    std::vector<uint8_t> decrypt(std::span<const uint8_t> cipher);

private:
    CryptoPP::AutoSeededRandomPool m_rng;
    CryptoPP::RSA::PrivateKey m_privateKey;
};
