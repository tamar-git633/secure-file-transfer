// RSA key pair of the client
#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include <osrng.h>
#include <rsa.h>

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
