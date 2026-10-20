#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "Cksum.h"
#include "Constants.h"
#include "RSAWrapper.h"

namespace fs = std::filesystem;

static std::vector<uint8_t> readAll(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

static void writeAll(const fs::path& path, const std::vector<uint8_t>& data)
{
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

static void writeText(const fs::path& path, const std::string& text)
{
    std::ofstream out(path);
    out << text;
}

static int keygen(const fs::path& dir)
{
    RSAPrivateWrapper rsa;
    writeAll(dir / "public.der", rsa.publicKeyDer());
    writeText(dir / "private.b64", Base64Wrapper::encode(rsa.privateKeyDer()));
    std::cout << "C++: generated RSA key, public key " << rsa.publicKeyDer().size() << " bytes" << std::endl;
    return 0;
}

static int encryptFile(const fs::path& dir)
{
    std::ifstream keyFile(dir / "private.b64");
    std::string privateB64;
    std::getline(keyFile, privateB64);
    RSAPrivateWrapper rsa(Base64Wrapper::decode(privateB64));

    const auto aesKey = rsa.decrypt(readAll(dir / "aes.enc"));
    writeAll(dir / "aes.key", aesKey);
    std::cout << "C++: decrypted AES key, " << aesKey.size() << " bytes" << std::endl;

    AesStreamEncryptor encryptor(aesKey);
    Cksum checksum;
    std::ifstream in(dir / "plain.bin", std::ios::binary);
    std::ofstream out(dir / "cipher.bin", std::ios::binary);
    std::vector<uint8_t> buffer(constants::PACKET_CONTENT_SIZE);
    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto count = static_cast<size_t>(in.gcount());
        const std::span<const uint8_t> piece(buffer.data(), count);
        checksum.update(piece);
        const auto encrypted = encryptor.update(piece);
        out.write(reinterpret_cast<const char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
    }
    const auto last = encryptor.finish();
    out.write(reinterpret_cast<const char*>(last.data()), static_cast<std::streamsize>(last.size()));
    writeText(dir / "crc.txt", std::to_string(checksum.digest()));
    std::cout << "C++: encrypted plain.bin, cksum " << checksum.digest() << std::endl;
    return 0;
}

int runInteropTool(const std::string& command, const fs::path& dir)
{
    if (command == "keygen") {
        return keygen(dir);
    }
    if (command == "encrypt") {
        return encryptFile(dir);
    }
    std::cerr << "Unknown command " << command << std::endl;
    return 2;
}
