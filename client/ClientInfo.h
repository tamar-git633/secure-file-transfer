#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "Constants.h"

// What the client keeps in me.info: name, ID from the server, private key
struct ClientIdentity {
    std::string name;
    ClientId id{};
    std::vector<uint8_t> privateKeyDer;
};

// Reads and writes me.info (name, client ID, private key) and priv.key
// in the folder of the client program
class ClientInfo {
public:
    explicit ClientInfo(std::filesystem::path directory);

    bool exists() const;
    ClientIdentity load() const;
    void save(const ClientIdentity& identity) const;

    static std::string idToHex(const ClientId& id);
    static ClientId idFromHex(std::string_view hex);

private:
    std::filesystem::path m_meFile;
    std::filesystem::path m_keyFile;
};
