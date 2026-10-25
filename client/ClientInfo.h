// Reading and writing me.info and priv.key
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "Constants.h"

struct ClientIdentity {
    std::string name;
    ClientId id{};
    std::vector<uint8_t> privateKeyDer;
};

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
