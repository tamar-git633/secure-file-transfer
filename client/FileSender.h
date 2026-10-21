#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "Constants.h"
#include "Protocol.h"

class Connection;

// Result of sending a file: the name used, encrypted size and our cksum
struct SentFile {
    std::string fileName;
    uint32_t contentSize = 0;
    uint32_t cksum = 0;
};

// Sends one file to the server in 828 packets. The file is read,
// encrypted and sent piece by piece, the cksum is calculated on the way.
class FileSender {
public:
    FileSender(Connection& connection, const ClientId& clientId, std::span<const uint8_t> aesKey);

    SentFile send(const std::filesystem::path& path);

    static std::string protocolFileName(const std::filesystem::path& path);
    static uint32_t checkedContentSize(uint64_t origSize);
    static uint16_t packetCount(uint32_t contentSize);

private:
    void sendPacket(const FilePacketInfo& info, std::span<const uint8_t> content);

    Connection& m_connection;
    ClientId m_clientId;
    std::vector<uint8_t> m_aesKey;
};
