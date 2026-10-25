// Building requests and parsing responses
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "Constants.h"

class Connection;

struct Response {
    uint8_t version = 0;
    uint16_t code = 0;
    std::vector<uint8_t> payload;
};

struct AesKeyPayload {
    ClientId clientId{};
    std::vector<uint8_t> encryptedKey;
};

struct FileReceivedPayload {
    ClientId clientId{};
    uint32_t contentSize = 0;
    std::string fileName;
    uint32_t cksum = 0;
};

struct FilePacketInfo {
    uint32_t contentSize = 0;
    uint32_t origSize = 0;
    uint16_t packetNumber = 0;
    uint16_t totalPackets = 0;
    std::string fileName;
};

class Protocol {
public:
    static std::vector<uint8_t> requestHeader(const ClientId& clientId, RequestCode code, uint32_t payloadSize);
    static std::vector<uint8_t> request(const ClientId& clientId, RequestCode code, std::span<const uint8_t> payload);

    static std::vector<uint8_t> packName(std::string_view name);
    static std::string unpackName(std::span<const uint8_t> field);

    static std::vector<uint8_t> namePayload(std::string_view name);
    static std::vector<uint8_t> publicKeyPayload(std::string_view name, std::span<const uint8_t> publicKey);
    static std::vector<uint8_t> filePacketHeader(const FilePacketInfo& info);

    static Response readResponse(Connection& connection);
    static ClientId parseClientId(std::span<const uint8_t> payload);
    static AesKeyPayload parseAesKey(std::span<const uint8_t> payload);
    static FileReceivedPayload parseFileReceived(std::span<const uint8_t> payload);
};
