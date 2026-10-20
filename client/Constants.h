#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace constants {

inline constexpr uint8_t CLIENT_VERSION = 3;
inline constexpr uint8_t SERVER_VERSION = 3;

inline constexpr size_t CLIENT_ID_SIZE = 16;
inline constexpr size_t NAME_SIZE = 255;
inline constexpr size_t MAX_CLIENT_NAME_LENGTH = 100;
inline constexpr size_t PUBLIC_KEY_SIZE = 160;
inline constexpr size_t AES_KEY_SIZE = 32;
inline constexpr size_t AES_BLOCK_SIZE = 16;
inline constexpr unsigned int RSA_KEY_BITS = 1024;

inline constexpr size_t VERSION_FIELD_SIZE = sizeof(uint8_t);
inline constexpr size_t CODE_FIELD_SIZE = sizeof(uint16_t);
inline constexpr size_t SIZE_FIELD_SIZE = sizeof(uint32_t);
inline constexpr size_t PACKET_NUMBER_FIELD_SIZE = sizeof(uint16_t);

inline constexpr size_t REQUEST_HEADER_SIZE = CLIENT_ID_SIZE + VERSION_FIELD_SIZE + CODE_FIELD_SIZE + SIZE_FIELD_SIZE;
inline constexpr size_t RESPONSE_HEADER_SIZE = VERSION_FIELD_SIZE + CODE_FIELD_SIZE + SIZE_FIELD_SIZE;
inline constexpr size_t FILE_PACKET_HEADER_SIZE =
    SIZE_FIELD_SIZE + SIZE_FIELD_SIZE + PACKET_NUMBER_FIELD_SIZE + PACKET_NUMBER_FIELD_SIZE + NAME_SIZE;
inline constexpr size_t PACKET_CONTENT_SIZE = 64 * 1024;
inline constexpr uint32_t MAX_PACKETS = UINT16_MAX;
inline constexpr size_t MAX_RESPONSE_PAYLOAD = 64 * 1024;

inline constexpr int MAX_ATTEMPTS = 3;
inline constexpr int MAX_CRC_RESENDS = 3;
inline constexpr int SOCKET_TIMEOUT_MS = 60 * 1000;

inline constexpr char TRANSFER_FILE[] = "transfer.json";
inline constexpr char ME_FILE[] = "me.info";
inline constexpr char PRIVATE_KEY_FILE[] = "priv.key";

}

using ClientId = std::array<uint8_t, constants::CLIENT_ID_SIZE>;

enum class RequestCode : uint16_t {
    Register = 825,
    SendPublicKey = 826,
    Reconnect = 827,
    SendFile = 828,
    CrcOk = 900,
    CrcRetry = 901,
    CrcAbort = 902,
};

enum class ResponseCode : uint16_t {
    RegisterOk = 1600,
    RegisterFailed = 1601,
    AesKey = 1602,
    FileReceived = 1603,
    Ack = 1604,
    ReconnectOk = 1605,
    ReconnectDenied = 1606,
    GeneralError = 1607,
};
