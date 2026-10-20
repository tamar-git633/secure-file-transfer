#include "Protocol.h"

#include <algorithm>

#include "Connection.h"
#include "Endian.h"
#include "Errors.h"

namespace {

constexpr size_t VERSION_OFFSET = 0;
constexpr size_t CODE_OFFSET = VERSION_OFFSET + constants::VERSION_FIELD_SIZE;
constexpr size_t SIZE_OFFSET = CODE_OFFSET + constants::CODE_FIELD_SIZE;
constexpr size_t MIN_ENCRYPTED_KEY_SIZE = 1;
constexpr size_t MAX_ENCRYPTED_KEY_SIZE = 512;
constexpr size_t FILE_RECEIVED_SIZE =
    constants::CLIENT_ID_SIZE + constants::SIZE_FIELD_SIZE + constants::NAME_SIZE + constants::SIZE_FIELD_SIZE;

ClientId readClientId(std::span<const uint8_t> payload)
{
    if (payload.size() < constants::CLIENT_ID_SIZE) {
        throw ProtocolError("Response is too short for a client ID");
    }
    ClientId id{};
    std::copy_n(payload.begin(), id.size(), id.begin());
    return id;
}

}

std::vector<uint8_t> Protocol::requestHeader(const ClientId& clientId, RequestCode code, uint32_t payloadSize)
{
    std::vector<uint8_t> header(clientId.begin(), clientId.end());
    header.push_back(constants::CLIENT_VERSION);
    endian::appendLE16(header, static_cast<uint16_t>(code));
    endian::appendLE32(header, payloadSize);
    return header;
}

std::vector<uint8_t> Protocol::request(const ClientId& clientId, RequestCode code, std::span<const uint8_t> payload)
{
    if (payload.size() > UINT32_MAX) {
        throw ProtocolError("Request payload is too large");
    }
    auto message = requestHeader(clientId, code, static_cast<uint32_t>(payload.size()));
    message.insert(message.end(), payload.begin(), payload.end());
    return message;
}

// Puts a name in a 255 byte field padded with zeros. The name must leave
// room for the terminating null and must not contain a null itself.
std::vector<uint8_t> Protocol::packName(std::string_view name)
{
    if (name.empty() || name.size() >= constants::NAME_SIZE) {
        throw ProtocolError("Name must be 1 to 254 characters");
    }
    if (name.find('\0') != std::string_view::npos) {
        throw ProtocolError("Name contains a null character");
    }
    std::vector<uint8_t> field(name.begin(), name.end());
    field.resize(constants::NAME_SIZE, 0);
    return field;
}

std::string Protocol::unpackName(std::span<const uint8_t> field)
{
    if (field.size() != constants::NAME_SIZE) {
        throw ProtocolError("Name field must be 255 bytes");
    }
    const auto end = std::find(field.begin(), field.end(), uint8_t{0});
    if (end == field.end()) {
        throw ProtocolError("Name field is not null terminated");
    }
    return {field.begin(), end};
}

std::vector<uint8_t> Protocol::namePayload(std::string_view name)
{
    return packName(name);
}

std::vector<uint8_t> Protocol::publicKeyPayload(std::string_view name, std::span<const uint8_t> publicKey)
{
    if (publicKey.size() != constants::PUBLIC_KEY_SIZE) {
        throw ProtocolError("Public key must be 160 bytes");
    }
    auto payload = packName(name);
    payload.insert(payload.end(), publicKey.begin(), publicKey.end());
    return payload;
}

std::vector<uint8_t> Protocol::filePacketHeader(const FilePacketInfo& info)
{
    std::vector<uint8_t> header;
    endian::appendLE32(header, info.contentSize);
    endian::appendLE32(header, info.origSize);
    endian::appendLE16(header, info.packetNumber);
    endian::appendLE16(header, info.totalPackets);
    const auto name = packName(info.fileName);
    header.insert(header.end(), name.begin(), name.end());
    return header;
}

// Reads one full response. The payload size from the server is checked
// before allocating memory for it.
Response Protocol::readResponse(Connection& connection)
{
    const auto header = connection.recvExact(constants::RESPONSE_HEADER_SIZE);
    Response response;
    response.version = header[VERSION_OFFSET];
    response.code = endian::readLE16(header, CODE_OFFSET);
    const uint32_t payloadSize = endian::readLE32(header, SIZE_OFFSET);
    if (payloadSize > constants::MAX_RESPONSE_PAYLOAD) {
        throw ProtocolError("Response payload too large: " + std::to_string(payloadSize));
    }
    response.payload = connection.recvExact(payloadSize);
    return response;
}

ClientId Protocol::parseClientId(std::span<const uint8_t> payload)
{
    if (payload.size() != constants::CLIENT_ID_SIZE) {
        throw ProtocolError("Response payload must be a 16 byte client ID");
    }
    return readClientId(payload);
}

AesKeyPayload Protocol::parseAesKey(std::span<const uint8_t> payload)
{
    AesKeyPayload result;
    result.clientId = readClientId(payload);
    const auto key = payload.subspan(constants::CLIENT_ID_SIZE);
    if (key.size() < MIN_ENCRYPTED_KEY_SIZE || key.size() > MAX_ENCRYPTED_KEY_SIZE) {
        throw ProtocolError("Encrypted AES key has a bad size");
    }
    result.encryptedKey.assign(key.begin(), key.end());
    return result;
}

FileReceivedPayload Protocol::parseFileReceived(std::span<const uint8_t> payload)
{
    if (payload.size() != FILE_RECEIVED_SIZE) {
        throw ProtocolError("File received response has a bad size");
    }
    FileReceivedPayload result;
    size_t offset = 0;
    result.clientId = readClientId(payload);
    offset += constants::CLIENT_ID_SIZE;
    result.contentSize = endian::readLE32(payload, offset);
    offset += constants::SIZE_FIELD_SIZE;
    result.fileName = unpackName(payload.subspan(offset, constants::NAME_SIZE));
    offset += constants::NAME_SIZE;
    result.cksum = endian::readLE32(payload, offset);
    return result;
}
