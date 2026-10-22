#include "FileSender.h"

#include <algorithm>
#include <fstream>

#include "AESWrapper.h"
#include "Cksum.h"
#include "Connection.h"
#include "Errors.h"
#include "TextUtils.h"

namespace {

constexpr char FIRST_PRINTABLE = ' ';
constexpr char LAST_PRINTABLE = '~';

}

FileSender::FileSender(Connection& connection, const ClientId& clientId, std::span<const uint8_t> aesKey)
    : m_connection(connection), m_clientId(clientId), m_aesKey(aesKey.begin(), aesKey.end())
{
}

// The protocol carries only the file name (not the folder), in ASCII
std::string FileSender::protocolFileName(const std::filesystem::path& path)
{
    const std::u8string utf8 = path.filename().u8string();
    std::string name(utf8.begin(), utf8.end());
    if (name.empty() || name.size() >= constants::NAME_SIZE) {
        throw FileError("File name must be 1 to 254 characters");
    }
    for (char c : name) {
        if (c < FIRST_PRINTABLE || c > LAST_PRINTABLE) {
            throw FileError("File name '" + text::pathToUtf8(path.filename()) + "' must be in English letters");
        }
    }
    return name;
}

// The encrypted size must fit the 4 byte Content Size field
uint32_t FileSender::checkedContentSize(uint64_t origSize)
{
    const uint64_t contentSize = AesStreamEncryptor::encryptedSize(origSize);
    if (contentSize > UINT32_MAX) {
        throw FileError("File is too large for the protocol (max 4GB)");
    }
    return static_cast<uint32_t>(contentSize);
}

uint16_t FileSender::packetCount(uint32_t contentSize)
{
    const uint64_t count = (static_cast<uint64_t>(contentSize) + constants::PACKET_CONTENT_SIZE - 1) /
                           constants::PACKET_CONTENT_SIZE;
    if (count == 0 || count > constants::MAX_PACKETS) {
        throw FileError("File is too large for the protocol (too many packets)");
    }
    return static_cast<uint16_t>(count);
}

// Reads the file in blocks, encrypts each block and sends a packet every
// time a full packet of encrypted data is ready. Memory use stays around
// two packets no matter how big the file is.
SentFile FileSender::send(const std::filesystem::path& path)
{
    std::error_code error;
    const uint64_t origSize = std::filesystem::file_size(path, error);
    if (error) {
        throw FileError("Cannot read the file");
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw FileError("Cannot open the file, it may be in use by another program");
    }

    FilePacketInfo info;
    info.fileName = protocolFileName(path);
    info.contentSize = checkedContentSize(origSize);
    info.origSize = static_cast<uint32_t>(origSize);
    info.totalPackets = packetCount(info.contentSize);
    info.packetNumber = 1;

    AesStreamEncryptor encryptor(m_aesKey);
    Cksum checksum;
    std::vector<uint8_t> readBuffer(constants::PACKET_CONTENT_SIZE);
    std::vector<uint8_t> pending;
    uint64_t sentBytes = 0;

    auto sendReady = [&](bool flushAll) {
        size_t offset = 0;
        while (pending.size() - offset >= constants::PACKET_CONTENT_SIZE ||
               (flushAll && offset < pending.size())) {
            const size_t size = std::min(constants::PACKET_CONTENT_SIZE, pending.size() - offset);
            sendPacket(info, std::span(pending).subspan(offset, size));
            offset += size;
            sentBytes += size;
            ++info.packetNumber;
        }
        pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(offset));
    };

    uint64_t readBytes = 0;
    while (readBytes < origSize) {
        in.read(reinterpret_cast<char*>(readBuffer.data()), static_cast<std::streamsize>(readBuffer.size()));
        const auto count = static_cast<size_t>(in.gcount());
        if (count == 0) {
            throw ClientError("File " + text::pathToUtf8(path) + " changed while sending");
        }
        readBytes += count;
        const std::span<const uint8_t> piece(readBuffer.data(), count);
        checksum.update(piece);
        const auto encrypted = encryptor.update(piece);
        pending.insert(pending.end(), encrypted.begin(), encrypted.end());
        sendReady(false);
    }
    const auto last = encryptor.finish();
    pending.insert(pending.end(), last.begin(), last.end());
    sendReady(true);

    if (sentBytes != info.contentSize || info.packetNumber - 1 != info.totalPackets) {
        throw ClientError("Sent size does not match the declared size");
    }
    return {info.fileName, info.contentSize, checksum.digest()};
}

void FileSender::sendPacket(const FilePacketInfo& info, std::span<const uint8_t> content)
{
    const auto packetHeader = Protocol::filePacketHeader(info);
    const auto payloadSize = static_cast<uint32_t>(packetHeader.size() + content.size());
    auto message = Protocol::requestHeader(m_clientId, RequestCode::SendFile, payloadSize);
    message.insert(message.end(), packetHeader.begin(), packetHeader.end());
    message.insert(message.end(), content.begin(), content.end());
    m_connection.sendAll(message);
}
