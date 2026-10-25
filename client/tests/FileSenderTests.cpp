// Tests for FileSender
#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <aes.h>
#include <filters.h>
#include <modes.h>

#include "Cksum.h"
#include "Connection.h"
#include "Constants.h"
#include "Endian.h"
#include "Errors.h"
#include "FileSender.h"
#include "Protocol.h"
#include "TestFramework.h"
#include "TestServer.h"

namespace fs = std::filesystem;

namespace {

struct ReceivedPacket {
    uint16_t code = 0;
    uint32_t payloadSize = 0;
    FilePacketInfo info;
    size_t contentLength = 0;
};

struct ReceivedFile {
    std::vector<ReceivedPacket> packets;
    std::vector<uint8_t> content;
    ClientId clientId{};
};

std::vector<uint8_t> testKey()
{
    std::vector<uint8_t> key(constants::AES_KEY_SIZE);
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(200 - i);
    }
    return key;
}

ClientId testId()
{
    ClientId id{};
    id.fill(0x42);
    return id;
}

std::vector<uint8_t> pattern(size_t size)
{
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((i * 7 + i / 251) & 0xFF);
    }
    return data;
}

std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipher)
{
    const auto key = testKey();
    const std::array<uint8_t, constants::AES_BLOCK_SIZE> iv{};
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key.data(), key.size(), iv.data());
    std::vector<uint8_t> plain;
    CryptoPP::ArraySource source(cipher.data(), cipher.size(), true,
        new CryptoPP::StreamTransformationFilter(decryption, new CryptoPP::VectorSink(plain)));
    return plain;
}

ReceivedFile receiveFile(SOCKET client)
{
    ReceivedFile file;
    while (true) {
        const auto header = recvRaw(client, constants::REQUEST_HEADER_SIZE);
        if (header.size() != constants::REQUEST_HEADER_SIZE) {
            return file;
        }
        std::copy_n(header.begin(), file.clientId.size(), file.clientId.begin());
        ReceivedPacket packet;
        packet.code = endian::readLE16(header, 17);
        packet.payloadSize = endian::readLE32(header, 19);
        const auto payload = recvRaw(client, packet.payloadSize);
        packet.info.contentSize = endian::readLE32(payload, 0);
        packet.info.origSize = endian::readLE32(payload, 4);
        packet.info.packetNumber = endian::readLE16(payload, 8);
        packet.info.totalPackets = endian::readLE16(payload, 10);
        packet.info.fileName = Protocol::unpackName(std::span(payload).subspan(12, constants::NAME_SIZE));
        packet.contentLength = payload.size() - constants::FILE_PACKET_HEADER_SIZE;
        file.content.insert(file.content.end(), payload.begin() + constants::FILE_PACKET_HEADER_SIZE, payload.end());
        file.packets.push_back(packet);
        if (packet.info.packetNumber == packet.info.totalPackets) {
            return file;
        }
    }
}

class TempFile {
public:
    TempFile(const std::string& name, const std::vector<uint8_t>& data)
        : m_path(fs::temp_directory_path() / name)
    {
        std::ofstream out(m_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    ~TempFile() { fs::remove(m_path); }
    const fs::path& path() const { return m_path; }

private:
    fs::path m_path;
};

void checkSend(size_t size)
{
    const auto data = pattern(size);
    TempFile file("sender_test.bin", data);
    ReceivedFile received;
    SentFile sent;
    {
        TestServer server([&received](SOCKET client) { received = receiveFile(client); });
        Connection connection("127.0.0.1", server.port());
        FileSender sender(connection, testId(), testKey());
        sent = sender.send(file.path());
    }
    const uint32_t expectedContent = static_cast<uint32_t>((size / 16 + 1) * 16);
    const auto expectedPackets = (expectedContent + constants::PACKET_CONTENT_SIZE - 1) / constants::PACKET_CONTENT_SIZE;

    CHECK(sent.fileName == "sender_test.bin");
    CHECK(sent.contentSize == expectedContent);
    CHECK(sent.cksum == memcrc(data));
    CHECK(received.clientId == testId());
    CHECK(received.packets.size() == expectedPackets);
    for (size_t i = 0; i < received.packets.size(); ++i) {
        const auto& packet = received.packets[i];
        CHECK(packet.code == static_cast<uint16_t>(RequestCode::SendFile));
        CHECK(packet.info.packetNumber == i + 1);
        CHECK(packet.info.totalPackets == expectedPackets);
        CHECK(packet.info.contentSize == expectedContent);
        CHECK(packet.info.origSize == size);
        CHECK(packet.info.fileName == "sender_test.bin");
        CHECK(packet.payloadSize == constants::FILE_PACKET_HEADER_SIZE + packet.contentLength);
        if (i + 1 < received.packets.size()) {
            CHECK(packet.contentLength == constants::PACKET_CONTENT_SIZE);
        }
    }
    CHECK(received.content.size() == expectedContent);
    CHECK(decrypt(received.content) == data);
}

}

TEST(sender_empty_file)
{
    checkSend(0);
}

TEST(sender_small_file)
{
    checkSend(1);
    checkSend(100);
}

TEST(sender_exactly_one_packet)
{
    checkSend(constants::PACKET_CONTENT_SIZE - 16);
}

TEST(sender_just_over_one_packet)
{
    checkSend(constants::PACKET_CONTENT_SIZE);
}

TEST(sender_100k_file)
{
    checkSend(100000);
}

TEST(sender_large_file)
{
    checkSend(3 * 1000 * 1000 + 7);
}

TEST(sender_sizes_and_limits)
{
    CHECK(FileSender::checkedContentSize(100000) == 100016);
    CHECK(FileSender::checkedContentSize(4294967279ULL) == 4294967280u);
    CHECK_THROWS(FileSender::checkedContentSize(4294967280ULL), FileError);
    CHECK(FileSender::packetCount(16) == 1);
    CHECK(FileSender::packetCount(65536) == 1);
    CHECK(FileSender::packetCount(65537) == 2);
    CHECK(FileSender::packetCount(65535u * 65536u) == 65535);
    CHECK_THROWS(FileSender::packetCount(65535u * 65536u + 1), FileError);
    CHECK_THROWS(FileSender::packetCount(4294967280u), FileError);
}

TEST(sender_file_name_rules)
{
    CHECK(FileSender::protocolFileName("c:\\docs\\report.pdf") == "report.pdf");
    CHECK(FileSender::protocolFileName("dir/sub/a.bin") == "a.bin");
    CHECK_THROWS(FileSender::protocolFileName(fs::path(u8"c:/docs/\u05e7\u05d5\u05d1\u05e5.txt")), FileError);
    CHECK_THROWS(FileSender::protocolFileName("c:\\docs\\" + std::string(260, 'a')), FileError);
}

TEST(sender_missing_file)
{
    TestServer server([](SOCKET) {});
    Connection connection("127.0.0.1", server.port());
    FileSender sender(connection, testId(), testKey());
    CHECK_THROWS(sender.send(fs::temp_directory_path() / "no_such_file_123.bin"), FileError);
}
