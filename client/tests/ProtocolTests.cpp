// Tests for Protocol
#include <cstdint>
#include <string>
#include <vector>

#include <filters.h>
#include <hex.h>
#include <sha.h>

#include "Constants.h"
#include "Errors.h"
#include "Protocol.h"
#include "TestFramework.h"

namespace {

ClientId sampleId()
{
    ClientId id{};
    for (size_t i = 0; i < id.size(); ++i) {
        id[i] = static_cast<uint8_t>(i);
    }
    return id;
}

std::string sha256Hex(const std::vector<uint8_t>& data)
{
    std::string hex;
    CryptoPP::SHA256 hash;
    CryptoPP::ArraySource source(data.data(), data.size(), true,
        new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hex), false)));
    return hex;
}

std::vector<uint8_t> fromHex(const std::string& hex)
{
    std::vector<uint8_t> data;
    CryptoPP::StringSource source(hex, true, new CryptoPP::HexDecoder(new CryptoPP::VectorSink(data)));
    return data;
}

std::vector<uint8_t> sequence(size_t size)
{
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(i);
    }
    return data;
}

}

TEST(protocol_register_matches_server)
{
    const auto message = Protocol::request(sampleId(), RequestCode::Register, Protocol::namePayload("alice"));
    CHECK(message.size() == 278);
    CHECK(sha256Hex(message) == "d583b0209deade437aa31e59b508069cb7addfb60998e7136f6aff785583c2d4");
}

TEST(protocol_public_key_matches_server)
{
    const auto payload = Protocol::publicKeyPayload("alice", sequence(160));
    const auto message = Protocol::request(sampleId(), RequestCode::SendPublicKey, payload);
    CHECK(message.size() == 438);
    CHECK(sha256Hex(message) == "02c41875c36c04973546ce784a5365206313e9f6a1d272f370b408832cc79337");
}

TEST(protocol_reconnect_matches_server)
{
    const auto message = Protocol::request(sampleId(), RequestCode::Reconnect, Protocol::namePayload("alice"));
    CHECK(sha256Hex(message) == "6d524fa0a118f1b058cc6cff10a1d00877a5026e6b6be07b83a4c347c58d8c1c");
}

TEST(protocol_crc_ok_matches_server)
{
    const auto message = Protocol::request(sampleId(), RequestCode::CrcOk, Protocol::namePayload("file.bin"));
    CHECK(sha256Hex(message) == "3d34bfc633c2f39eeab3ac5d2f02f74b32124782e8bf748971db9c9f5e0c290b");
}

TEST(protocol_file_packet_header_matches_server)
{
    const FilePacketInfo info{100016, 100000, 1, 2, "file.bin"};
    const auto packetHeader = Protocol::filePacketHeader(info);
    CHECK(packetHeader.size() == constants::FILE_PACKET_HEADER_SIZE);
    auto message = Protocol::requestHeader(sampleId(), RequestCode::SendFile,
                                           static_cast<uint32_t>(packetHeader.size() + 65536));
    message.insert(message.end(), packetHeader.begin(), packetHeader.end());
    CHECK(sha256Hex(message) == "36cc4b6c0dce620a772dc1553721d1ecd1fb76b898aa7cbfa37206900f88fda6");
}

TEST(protocol_parse_file_received_from_server)
{
    const auto response = fromHex(
        "03430617010000000102030405060708090a0b0c0d0e0fb086010066696c652e62696e" + std::string(494, '0') +
        "11607a37");
    CHECK(response.size() == 7 + 279);
    const auto payload = std::span(response).subspan(7);
    const FileReceivedPayload parsed = Protocol::parseFileReceived(payload);
    CHECK(parsed.clientId == sampleId());
    CHECK(parsed.contentSize == 100016);
    CHECK(parsed.fileName == "file.bin");
    CHECK(parsed.cksum == 930766865u);
}

TEST(protocol_name_limits)
{
    CHECK(Protocol::unpackName(Protocol::packName(std::string(254, 'a'))) == std::string(254, 'a'));
    CHECK_THROWS(Protocol::packName(std::string(255, 'a')), ProtocolError);
    CHECK_THROWS(Protocol::packName(""), ProtocolError);
    CHECK_THROWS(Protocol::packName(std::string("a\0b", 3)), ProtocolError);
    CHECK_THROWS(Protocol::unpackName(std::vector<uint8_t>(255, 'a')), ProtocolError);
    CHECK_THROWS(Protocol::unpackName(std::vector<uint8_t>(10, 0)), ProtocolError);
}

TEST(protocol_public_key_size_checked)
{
    CHECK_THROWS(Protocol::publicKeyPayload("alice", sequence(162)), ProtocolError);
}

TEST(protocol_parse_client_id)
{
    CHECK(Protocol::parseClientId(sequence(16)) == sampleId());
    CHECK_THROWS(Protocol::parseClientId(sequence(15)), ProtocolError);
    CHECK_THROWS(Protocol::parseClientId(sequence(17)), ProtocolError);
}

TEST(protocol_parse_aes_key)
{
    const AesKeyPayload parsed = Protocol::parseAesKey(sequence(16 + 128));
    CHECK(parsed.clientId == sampleId());
    CHECK(parsed.encryptedKey.size() == 128);
    CHECK(parsed.encryptedKey[0] == 16);
    CHECK_THROWS(Protocol::parseAesKey(sequence(16)), ProtocolError);
    CHECK_THROWS(Protocol::parseAesKey(sequence(10)), ProtocolError);
}

TEST(protocol_parse_file_received_bad_input)
{
    CHECK_THROWS(Protocol::parseFileReceived(sequence(100)), ProtocolError);
    std::vector<uint8_t> noNull(279, 'x');
    CHECK_THROWS(Protocol::parseFileReceived(noNull), ProtocolError);
}
