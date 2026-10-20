#include <cstdint>
#include <vector>

#include "Constants.h"
#include "Endian.h"
#include "TestFramework.h"

TEST(append32_writes_little_endian)
{
    std::vector<uint8_t> out;
    endian::appendLE32(out, 0x12345678);
    CHECK((out == std::vector<uint8_t>{0x78, 0x56, 0x34, 0x12}));
}

TEST(append16_writes_little_endian)
{
    std::vector<uint8_t> out;
    endian::appendLE16(out, static_cast<uint16_t>(RequestCode::Register));
    CHECK((out == std::vector<uint8_t>{0x39, 0x03}));
}

TEST(append_keeps_existing_bytes)
{
    std::vector<uint8_t> out{0xAA};
    endian::appendLE16(out, 0x0102);
    CHECK((out == std::vector<uint8_t>{0xAA, 0x02, 0x01}));
}

TEST(read_matches_append)
{
    std::vector<uint8_t> out;
    endian::appendLE32(out, 0xDEADBEEF);
    endian::appendLE16(out, 0xFFFF);
    CHECK(endian::readLE32(out, 0) == 0xDEADBEEF);
    CHECK(endian::readLE16(out, 4) == 0xFFFF);
}

TEST(read_known_bytes)
{
    std::vector<uint8_t> data{0x40, 0x06, 0x10, 0x00, 0x00, 0x00};
    CHECK(endian::readLE16(data, 0) == static_cast<uint16_t>(ResponseCode::RegisterOk));
    CHECK(endian::readLE32(data, 2) == 16);
}

TEST(read_past_end_throws)
{
    std::vector<uint8_t> data{0x01, 0x02, 0x03};
    CHECK_THROWS(endian::readLE32(data, 0), ProtocolError);
    CHECK_THROWS(endian::readLE16(data, 2), ProtocolError);
    CHECK_THROWS(endian::readLE16(data, 100), ProtocolError);
}

static_assert(constants::REQUEST_HEADER_SIZE == 23);
static_assert(constants::RESPONSE_HEADER_SIZE == 7);
static_assert(constants::FILE_PACKET_HEADER_SIZE == 267);
