// Tests for Cksum
#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

#include "Cksum.h"
#include "TestFramework.h"

static std::vector<uint8_t> bytesOf(std::string_view text)
{
    return {text.begin(), text.end()};
}

static std::vector<uint8_t> pattern(size_t size)
{
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
    }
    return data;
}

TEST(cksum_known_value)
{
    CHECK(memcrc(bytesOf("123456789")) == 930766865u);
}

TEST(cksum_empty)
{
    CHECK(memcrc({}) == 4294967295u);
}

TEST(cksum_single_char)
{
    CHECK(memcrc(bytesOf("a")) == 1220704766u);
}

TEST(cksum_text_with_newline)
{
    CHECK(memcrc(bytesOf("hello\n")) == 3015617425u);
}

TEST(cksum_matches_linux_and_python_on_100k)
{
    CHECK(memcrc(pattern(100000)) == 467883314u);
}

TEST(cksum_incremental_equals_whole)
{
    const auto data = pattern(100000);
    for (size_t piece : {1u, 7u, 4096u, 65536u}) {
        Cksum checksum;
        for (size_t pos = 0; pos < data.size(); pos += piece) {
            const size_t size = std::min(piece, data.size() - pos);
            checksum.update(std::span(data).subspan(pos, size));
        }
        CHECK(checksum.digest() == memcrc(data));
    }
}

TEST(cksum_digest_twice_is_same)
{
    Cksum checksum;
    checksum.update(bytesOf("123456789"));
    CHECK(checksum.digest() == checksum.digest());
}

TEST(cksum_length_affects_result)
{
    CHECK(memcrc(std::vector<uint8_t>{0}) != memcrc(std::vector<uint8_t>{0, 0}));
}
