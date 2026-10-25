#include <filesystem>
#include <fstream>
#include <string>

#include "Config.h"
#include "Errors.h"
#include "JsonParser.h"
#include "TestFramework.h"

static const char* VALID_JSON = R"({
    "server": {
        "ip": "192.168.1.5",
        "port": 1265,
        "client": "MyComputer"
    },
    "files": ["c:\\doc\\file02.docx",
              "c:/openu/defensive/file06-2026c.pdf"]
})";

static std::string withServer(const std::string& ip, const std::string& port, const std::string& client)
{
    return R"({"server": {"ip": )" + ip + R"(, "port": )" + port + R"(, "client": )" + client +
           R"(}, "files": ["a.txt"]})";
}

TEST(config_valid_example)
{
    const Config config = Config::parse(VALID_JSON);
    CHECK(config.host() == "192.168.1.5");
    CHECK(config.port() == 1265);
    CHECK(config.clientName() == "MyComputer");
    CHECK(config.files().size() == 2);
    CHECK(config.files()[0] == std::filesystem::path("c:\\doc\\file02.docx"));
    CHECK(config.files()[1].filename() == "file06-2026c.pdf");
}

TEST(config_hostname_allowed)
{
    CHECK(Config::parse(withServer(R"("localhost")", "1234", R"("bob")")).host() == "localhost");
}

TEST(config_assignment_example_with_single_backslash)
{
    const std::string json = R"({"server": {"ip": "1.2.3.4", "port": 1, "client": "a"},
                                 "files": ["c:\doc\file02.docx", "c:\openu\defensive\file06-2026c.pdf"]})";
    const Config config = Config::parse(json);
    CHECK(config.files()[0] == std::filesystem::path("c:\\doc\\file02.docx"));
    CHECK(config.files()[1] == std::filesystem::path("c:\\openu\\defensive\\file06-2026c.pdf"));
}

TEST(config_single_backslash_that_looks_like_escape)
{
    const std::string json = R"({"server": {"ip": "1.2.3.4", "port": 1, "client": "a"},
                                 "files": ["c:\temp\new\files\report.txt", "c:\users\bob\run.bin"]})";
    const Config config = Config::parse(json);
    CHECK(config.files()[0] == std::filesystem::path("c:\\temp\\new\\files\\report.txt"));
    CHECK(config.files()[1] == std::filesystem::path("c:\\users\\bob\\run.bin"));
}

TEST(config_double_backslash_still_works)
{
    const std::string json = R"({"server": {"ip": "1.2.3.4", "port": 1, "client": "a"},
                                 "files": ["c:\\temp\\new.txt"]})";
    CHECK(Config::parse(json).files()[0] == std::filesystem::path("c:\\temp\\new.txt"));
}

TEST(json_unknown_escape_is_kept)
{
    const std::string unknownEscape = R"("a\qb")";
    const std::string notHexAfterU = R"("\users")";
    CHECK(JsonParser::parse(unknownEscape).asString("s") == "a\\qb");
    CHECK(JsonParser::parse(notHexAfterU).asString("s") == "\\users");
}

TEST(config_missing_fields)
{
    CHECK_THROWS(Config::parse(R"({"files": ["a"]})"), ConfigError);
    CHECK_THROWS(Config::parse(R"({"server": {"ip": "1.2.3.4", "port": 1, "client": "a"}})"), ConfigError);
    CHECK_THROWS(Config::parse(R"({"server": {"port": 1, "client": "a"}, "files": ["a"]})"), ConfigError);
    CHECK_THROWS(Config::parse(R"({"server": {"ip": "1.2.3.4", "client": "a"}, "files": ["a"]})"), ConfigError);
    CHECK_THROWS(Config::parse(R"({"server": {"ip": "1.2.3.4", "port": 1}, "files": ["a"]})"), ConfigError);
}

TEST(config_bad_port)
{
    for (const char* port : {"0", "-5", "65536", "12.5", "\"1234\"", "1e9"}) {
        CHECK_THROWS(Config::parse(withServer(R"("1.2.3.4")", port, R"("bob")")), ConfigError);
    }
    CHECK(Config::parse(withServer(R"("1.2.3.4")", "65535", R"("bob")")).port() == 65535);
}

TEST(config_bad_client_name)
{
    CHECK_THROWS(Config::parse(withServer(R"("1.2.3.4")", "1", R"("")")), ConfigError);
    CHECK_THROWS(Config::parse(withServer(R"("1.2.3.4")", "1", "\"" + std::string(101, 'a') + "\"")), ConfigError);
    CHECK_THROWS(Config::parse(withServer(R"("1.2.3.4")", "1", R"("\u05ea\u05de\u05e8")")), ConfigError);
    CHECK_THROWS(Config::parse(withServer(R"("1.2.3.4")", "1", R"("a\nb")")), ConfigError);
    CHECK(Config::parse(withServer(R"("1.2.3.4")", "1", "\"" + std::string(100, 'a') + "\"")).clientName().size() ==
          100);
}

TEST(config_bad_host)
{
    CHECK_THROWS(Config::parse(withServer(R"("")", "1", R"("bob")")), ConfigError);
    CHECK_THROWS(Config::parse(withServer(R"("1.2.3.4; rm")", "1", R"("bob")")), ConfigError);
    CHECK_THROWS(Config::parse(withServer("5", "1", R"("bob")")), ConfigError);
}

TEST(config_bad_files)
{
    const std::string server = R"({"server": {"ip": "1.2.3.4", "port": 1, "client": "a"}, "files": )";
    CHECK_THROWS(Config::parse(server + "[]}"), ConfigError);
    CHECK_THROWS(Config::parse(server + R"("a.txt"})"), ConfigError);
    CHECK_THROWS(Config::parse(server + R"([""]})"), ConfigError);
    CHECK_THROWS(Config::parse(server + R"([5]})"), ConfigError);
}

TEST(json_invalid_syntax)
{
    for (const char* text : {"", "{", R"({"a": 1,})", R"({"a" 1})", R"({"a": "x)", R"({"a": 1} extra)",
                             R"([1, 2,])", R"({"a": tru})", R"({"a": 1, "a": 2})", R"({'a': 1})"}) {
        CHECK_THROWS(JsonParser::parse(text), ConfigError);
    }
}

TEST(json_too_deep)
{
    CHECK_THROWS(JsonParser::parse(std::string(100, '[') + std::string(100, ']')), ConfigError);
}

TEST(json_values)
{
    const JsonValue value = JsonParser::parse(R"({"n": -1.5e2, "s": "a\"b\\c\/d\u0041", "list": [true, false, null]})");
    CHECK(value.at("n").asNumber("n") == -150);
    CHECK(value.at("s").asString("s") == "a\"b\\c/dA");
    CHECK(value.at("list").asArray("list").size() == 3);
}

TEST(json_unicode_escape_to_utf8)
{
    const JsonValue value = JsonParser::parse(R"("\u05ea")");
    CHECK(value.asString("s") == "\xD7\xAA");
}

TEST(config_load_from_file)
{
    const auto path = std::filesystem::temp_directory_path() / "transfer_test.json";
    {
        std::ofstream out(path);
        out << VALID_JSON;
    }
    CHECK(Config::load(path).clientName() == "MyComputer");
    std::filesystem::remove(path);
    CHECK_THROWS(Config::load(path), ConfigError);
}

TEST(config_load_with_utf8_bom)
{
    const auto path = std::filesystem::temp_directory_path() / "transfer_bom_test.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << "\xEF\xBB\xBF" << VALID_JSON;
    }
    CHECK(Config::load(path).port() == 1265);
    std::filesystem::remove(path);
}
