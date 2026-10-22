#include "Config.h"

#include <cctype>
#include <cmath>
#include <fstream>
#include <iterator>

#include "Constants.h"
#include "Errors.h"
#include "JsonParser.h"
#include "TextUtils.h"

namespace {

constexpr uintmax_t MAX_CONFIG_FILE_SIZE = 1024 * 1024;
constexpr size_t MAX_HOST_LENGTH = 253;
constexpr double MIN_PORT = 1;
constexpr double MAX_PORT = 65535;
constexpr char FIRST_PRINTABLE = ' ';
constexpr char LAST_PRINTABLE = '~';

bool isPrintableAscii(std::string_view text)
{
    for (char c : text) {
        if (c < FIRST_PRINTABLE || c > LAST_PRINTABLE) {
            return false;
        }
    }
    return true;
}

bool isValidHost(std::string_view host)
{
    if (host.empty() || host.size() > MAX_HOST_LENGTH) {
        return false;
    }
    for (char c : host) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != ':') {
            return false;
        }
    }
    return true;
}

std::filesystem::path pathFromUtf8(const std::string& text)
{
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

}

Config Config::load(const std::filesystem::path& path)
{
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error) {
        throw ConfigError("Cannot open " + text::pathToUtf8(path));
    }
    if (size > MAX_CONFIG_FILE_SIZE) {
        throw ConfigError(text::pathToUtf8(path) + " is too large");
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw ConfigError("Cannot open " + text::pathToUtf8(path));
    }
    std::string content{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    text::stripUtf8Bom(content);
    return parse(content);
}

// Parses transfer.json text and checks every field
Config Config::parse(std::string_view json)
{
    const JsonValue root = JsonParser::parse(json);
    const JsonValue& server = root.at("server");
    Config config;

    config.m_host = server.at("ip").asString("server.ip");
    if (!isValidHost(config.m_host)) {
        throw ConfigError("Invalid server address '" + config.m_host + "'");
    }

    const double port = server.at("port").asNumber("server.port");
    if (port < MIN_PORT || port > MAX_PORT || std::floor(port) != port) {
        throw ConfigError("server.port must be a whole number between 1 and 65535");
    }
    config.m_port = static_cast<uint16_t>(port);

    config.m_clientName = server.at("client").asString("server.client");
    if (config.m_clientName.empty() || config.m_clientName.size() > constants::MAX_CLIENT_NAME_LENGTH) {
        throw ConfigError("Client name must be 1 to 100 characters");
    }
    if (!isPrintableAscii(config.m_clientName)) {
        throw ConfigError("Client name must contain English letters, digits and symbols only");
    }

    const auto& files = root.at("files").asArray("files");
    if (files.empty()) {
        throw ConfigError("The files list is empty");
    }
    for (const auto& file : files) {
        const std::string& name = file.asString("Every item in files");
        if (name.empty()) {
            throw ConfigError("Empty file path in files");
        }
        config.m_files.push_back(pathFromUtf8(name));
    }
    return config;
}
