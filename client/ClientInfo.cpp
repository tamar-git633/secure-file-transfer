#include "ClientInfo.h"

#include <charconv>
#include <fstream>
#include <iterator>
#include <sstream>

#include "Base64Wrapper.h"
#include "Errors.h"

namespace {

constexpr uintmax_t MAX_INFO_FILE_SIZE = 64 * 1024;
constexpr unsigned int HEX_BASE = 16;
constexpr size_t HEX_CHARS_PER_BYTE = 2;
constexpr char HEX_DIGITS[] = "0123456789abcdef";
constexpr unsigned int NIBBLE_BITS = 4;
constexpr uint8_t NIBBLE_MASK = 0x0F;
constexpr char FIRST_PRINTABLE = ' ';
constexpr char LAST_PRINTABLE = '~';

std::string readSmallFile(const std::filesystem::path& path)
{
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error) {
        throw ConfigError("Cannot read " + path.string());
    }
    if (size > MAX_INFO_FILE_SIZE) {
        throw ConfigError(path.string() + " is too large");
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw ConfigError("Cannot read " + path.string());
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::vector<std::string> splitLines(const std::string& text)
{
    std::vector<std::string> lines;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

// Writes to a temp file first and then renames it, so a crash in the middle
// never leaves a half written file behind
void writeFile(const std::filesystem::path& path, const std::string& content)
{
    auto temp = path;
    temp += ".tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        out << content;
        if (!out.flush()) {
            throw ConfigError("Cannot write " + path.string());
        }
    }
    std::error_code error;
    std::filesystem::rename(temp, path, error);
    if (error) {
        std::filesystem::remove(temp, error);
        throw ConfigError("Cannot write " + path.string());
    }
}

void checkName(const std::string& name)
{
    if (name.empty() || name.size() > constants::MAX_CLIENT_NAME_LENGTH) {
        throw ConfigError("Name in me.info must be 1 to 100 characters");
    }
    for (char c : name) {
        if (c < FIRST_PRINTABLE || c > LAST_PRINTABLE) {
            throw ConfigError("Name in me.info must be ASCII");
        }
    }
}

}

ClientInfo::ClientInfo(std::filesystem::path directory)
    : m_meFile(directory / constants::ME_FILE), m_keyFile(directory / constants::PRIVATE_KEY_FILE)
{
}

bool ClientInfo::exists() const
{
    return std::filesystem::is_regular_file(m_meFile);
}

// Loads the saved identity. The private key is taken from priv.key,
// or from the third line of me.info if priv.key is missing.
ClientIdentity ClientInfo::load() const
{
    const auto lines = splitLines(readSmallFile(m_meFile));
    if (lines.size() < 2) {
        throw ConfigError("me.info must have the name and the client ID");
    }

    ClientIdentity identity;
    identity.name = lines[0];
    checkName(identity.name);
    identity.id = idFromHex(lines[1]);

    std::string keyText;
    if (std::filesystem::is_regular_file(m_keyFile)) {
        const auto keyLines = splitLines(readSmallFile(m_keyFile));
        if (!keyLines.empty()) {
            keyText = keyLines[0];
        }
    } else if (lines.size() >= 3) {
        keyText = lines[2];
    }
    if (keyText.empty()) {
        throw ConfigError("Private key not found in priv.key or me.info");
    }
    identity.privateKeyDer = Base64Wrapper::decode(keyText);
    return identity;
}

void ClientInfo::save(const ClientIdentity& identity) const
{
    checkName(identity.name);
    const std::string keyText = Base64Wrapper::encode(identity.privateKeyDer);
    writeFile(m_meFile, identity.name + "\n" + idToHex(identity.id) + "\n" + keyText + "\n");
    writeFile(m_keyFile, keyText + "\n");
}

std::string ClientInfo::idToHex(const ClientId& id)
{
    std::string hex;
    hex.reserve(id.size() * HEX_CHARS_PER_BYTE);
    for (uint8_t byte : id) {
        hex += HEX_DIGITS[byte >> NIBBLE_BITS];
        hex += HEX_DIGITS[byte & NIBBLE_MASK];
    }
    return hex;
}

ClientId ClientInfo::idFromHex(std::string_view hex)
{
    ClientId id{};
    if (hex.size() != id.size() * HEX_CHARS_PER_BYTE) {
        throw ConfigError("Client ID in me.info must be 32 hex digits");
    }
    for (size_t i = 0; i < id.size(); ++i) {
        const char* begin = hex.data() + i * HEX_CHARS_PER_BYTE;
        const auto [end, error] = std::from_chars(begin, begin + HEX_CHARS_PER_BYTE, id[i], HEX_BASE);
        if (error != std::errc() || end != begin + HEX_CHARS_PER_BYTE) {
            throw ConfigError("Client ID in me.info must be 32 hex digits");
        }
    }
    return id;
}
