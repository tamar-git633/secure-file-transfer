// Loading and checking transfer.json
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

class Config {
public:
    static Config load(const std::filesystem::path& path);
    static Config parse(std::string_view json);

    const std::string& host() const { return m_host; }
    uint16_t port() const { return m_port; }
    const std::string& clientName() const { return m_clientName; }
    const std::vector<std::filesystem::path>& files() const { return m_files; }

private:
    std::string m_host;
    uint16_t m_port = 0;
    std::string m_clientName;
    std::vector<std::filesystem::path> m_files;
};
