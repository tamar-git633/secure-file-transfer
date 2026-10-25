// Small text helpers (UTF-8 BOM, paths)
#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace text {

inline constexpr std::string_view UTF8_BOM = "\xEF\xBB\xBF";

inline void stripUtf8Bom(std::string& content)
{
    if (content.starts_with(UTF8_BOM)) {
        content.erase(0, UTF8_BOM.size());
    }
}

inline std::string pathToUtf8(const std::filesystem::path& path)
{
    const std::u8string utf8 = path.u8string();
    return {utf8.begin(), utf8.end()};
}

}
