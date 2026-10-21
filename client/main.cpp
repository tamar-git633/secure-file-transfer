#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

#include <windows.h>

#include "Constants.h"
#include "Errors.h"
#include "FileTransferClient.h"

namespace {

constexpr DWORD INITIAL_PATH_SIZE = MAX_PATH;
constexpr DWORD MAX_PATH_SIZE = 32 * 1024;

// The folder of the running exe, transfer.json and me.info are kept there
std::filesystem::path executableDirectory()
{
    std::wstring buffer(INITIAL_PATH_SIZE, L'\0');
    while (buffer.size() <= MAX_PATH_SIZE) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            break;
        }
        if (length < buffer.size()) {
            buffer.resize(length);
            return std::filesystem::path(buffer).parent_path();
        }
        buffer.resize(buffer.size() * 2);
    }
    return std::filesystem::current_path();
}

}

int main()
{
    std::cout << "File transfer client, version " << static_cast<int>(constants::CLIENT_VERSION) << std::endl;
    try {
        FileTransferClient client(executableDirectory());
        return client.run() ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << std::endl;
        return 1;
    }
}
