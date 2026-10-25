// Runs all client tests
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

#include "TestFramework.h"

int runInteropTool(const std::string& command, const std::filesystem::path& dir);

std::vector<TestCase>& testRegistry()
{
    static std::vector<TestCase> tests;
    return tests;
}

static int runTests()
{
    int failed = 0;
    for (const auto& test : testRegistry()) {
        try {
            test.body();
            std::cout << "[ OK ]   " << test.name << std::endl;
        } catch (const std::exception& e) {
            ++failed;
            std::cout << "[FAIL]   " << test.name << ": " << e.what() << std::endl;
        }
    }
    std::cout << std::endl << testRegistry().size() << " tests, " << failed << " failed" << std::endl;
    return failed == 0 ? 0 : 1;
}

int main(int argc, char* argv[])
{
    if (argc == 3) {
        try {
            return runInteropTool(argv[1], argv[2]);
        } catch (const std::exception& e) {
            std::cerr << "Interop error: " << e.what() << std::endl;
            return 1;
        }
    }
    return runTests();
}
