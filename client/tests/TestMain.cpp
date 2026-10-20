#include <exception>
#include <iostream>

#include "TestFramework.h"

std::vector<TestCase>& testRegistry()
{
    static std::vector<TestCase> tests;
    return tests;
}

int main()
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
