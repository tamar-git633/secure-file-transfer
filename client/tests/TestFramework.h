#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

struct TestCase {
    std::string name;
    std::function<void()> body;
};

class TestFailure : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::vector<TestCase>& testRegistry();

struct TestRegistrar {
    TestRegistrar(const char* name, std::function<void()> body)
    {
        testRegistry().push_back({name, std::move(body)});
    }
};

#define TEST(name)                                          \
    static void name();                                     \
    static TestRegistrar name##_registrar(#name, name);     \
    static void name()

#define CHECK(condition)                                                                   \
    do {                                                                                   \
        if (!(condition)) {                                                                \
            throw TestFailure(std::string(__FILE__) + ":" + std::to_string(__LINE__) +     \
                              ": CHECK(" #condition ") failed");                           \
        }                                                                                  \
    } while (false)

#define CHECK_THROWS(expression, ErrorType)                                                \
    do {                                                                                   \
        bool thrown = false;                                                               \
        try {                                                                              \
            expression;                                                                    \
        } catch (const ErrorType&) {                                                       \
            thrown = true;                                                                 \
        }                                                                                  \
        if (!thrown) {                                                                     \
            throw TestFailure(std::string(__FILE__) + ":" + std::to_string(__LINE__) +     \
                              ": " #expression " did not throw " #ErrorType);              \
        }                                                                                  \
    } while (false)
