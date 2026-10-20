#pragma once

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// A parsed JSON value: null, bool, number, string, array or object
class JsonValue {
public:
    using Array = std::vector<JsonValue>;
    using Object = std::map<std::string, JsonValue>;

    JsonValue() = default;
    explicit JsonValue(bool value) : m_value(value) {}
    explicit JsonValue(double value) : m_value(value) {}
    explicit JsonValue(std::string value) : m_value(std::move(value)) {}
    explicit JsonValue(Array value) : m_value(std::move(value)) {}
    explicit JsonValue(Object value) : m_value(std::move(value)) {}

    bool isNumber() const { return std::holds_alternative<double>(m_value); }
    bool isString() const { return std::holds_alternative<std::string>(m_value); }
    bool isArray() const { return std::holds_alternative<Array>(m_value); }
    bool isObject() const { return std::holds_alternative<Object>(m_value); }

    double asNumber(std::string_view what) const;
    const std::string& asString(std::string_view what) const;
    const Array& asArray(std::string_view what) const;
    const Object& asObject(std::string_view what) const;

    const JsonValue& at(const std::string& key) const;

private:
    std::variant<std::monostate, bool, double, std::string, Array, Object> m_value;
};

// Minimal JSON parser, enough for transfer.json.
// Throws ConfigError with the position of the problem on invalid input.
class JsonParser {
public:
    static JsonValue parse(std::string_view text);

private:
    explicit JsonParser(std::string_view text) : m_text(text) {}

    JsonValue parseValue(int depth);
    JsonValue parseObject(int depth);
    JsonValue parseArray(int depth);
    std::string parseString();
    JsonValue parseNumber();
    JsonValue parseLiteral();
    unsigned int parseHex4();
    void appendUtf8(std::string& out, unsigned int codePoint);

    void skipWhitespace();
    char peek() const;
    char next();
    void expect(char expected);
    [[noreturn]] void fail(const std::string& message) const;

    std::string_view m_text;
    size_t m_pos = 0;
};
