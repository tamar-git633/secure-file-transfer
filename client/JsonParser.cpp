#include "JsonParser.h"

#include <charconv>
#include <cctype>

#include "Errors.h"

namespace {

constexpr int MAX_DEPTH = 32;
constexpr unsigned int HEX_DIGITS = 4;
constexpr unsigned int HEX_BASE = 16;
constexpr unsigned int FIRST_PRINTABLE = 0x20;
constexpr unsigned int MAX_ONE_BYTE = 0x7F;
constexpr unsigned int MAX_TWO_BYTES = 0x7FF;
constexpr unsigned int UTF8_TWO_BYTE_LEAD = 0xC0;
constexpr unsigned int UTF8_THREE_BYTE_LEAD = 0xE0;
constexpr unsigned int UTF8_CONTINUATION = 0x80;
constexpr unsigned int UTF8_SIX_BITS = 0x3F;
constexpr unsigned int UTF8_SHIFT = 6;
constexpr unsigned int SURROGATE_FIRST = 0xD800;
constexpr unsigned int SURROGATE_LAST = 0xDFFF;

}

double JsonValue::asNumber(std::string_view what) const
{
    if (!isNumber()) {
        throw ConfigError(std::string(what) + " must be a number");
    }
    return std::get<double>(m_value);
}

const std::string& JsonValue::asString(std::string_view what) const
{
    if (!isString()) {
        throw ConfigError(std::string(what) + " must be a string");
    }
    return std::get<std::string>(m_value);
}

const JsonValue::Array& JsonValue::asArray(std::string_view what) const
{
    if (!isArray()) {
        throw ConfigError(std::string(what) + " must be a list");
    }
    return std::get<Array>(m_value);
}

const JsonValue::Object& JsonValue::asObject(std::string_view what) const
{
    if (!isObject()) {
        throw ConfigError(std::string(what) + " must be an object");
    }
    return std::get<Object>(m_value);
}

const JsonValue& JsonValue::at(const std::string& key) const
{
    const auto& object = asObject("value");
    const auto it = object.find(key);
    if (it == object.end()) {
        throw ConfigError("Missing field '" + key + "'");
    }
    return it->second;
}

JsonValue JsonParser::parse(std::string_view text)
{
    JsonParser parser(text);
    JsonValue value = parser.parseValue(0);
    parser.skipWhitespace();
    if (parser.m_pos != text.size()) {
        parser.fail("Unexpected data after the end");
    }
    return value;
}

JsonValue JsonParser::parseValue(int depth)
{
    if (depth > MAX_DEPTH) {
        fail("Nesting is too deep");
    }
    skipWhitespace();
    const char c = peek();
    if (c == '{') {
        return parseObject(depth);
    }
    if (c == '[') {
        return parseArray(depth);
    }
    if (c == '"') {
        return JsonValue(parseString());
    }
    if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
        return parseNumber();
    }
    return parseLiteral();
}

JsonValue JsonParser::parseObject(int depth)
{
    expect('{');
    JsonValue::Object object;
    skipWhitespace();
    if (peek() == '}') {
        next();
        return JsonValue(std::move(object));
    }
    while (true) {
        skipWhitespace();
        std::string key = parseString();
        if (object.contains(key)) {
            fail("Duplicate key '" + key + "'");
        }
        skipWhitespace();
        expect(':');
        object.emplace(std::move(key), parseValue(depth + 1));
        skipWhitespace();
        if (peek() == ',') {
            next();
            continue;
        }
        expect('}');
        return JsonValue(std::move(object));
    }
}

JsonValue JsonParser::parseArray(int depth)
{
    expect('[');
    JsonValue::Array array;
    skipWhitespace();
    if (peek() == ']') {
        next();
        return JsonValue(std::move(array));
    }
    while (true) {
        array.push_back(parseValue(depth + 1));
        skipWhitespace();
        if (peek() == ',') {
            next();
            continue;
        }
        expect(']');
        return JsonValue(std::move(array));
    }
}

// Reads a quoted string and handles the escape sequences.
// Windows paths are often written with a single backslash (like the example
// in the assignment), so an unknown escape such as \d is kept as it is.
std::string JsonParser::parseString()
{
    expect('"');
    std::string result;
    while (true) {
        const char c = next();
        if (c == '"') {
            return result;
        }
        if (static_cast<unsigned char>(c) < FIRST_PRINTABLE) {
            fail("Control character inside a string");
        }
        if (c != '\\') {
            result += c;
            continue;
        }
        const char escape = next();
        switch (escape) {
        case '"': result += '"'; break;
        case '\\': result += '\\'; break;
        case '/': result += '/'; break;
        case 'b': result += '\b'; break;
        case 'f': result += '\f'; break;
        case 'n': result += '\n'; break;
        case 'r': result += '\r'; break;
        case 't': result += '\t'; break;
        case 'u':
            if (hasHex4()) {
                appendUtf8(result, parseHex4());
            } else {
                result += "\\u";
            }
            break;
        default:
            result += '\\';
            result += escape;
        }
    }
}

JsonValue JsonParser::parseNumber()
{
    const size_t start = m_pos;
    if (peek() == '-') {
        next();
    }
    while (m_pos < m_text.size() && (std::isdigit(static_cast<unsigned char>(m_text[m_pos])) ||
                                     m_text[m_pos] == '.' || m_text[m_pos] == 'e' || m_text[m_pos] == 'E' ||
                                     m_text[m_pos] == '+' || m_text[m_pos] == '-')) {
        ++m_pos;
    }
    double value = 0;
    const auto [end, error] = std::from_chars(m_text.data() + start, m_text.data() + m_pos, value);
    if (error != std::errc() || end != m_text.data() + m_pos) {
        m_pos = start;
        fail("Invalid number");
    }
    return JsonValue(value);
}

JsonValue JsonParser::parseLiteral()
{
    const auto rest = m_text.substr(m_pos);
    if (rest.starts_with("true")) {
        m_pos += std::string_view("true").size();
        return JsonValue(true);
    }
    if (rest.starts_with("false")) {
        m_pos += std::string_view("false").size();
        return JsonValue(false);
    }
    if (rest.starts_with("null")) {
        m_pos += std::string_view("null").size();
        return JsonValue();
    }
    fail("Unexpected character");
}

bool JsonParser::hasHex4() const
{
    if (m_text.size() - m_pos < HEX_DIGITS) {
        return false;
    }
    for (size_t i = 0; i < HEX_DIGITS; ++i) {
        if (!std::isxdigit(static_cast<unsigned char>(m_text[m_pos + i]))) {
            return false;
        }
    }
    return true;
}

unsigned int JsonParser::parseHex4()
{
    unsigned int value = 0;
    for (unsigned int i = 0; i < HEX_DIGITS; ++i) {
        const char c = next();
        unsigned int digit = 0;
        const auto [end, error] = std::from_chars(&c, &c + 1, digit, HEX_BASE);
        if (error != std::errc()) {
            fail("Invalid \\u escape");
        }
        value = value * HEX_BASE + digit;
    }
    if (value >= SURROGATE_FIRST && value <= SURROGATE_LAST) {
        fail("Unsupported \\u escape");
    }
    return value;
}

void JsonParser::appendUtf8(std::string& out, unsigned int codePoint)
{
    if (codePoint <= MAX_ONE_BYTE) {
        out += static_cast<char>(codePoint);
    } else if (codePoint <= MAX_TWO_BYTES) {
        out += static_cast<char>(UTF8_TWO_BYTE_LEAD | (codePoint >> UTF8_SHIFT));
        out += static_cast<char>(UTF8_CONTINUATION | (codePoint & UTF8_SIX_BITS));
    } else {
        out += static_cast<char>(UTF8_THREE_BYTE_LEAD | (codePoint >> (2 * UTF8_SHIFT)));
        out += static_cast<char>(UTF8_CONTINUATION | ((codePoint >> UTF8_SHIFT) & UTF8_SIX_BITS));
        out += static_cast<char>(UTF8_CONTINUATION | (codePoint & UTF8_SIX_BITS));
    }
}

void JsonParser::skipWhitespace()
{
    while (m_pos < m_text.size() && (m_text[m_pos] == ' ' || m_text[m_pos] == '\t' ||
                                     m_text[m_pos] == '\n' || m_text[m_pos] == '\r')) {
        ++m_pos;
    }
}

char JsonParser::peek() const
{
    if (m_pos >= m_text.size()) {
        fail("Unexpected end of file");
    }
    return m_text[m_pos];
}

char JsonParser::next()
{
    const char c = peek();
    ++m_pos;
    return c;
}

void JsonParser::expect(char expected)
{
    if (peek() != expected) {
        fail(std::string("Expected '") + expected + "'");
    }
    ++m_pos;
}

void JsonParser::fail(const std::string& message) const
{
    size_t line = 1;
    for (size_t i = 0; i < m_pos && i < m_text.size(); ++i) {
        if (m_text[i] == '\n') {
            ++line;
        }
    }
    throw ConfigError("JSON error at line " + std::to_string(line) + ": " + message);
}
