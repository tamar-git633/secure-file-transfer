#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "Platform.h"

#include "Constants.h"

// Starts Winsock in the constructor and cleans it up in the destructor
class WinsockSession {
public:
    WinsockSession();
    ~WinsockSession();
    WinsockSession(const WinsockSession&) = delete;
    WinsockSession& operator=(const WinsockSession&) = delete;
};

// A TCP connection to the server. The socket is closed automatically
// when the object is destroyed.
class Connection {
public:
    Connection(const std::string& host, uint16_t port, int timeoutMs = constants::SOCKET_TIMEOUT_MS);
    ~Connection();
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    void sendAll(std::span<const uint8_t> data);
    std::vector<uint8_t> recvExact(size_t size);

private:
    WinsockSession m_winsock;
    SOCKET m_socket = INVALID_SOCKET;
};
