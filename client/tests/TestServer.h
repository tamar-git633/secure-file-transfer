#pragma once

#include <cstdint>
#include <functional>
#include <thread>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Connection.h"

inline void sendRaw(SOCKET s, const std::vector<uint8_t>& data)
{
    size_t sent = 0;
    while (sent < data.size()) {
        const int n = send(s, reinterpret_cast<const char*>(data.data() + sent), static_cast<int>(data.size() - sent), 0);
        if (n <= 0) {
            return;
        }
        sent += static_cast<size_t>(n);
    }
}

inline std::vector<uint8_t> recvRaw(SOCKET s, size_t size)
{
    std::vector<uint8_t> data(size);
    size_t got = 0;
    while (got < size) {
        const int n = recv(s, reinterpret_cast<char*>(data.data() + got), static_cast<int>(size - got), 0);
        if (n <= 0) {
            data.resize(got);
            return data;
        }
        got += static_cast<size_t>(n);
    }
    return data;
}

// Listens on a free local port and runs the handler on the first client
class TestServer {
public:
    explicit TestServer(std::function<void(SOCKET)> handler)
    {
        m_listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        bind(m_listener, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        listen(m_listener, 1);
        int length = sizeof(address);
        getsockname(m_listener, reinterpret_cast<sockaddr*>(&address), &length);
        m_port = ntohs(address.sin_port);
        m_thread = std::thread([this, handler] {
            const SOCKET client = accept(m_listener, nullptr, nullptr);
            if (client != INVALID_SOCKET) {
                handler(client);
                closesocket(client);
            }
        });
    }

    ~TestServer()
    {
        closesocket(m_listener);
        m_thread.join();
    }

    TestServer(const TestServer&) = delete;
    TestServer& operator=(const TestServer&) = delete;

    uint16_t port() const { return m_port; }

private:
    WinsockSession m_winsock;
    SOCKET m_listener = INVALID_SOCKET;
    uint16_t m_port = 0;
    std::thread m_thread;
};
