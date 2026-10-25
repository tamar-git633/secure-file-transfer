// Local test server for the client tests
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <thread>
#include <vector>

#include "Platform.h"

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
            m_accepted = true;
            if (client != INVALID_SOCKET) {
                handler(client);
                closesocket(client);
            }
        });
    }

    ~TestServer()
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!m_accepted && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
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
    std::atomic<bool> m_accepted = false;
    std::thread m_thread;
};
