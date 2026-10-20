#include "Connection.h"

#include <algorithm>

#include <ws2tcpip.h>

#include "Errors.h"

namespace {

constexpr WORD WINSOCK_VERSION_2_2 = MAKEWORD(2, 2);
constexpr size_t MAX_CHUNK = 64 * 1024;

std::string socketError(const std::string& what)
{
    return what + " (error " + std::to_string(WSAGetLastError()) + ")";
}

struct AddressList {
    addrinfo* head = nullptr;
    ~AddressList()
    {
        if (head) {
            freeaddrinfo(head);
        }
    }
};

}

WinsockSession::WinsockSession()
{
    WSADATA data{};
    const int result = WSAStartup(WINSOCK_VERSION_2_2, &data);
    if (result != 0) {
        throw NetworkError("WSAStartup failed (error " + std::to_string(result) + ")");
    }
}

WinsockSession::~WinsockSession()
{
    WSACleanup();
}

// Resolves the host and connects to the first address that answers
Connection::Connection(const std::string& host, uint16_t port, int timeoutMs)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    AddressList addresses;
    const std::string portText = std::to_string(port);
    if (getaddrinfo(host.c_str(), portText.c_str(), &hints, &addresses.head) != 0) {
        throw NetworkError(socketError("Cannot resolve server address " + host));
    }

    for (const addrinfo* address = addresses.head; address != nullptr; address = address->ai_next) {
        m_socket = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (m_socket == INVALID_SOCKET) {
            continue;
        }
        if (connect(m_socket, address->ai_addr, static_cast<int>(address->ai_addrlen)) == 0) {
            break;
        }
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    if (m_socket == INVALID_SOCKET) {
        throw NetworkError(socketError("Cannot connect to " + host + ":" + portText));
    }

    const DWORD timeout = static_cast<DWORD>(timeoutMs);
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
}

Connection::~Connection()
{
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
    }
}

// Sends the whole buffer, send() may take only part of it each time
void Connection::sendAll(std::span<const uint8_t> data)
{
    size_t sent = 0;
    while (sent < data.size()) {
        const size_t chunk = std::min(data.size() - sent, MAX_CHUNK);
        const int result = send(m_socket, reinterpret_cast<const char*>(data.data() + sent), static_cast<int>(chunk), 0);
        if (result == SOCKET_ERROR) {
            throw NetworkError(socketError("Sending to the server failed"));
        }
        sent += static_cast<size_t>(result);
    }
}

// Receives exactly size bytes, throws NetworkError if the server
// closes the connection or does not answer in time
std::vector<uint8_t> Connection::recvExact(size_t size)
{
    std::vector<uint8_t> buffer(size);
    size_t received = 0;
    while (received < size) {
        const size_t chunk = std::min(size - received, MAX_CHUNK);
        const int result = recv(m_socket, reinterpret_cast<char*>(buffer.data() + received), static_cast<int>(chunk), 0);
        if (result == 0) {
            throw NetworkError("The server closed the connection");
        }
        if (result == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAETIMEDOUT) {
                throw NetworkError("The server did not answer in time");
            }
            throw NetworkError(socketError("Receiving from the server failed"));
        }
        received += static_cast<size_t>(result);
    }
    return buffer;
}
