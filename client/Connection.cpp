// TCP connection to the server over Winsock
#include "Connection.h"

#include <algorithm>

#include "Errors.h"

namespace {

constexpr WORD WINSOCK_VERSION_2_2 = MAKEWORD(2, 2);
constexpr size_t MAX_CHUNK = 64 * 1024;

std::string socketError(const std::string& what)
{
    const int error = WSAGetLastError();
    if (error == WSAECONNRESET || error == WSAECONNABORTED) {
        return what + ": the server closed the connection";
    }
    if (error == WSAETIMEDOUT) {
        return what + ": the server did not answer in time";
    }
    return what + " (error " + std::to_string(error) + ")";
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

    int lastError = 0;
    for (const addrinfo* address = addresses.head; address != nullptr; address = address->ai_next) {
        m_socket = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (m_socket == INVALID_SOCKET) {
            lastError = WSAGetLastError();
            continue;
        }
        if (connect(m_socket, address->ai_addr, static_cast<int>(address->ai_addrlen)) == 0) {
            break;
        }
        lastError = WSAGetLastError();
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    if (m_socket == INVALID_SOCKET) {
        const std::string reason = lastError == WSAECONNREFUSED ? "the server is not running or the port is wrong"
                                                                : "error " + std::to_string(lastError);
        throw NetworkError("Cannot connect to " + host + ":" + portText + " (" + reason + ")");
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
            throw NetworkError(socketError("Receiving from the server failed"));
        }
        received += static_cast<size_t>(result);
    }
    return buffer;
}
