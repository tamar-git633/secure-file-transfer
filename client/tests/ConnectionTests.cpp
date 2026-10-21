#include <chrono>
#include <thread>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Connection.h"
#include "Errors.h"
#include "TestFramework.h"
#include "TestServer.h"

namespace {

std::vector<uint8_t> pattern(size_t size)
{
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((i * 17 + 3) & 0xFF);
    }
    return data;
}

uint16_t unusedPort()
{
    WinsockSession winsock;
    const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    int length = sizeof(address);
    getsockname(s, reinterpret_cast<sockaddr*>(&address), &length);
    closesocket(s);
    return ntohs(address.sin_port);
}

}

TEST(connection_echo_large_buffer)
{
    const auto data = pattern(300000);
    TestServer server([size = data.size()](SOCKET client) { sendRaw(client, recvRaw(client, size)); });
    Connection connection("127.0.0.1", server.port());
    connection.sendAll(data);
    CHECK(connection.recvExact(data.size()) == data);
}

TEST(connection_by_host_name)
{
    TestServer server([](SOCKET client) { sendRaw(client, {1, 2, 3}); });
    Connection connection("localhost", server.port());
    CHECK((connection.recvExact(3) == std::vector<uint8_t>{1, 2, 3}));
}

TEST(connection_recv_zero_bytes)
{
    TestServer server([](SOCKET) {});
    Connection connection("127.0.0.1", server.port());
    CHECK(connection.recvExact(0).empty());
}

TEST(connection_refused)
{
    CHECK_THROWS(Connection("127.0.0.1", unusedPort()), NetworkError);
}

TEST(connection_unknown_host)
{
    CHECK_THROWS(Connection("no-such-host.invalid", 1234), NetworkError);
}

TEST(connection_server_closes_early)
{
    TestServer server([](SOCKET client) { sendRaw(client, {1, 2, 3}); });
    Connection connection("127.0.0.1", server.port());
    CHECK_THROWS(connection.recvExact(10), NetworkError);
}

TEST(connection_timeout)
{
    TestServer server([](SOCKET) { std::this_thread::sleep_for(std::chrono::milliseconds(1500)); });
    Connection connection("127.0.0.1", server.port(), 200);
    const auto start = std::chrono::steady_clock::now();
    CHECK_THROWS(connection.recvExact(1), NetworkError);
    CHECK(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(1200));
}
