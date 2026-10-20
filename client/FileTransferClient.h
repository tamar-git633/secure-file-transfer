#pragma once

#include <filesystem>
#include <initializer_list>
#include <memory>
#include <span>
#include <vector>

#include "ClientInfo.h"
#include "Config.h"
#include "Connection.h"
#include "Protocol.h"
#include "RSAWrapper.h"

// Runs the whole client flow: connects to the server, registers or
// reconnects, gets the AES key and sends the files from transfer.json
class FileTransferClient {
public:
    explicit FileTransferClient(const std::filesystem::path& workDir);
    void run();

private:
    void registerNew();
    void sendPublicKey();
    bool reconnect();
    void takeAesKey(const Response& response);

    Response exchange(RequestCode code, std::span<const uint8_t> payload, std::initializer_list<ResponseCode> expected);
    void checkClientId(const ClientId& id) const;

    Config m_config;
    ClientInfo m_info;
    std::unique_ptr<Connection> m_connection;
    ClientIdentity m_identity;
    std::unique_ptr<RSAPrivateWrapper> m_rsa;
    std::vector<uint8_t> m_aesKey;
};
