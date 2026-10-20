#include "FileTransferClient.h"

#include <algorithm>
#include <iostream>

#include "Errors.h"

FileTransferClient::FileTransferClient(const std::filesystem::path& workDir)
    : m_config(Config::load(workDir / constants::TRANSFER_FILE)), m_info(workDir)
{
}

void FileTransferClient::run()
{
    std::cout << "Connecting to " << m_config.host() << ":" << m_config.port() << std::endl;
    m_connection = std::make_unique<Connection>(m_config.host(), m_config.port());
    if (m_info.exists() && reconnect()) {
        return;
    }
    registerNew();
    sendPublicKey();
}

// Request 827, used when me.info exists. The saved RSA key is reused.
// Returns false if the server does not know us (1606).
bool FileTransferClient::reconnect()
{
    m_identity = m_info.load();
    m_rsa = std::make_unique<RSAPrivateWrapper>(m_identity.privateKeyDer);
    std::cout << "Found " << constants::ME_FILE << ", reconnecting as '" << m_identity.name << "' (ID "
              << ClientInfo::idToHex(m_identity.id) << ")" << std::endl;

    const auto response = exchange(RequestCode::Reconnect, Protocol::namePayload(m_identity.name),
                                   {ResponseCode::ReconnectOk, ResponseCode::ReconnectDenied});
    if (response.code == static_cast<uint16_t>(ResponseCode::ReconnectDenied)) {
        std::cout << "Reconnect rejected by the server, registering as a new client" << std::endl;
        return false;
    }
    takeAesKey(response);
    return true;
}

// Request 825. The server returns our new client ID, then a new RSA key
// pair is created and saved to me.info and priv.key.
void FileTransferClient::registerNew()
{
    m_identity = ClientIdentity{};
    m_identity.name = m_config.clientName();
    std::cout << "Registering as '" << m_identity.name << "'" << std::endl;

    const auto response = exchange(RequestCode::Register, Protocol::namePayload(m_identity.name),
                                   {ResponseCode::RegisterOk});
    m_identity.id = Protocol::parseClientId(response.payload);
    std::cout << "Registered, client ID " << ClientInfo::idToHex(m_identity.id) << std::endl;

    m_rsa = std::make_unique<RSAPrivateWrapper>();
    m_identity.privateKeyDer = m_rsa->privateKeyDer();
    m_info.save(m_identity);
    std::cout << "Created RSA key pair, saved " << constants::ME_FILE << " and " << constants::PRIVATE_KEY_FILE
              << std::endl;
}

// Request 826, the answer (1602) has the AES key encrypted with our public key
void FileTransferClient::sendPublicKey()
{
    std::cout << "Sending public key" << std::endl;
    const auto payload = Protocol::publicKeyPayload(m_identity.name, m_rsa->publicKeyDer());
    takeAesKey(exchange(RequestCode::SendPublicKey, payload, {ResponseCode::AesKey}));
}

void FileTransferClient::takeAesKey(const Response& response)
{
    const AesKeyPayload parsed = Protocol::parseAesKey(response.payload);
    checkClientId(parsed.clientId);
    m_aesKey = m_rsa->decrypt(parsed.encryptedKey);
    if (m_aesKey.size() != constants::AES_KEY_SIZE) {
        throw CryptoError("AES key from the server has a wrong size");
    }
    std::cout << "Received AES key from the server" << std::endl;
}

// Sends a request and reads the response. Any other response code is
// treated as a server error: the request is sent again, up to 3 times.
Response FileTransferClient::exchange(RequestCode code, std::span<const uint8_t> payload,
                                      std::initializer_list<ResponseCode> expected)
{
    const auto message = Protocol::request(m_identity.id, code, payload);
    uint16_t lastCode = 0;
    for (int attempt = 1; attempt <= constants::MAX_ATTEMPTS; ++attempt) {
        m_connection->sendAll(message);
        Response response = Protocol::readResponse(*m_connection);
        if (response.version != constants::SERVER_VERSION) {
            std::cout << "Warning: server version is " << static_cast<int>(response.version) << std::endl;
        }
        const bool ok = std::any_of(expected.begin(), expected.end(), [&](ResponseCode accepted) {
            return response.code == static_cast<uint16_t>(accepted);
        });
        if (ok) {
            return response;
        }
        lastCode = response.code;
        std::cout << "server responded with an error" << std::endl;
        if (attempt < constants::MAX_ATTEMPTS) {
            std::cout << "Trying again (" << attempt + 1 << "/" << constants::MAX_ATTEMPTS << ")" << std::endl;
        }
    }
    throw ServerError("Request " + std::to_string(static_cast<int>(code)) + " failed " +
                      std::to_string(constants::MAX_ATTEMPTS) + " times, last server response was " +
                      std::to_string(lastCode));
}

void FileTransferClient::checkClientId(const ClientId& id) const
{
    if (id != m_identity.id) {
        throw ProtocolError("Server answered with a different client ID");
    }
}
