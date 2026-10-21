#include "FileTransferClient.h"

#include <algorithm>
#include <iostream>

#include "Errors.h"
#include "FileSender.h"

FileTransferClient::FileTransferClient(const std::filesystem::path& workDir)
    : m_config(Config::load(workDir / constants::TRANSFER_FILE)), m_info(workDir)
{
}

bool FileTransferClient::run()
{
    connectAndGetKey();
    return sendFiles();
}

void FileTransferClient::connectAndGetKey()
{
    std::cout << "Connecting to " << m_config.host() << ":" << m_config.port() << std::endl;
    m_connection = std::make_unique<Connection>(m_config.host(), m_config.port());
    if (m_info.exists() && reconnect()) {
        return;
    }
    registerNew();
    sendPublicKey();
}

// Sends every file from transfer.json. Returns true only if all of them
// were sent and verified.
bool FileTransferClient::sendFiles()
{
    int verified = 0;
    int failed = 0;
    int skipped = 0;
    for (const auto& path : m_config.files()) {
        if (!std::filesystem::is_regular_file(path)) {
            std::cout << "Skipping " << path.string() << ": file not found" << std::endl;
            ++skipped;
        } else if (sendOneFile(path)) {
            ++verified;
        } else {
            ++failed;
        }
    }
    std::cout << "Done: " << verified << " verified, " << failed << " failed, " << skipped << " skipped" << std::endl;
    return failed == 0 && skipped == 0;
}

// Sends a file and compares the CRC. On a mismatch the client sends 901
// and the file again, after the fourth mismatch it gives up with 902.
bool FileTransferClient::sendOneFile(const std::filesystem::path& path)
{
    const std::string fileName = FileSender::protocolFileName(path);
    const auto namePayload = Protocol::namePayload(fileName);
    std::cout << "Sending " << path.string() << " (" << std::filesystem::file_size(path) << " bytes)" << std::endl;

    for (int sendCount = 1;; ++sendCount) {
        const UploadResult result = uploadFile(path);
        if (result.serverCksum == result.ourCksum) {
            std::cout << "CRC OK (" << result.ourCksum << "), sending confirmation" << std::endl;
            exchange(RequestCode::CrcOk, namePayload, {ResponseCode::Ack});
            std::cout << "Server confirmed '" << fileName << "'" << std::endl;
            return true;
        }
        std::cout << "CRC mismatch: server " << result.serverCksum << ", ours " << result.ourCksum << std::endl;
        if (sendCount > constants::MAX_CRC_RESENDS) {
            exchange(RequestCode::CrcAbort, namePayload, {ResponseCode::Ack});
            std::cout << "CRC failed " << sendCount << " times, giving up on '" << fileName << "'" << std::endl;
            return false;
        }
        m_connection->sendAll(Protocol::request(m_identity.id, RequestCode::CrcRetry, namePayload));
        std::cout << "Sending the file again (" << sendCount << "/" << constants::MAX_CRC_RESENDS << ")" << std::endl;
    }
}

// Sends the file packets and reads the 1603 answer. If the server answers
// with an error the file is sent again, up to 3 times.
FileTransferClient::UploadResult FileTransferClient::uploadFile(const std::filesystem::path& path)
{
    for (int attempt = 1; attempt <= constants::MAX_ATTEMPTS; ++attempt) {
        FileSender sender(*m_connection, m_identity.id, m_aesKey);
        const SentFile sent = sender.send(path);
        const Response response = Protocol::readResponse(*m_connection);
        if (response.code == static_cast<uint16_t>(ResponseCode::FileReceived)) {
            const FileReceivedPayload received = Protocol::parseFileReceived(response.payload);
            checkClientId(received.clientId);
            if (received.fileName != sent.fileName || received.contentSize != sent.contentSize) {
                throw ProtocolError("Server confirmed a different file");
            }
            std::cout << "Server got '" << received.fileName << "', " << received.contentSize << " bytes" << std::endl;
            return {received.cksum, sent.cksum};
        }
        std::cout << "server responded with an error" << std::endl;
        if (attempt < constants::MAX_ATTEMPTS) {
            std::cout << "Trying again (" << attempt + 1 << "/" << constants::MAX_ATTEMPTS << ")" << std::endl;
        }
    }
    throw ServerError("Sending file " + path.filename().string() + " failed " +
                      std::to_string(constants::MAX_ATTEMPTS) + " times");
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
