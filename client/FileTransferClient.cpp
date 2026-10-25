#include "FileTransferClient.h"

#include <algorithm>
#include <iostream>

#include "Errors.h"
#include "FileSender.h"
#include "TextUtils.h"

FileTransferClient::FileTransferClient(const std::filesystem::path& workDir)
    : m_config(Config::load(workDir / constants::TRANSFER_FILE)), m_info(workDir)
{
}

bool FileTransferClient::run()
{
    connectAndGetKey();
    return sendFiles();
}

// me.info is read before connecting, so a broken file is reported
// right away even when the server is down
void FileTransferClient::connectAndGetKey()
{
    const bool registeredBefore = m_info.exists();
    if (registeredBefore) {
        try {
            m_identity = m_info.load();
            m_rsa = std::make_unique<RSAPrivateWrapper>(m_identity.privateKeyDer);
        } catch (const ClientError& e) {
            throw ConfigError(std::string(e.what()) + ". Delete me.info and priv.key to register again");
        }
        std::cout << "Found " << constants::ME_FILE << std::endl;
    }
    std::cout << "Connecting to " << m_config.host() << ":" << m_config.port() << std::endl;
    m_connection = std::make_unique<Connection>(m_config.host(), m_config.port());
    if (registeredBefore && reconnect()) {
        return;
    }
    registerNew();
    sendPublicKey();
}

// Sends every file from transfer.json. A file that cannot be sent (missing,
// locked, bad name) is skipped. Returns true only if all files were verified.
bool FileTransferClient::sendFiles()
{
    int verified = 0;
    int failed = 0;
    int skipped = 0;
    for (const auto& path : m_config.files()) {
        if (std::filesystem::is_directory(path)) {
            std::cout << "Skipping " << text::pathToUtf8(path) << ": this is a folder, not a file" << std::endl;
            ++skipped;
            continue;
        }
        if (!std::filesystem::is_regular_file(path)) {
            std::cout << "Skipping " << text::pathToUtf8(path) << ": file not found" << std::endl;
            ++skipped;
            continue;
        }
        try {
            if (sendOneFile(path)) {
                ++verified;
            } else {
                ++failed;
            }
        } catch (const FileError& e) {
            std::cout << "Skipping " << text::pathToUtf8(path) << ": " << e.what() << std::endl;
            ++skipped;
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
    std::error_code sizeError;
    const auto size = std::filesystem::file_size(path, sizeError);
    std::cout << "Sending " << text::pathToUtf8(path);
    if (!sizeError) {
        std::cout << " (" << size << " bytes)";
    }
    std::cout << std::endl;

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
        try {
            m_connection->sendAll(Protocol::request(m_identity.id, RequestCode::CrcRetry, namePayload));
        } catch (const NetworkError&) {
            reopenConnection();
        }
        std::cout << "Sending the file again (" << sendCount << "/" << constants::MAX_CRC_RESENDS << ")" << std::endl;
    }
}

// Sends the file packets and reads the 1603 answer. On a server error, a
// broken answer or a lost connection the file is sent again, up to 3 times.
FileTransferClient::UploadResult FileTransferClient::uploadFile(const std::filesystem::path& path)
{
    std::string lastProblem;
    for (int attempt = 0; attempt <= constants::MAX_RETRIES; ++attempt) {
        if (attempt > 0) {
            std::cout << "Trying again (" << attempt << "/" << constants::MAX_RETRIES << ")" << std::endl;
        }
        try {
            FileSender sender(*m_connection, m_identity.id, m_aesKey);
            const SentFile sent = sender.send(path);
            const Response response = Protocol::readResponse(*m_connection);
            if (response.code == static_cast<uint16_t>(ResponseCode::FileReceived)) {
                const FileReceivedPayload received = Protocol::parseFileReceived(response.payload);
                checkClientId(received.clientId);
                if (received.fileName != sent.fileName || received.contentSize != sent.contentSize) {
                    throw ProtocolError("Server confirmed a different file");
                }
                std::cout << "Server got '" << received.fileName << "', " << received.contentSize << " bytes"
                          << std::endl;
                return {received.cksum, sent.cksum};
            }
            lastProblem = "server answered " + std::to_string(response.code);
            std::cout << "server responded with an error" << std::endl;
        } catch (const NetworkError& e) {
            lastProblem = e.what();
            std::cout << "server responded with an error (" << e.what() << ")" << std::endl;
            if (attempt < constants::MAX_RETRIES) {
                reopenConnection();
            }
        } catch (const ProtocolError& e) {
            lastProblem = e.what();
            std::cout << "server responded with an error (" << e.what() << ")" << std::endl;
            if (attempt < constants::MAX_RETRIES) {
                reopenConnection();
            }
        }
    }
    throw ServerError("Sending file " + text::pathToUtf8(path.filename()) + " failed " +
                      std::to_string(constants::MAX_RETRIES + 1) + " times, last problem: " + lastProblem);
}

// Request 827, used when me.info exists. The saved RSA key is reused.
// Returns false if the server does not know us (1606).
bool FileTransferClient::reconnect()
{
    std::cout << "Reconnecting as '" << m_identity.name << "' (ID " << ClientInfo::idToHex(m_identity.id) << ")"
              << std::endl;

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

// Opens a new connection after the old one broke. If the keys were already
// exchanged, the session is restored with a reconnect (827) and a new AES key.
void FileTransferClient::reopenConnection()
{
    std::cout << "Opening a new connection to the server" << std::endl;
    m_connection = std::make_unique<Connection>(m_config.host(), m_config.port());
    if (!m_aesKey.empty()) {
        m_aesKey.clear();
        if (!reconnect()) {
            throw ServerError("The server does not know this client anymore");
        }
    }
}

// Sends a request and reads the response. A server error, a broken answer
// or a lost connection counts as an error: the request is sent again,
// up to 3 more times. A broken connection is opened again first.
Response FileTransferClient::exchange(RequestCode code, std::span<const uint8_t> payload,
                                      std::initializer_list<ResponseCode> expected)
{
    const auto message = Protocol::request(m_identity.id, code, payload);
    std::string lastProblem;
    for (int attempt = 0; attempt <= constants::MAX_RETRIES; ++attempt) {
        if (attempt > 0) {
            std::cout << "Trying again (" << attempt << "/" << constants::MAX_RETRIES << ")" << std::endl;
        }
        try {
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
            lastProblem = "server answered " + std::to_string(response.code);
            std::cout << "server responded with an error" << std::endl;
        } catch (const NetworkError& e) {
            lastProblem = e.what();
            std::cout << "server responded with an error (" << e.what() << ")" << std::endl;
            if (attempt < constants::MAX_RETRIES) {
                reopenConnection();
            }
        } catch (const ProtocolError& e) {
            lastProblem = e.what();
            std::cout << "server responded with an error (" << e.what() << ")" << std::endl;
            if (attempt < constants::MAX_RETRIES) {
                reopenConnection();
            }
        }
    }
    throw ServerError("Request " + std::to_string(static_cast<int>(code)) + " failed " +
                      std::to_string(constants::MAX_RETRIES + 1) + " times, last problem: " + lastProblem);
}

void FileTransferClient::checkClientId(const ClientId& id) const
{
    if (id != m_identity.id) {
        throw ProtocolError("Server answered with a different client ID");
    }
}
