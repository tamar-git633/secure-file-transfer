#pragma once

#include <stdexcept>

// Base class for all errors of the client
class ClientError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class ConfigError : public ClientError {
public:
    using ClientError::ClientError;
};

class NetworkError : public ClientError {
public:
    using ClientError::ClientError;
};

class ProtocolError : public ClientError {
public:
    using ClientError::ClientError;
};

class CryptoError : public ClientError {
public:
    using ClientError::ClientError;
};

class ServerError : public ClientError {
public:
    using ClientError::ClientError;
};
