#include <filesystem>
#include <fstream>
#include <string>

#include "Base64Wrapper.h"
#include "ClientInfo.h"
#include "Errors.h"
#include "RSAWrapper.h"
#include "TestFramework.h"

namespace fs = std::filesystem;

namespace {

class TempDir {
public:
    TempDir() : m_path(fs::temp_directory_path() / "client_info_test")
    {
        fs::remove_all(m_path);
        fs::create_directories(m_path);
    }
    ~TempDir() { fs::remove_all(m_path); }
    const fs::path& path() const { return m_path; }

private:
    fs::path m_path;
};

void writeText(const fs::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::binary);
    out << text;
}

ClientIdentity sampleIdentity()
{
    ClientIdentity identity;
    identity.name = "Michael Jackson";
    identity.id = ClientInfo::idFromHex("64f3f63985f04beb81a0e43321880182");
    identity.privateKeyDer = RSAPrivateWrapper().privateKeyDer();
    return identity;
}

}

TEST(info_hex_round_trip)
{
    const ClientId id = ClientInfo::idFromHex("64f3f63985f04beb81a0e43321880182");
    CHECK(id[0] == 0x64);
    CHECK(id[15] == 0x82);
    CHECK(ClientInfo::idToHex(id) == "64f3f63985f04beb81a0e43321880182");
    CHECK(ClientInfo::idToHex(ClientInfo::idFromHex("64F3F63985F04BEB81A0E43321880182")) ==
          "64f3f63985f04beb81a0e43321880182");
}

TEST(info_bad_hex)
{
    CHECK_THROWS(ClientInfo::idFromHex("64f3f63985f04beb81a0e4332188018"), ConfigError);
    CHECK_THROWS(ClientInfo::idFromHex("64f3f63985f04beb81a0e433218801822"), ConfigError);
    CHECK_THROWS(ClientInfo::idFromHex("zzf3f63985f04beb81a0e43321880182"), ConfigError);
    CHECK_THROWS(ClientInfo::idFromHex("-4f3f63985f04beb81a0e43321880182"), ConfigError);
    CHECK_THROWS(ClientInfo::idFromHex(""), ConfigError);
}

TEST(info_save_and_load)
{
    TempDir dir;
    ClientInfo info(dir.path());
    CHECK(!info.exists());

    const ClientIdentity saved = sampleIdentity();
    info.save(saved);
    CHECK(info.exists());
    CHECK(fs::exists(dir.path() / "priv.key"));

    const ClientIdentity loaded = info.load();
    CHECK(loaded.name == saved.name);
    CHECK(loaded.id == saved.id);
    CHECK(loaded.privateKeyDer == saved.privateKeyDer);
    RSAPrivateWrapper rsa(loaded.privateKeyDer);
    CHECK(rsa.publicKeyDer().size() == 160);
}

TEST(info_file_format)
{
    TempDir dir;
    ClientInfo info(dir.path());
    const ClientIdentity identity = sampleIdentity();
    info.save(identity);
    std::ifstream in(dir.path() / "me.info");
    std::string name, id, key;
    std::getline(in, name);
    std::getline(in, id);
    std::getline(in, key);
    CHECK(name == "Michael Jackson");
    CHECK(id == "64f3f63985f04beb81a0e43321880182");
    CHECK(Base64Wrapper::decode(key) == identity.privateKeyDer);
}

TEST(info_key_from_me_info_when_priv_key_missing)
{
    TempDir dir;
    ClientInfo info(dir.path());
    const ClientIdentity identity = sampleIdentity();
    info.save(identity);
    fs::remove(dir.path() / "priv.key");
    CHECK(info.load().privateKeyDer == identity.privateKeyDer);
}

TEST(info_windows_line_endings)
{
    TempDir dir;
    const ClientIdentity identity = sampleIdentity();
    writeText(dir.path() / "me.info", "Michael Jackson\r\n64f3f63985f04beb81a0e43321880182\r\n" +
                                          Base64Wrapper::encode(identity.privateKeyDer) + "\r\n");
    const ClientIdentity loaded = ClientInfo(dir.path()).load();
    CHECK(loaded.name == "Michael Jackson");
    CHECK(loaded.privateKeyDer == identity.privateKeyDer);
}

TEST(info_broken_files)
{
    TempDir dir;
    ClientInfo info(dir.path());
    CHECK_THROWS(info.load(), ConfigError);

    writeText(dir.path() / "me.info", "only a name\n");
    CHECK_THROWS(info.load(), ConfigError);

    writeText(dir.path() / "me.info", "\n64f3f63985f04beb81a0e43321880182\nAAAA\n");
    CHECK_THROWS(info.load(), ConfigError);

    writeText(dir.path() / "me.info", "bob\nnot-an-id\nAAAA\n");
    CHECK_THROWS(info.load(), ConfigError);

    writeText(dir.path() / "me.info", "bob\n64f3f63985f04beb81a0e43321880182\n");
    CHECK_THROWS(info.load(), ConfigError);

    writeText(dir.path() / "me.info", "bob\n64f3f63985f04beb81a0e43321880182\n$$$\n");
    CHECK_THROWS(info.load(), CryptoError);

    writeText(dir.path() / "me.info", std::string(100000, 'a'));
    CHECK_THROWS(info.load(), ConfigError);
}

TEST(info_save_rejects_bad_name)
{
    TempDir dir;
    ClientIdentity identity = sampleIdentity();
    identity.name = "";
    CHECK_THROWS(ClientInfo(dir.path()).save(identity), ConfigError);
    CHECK(!fs::exists(dir.path() / "me.info"));
}

TEST(info_utf8_bom_in_files)
{
    TempDir dir;
    const ClientIdentity identity = sampleIdentity();
    const std::string key = Base64Wrapper::encode(identity.privateKeyDer);
    writeText(dir.path() / "me.info", "\xEF\xBB\xBFMichael Jackson\n64f3f63985f04beb81a0e43321880182\n" + key + "\n");
    writeText(dir.path() / "priv.key", "\xEF\xBB\xBF" + key + "\n");
    const ClientIdentity loaded = ClientInfo(dir.path()).load();
    CHECK(loaded.name == "Michael Jackson");
    CHECK(loaded.privateKeyDer == identity.privateKeyDer);
}
