// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "ConnectionStore.h"
#include "ConnectionTree.h"
#include <cstdio>
#include <fstream>

class ConnectionStoreTest : public testing::Test {
protected:
  std::string path;
  void SetUp() override {
    path = std::string("manager-") + testing::UnitTest::GetInstance()->current_test_info()->name() + ".json";
    std::remove(path.c_str());
  }
  void TearDown() override { std::remove(path.c_str()); }
};

TEST(CredentialVaultTest, AuthenticatedRoundtripAndRandomNonce) {
  Json::Value doc(Json::objectValue);
  for (const std::string password : {std::string(), std::string("unicode-\xD0\xBF\xD0\xB0\xD1\x80\xD0\xBE\xD0\xBB\xD1\x8C"), std::string(4096, 'x')}) {
    auto a = CredentialVault::encrypt(doc, "profile", password);
    auto b = CredentialVault::encrypt(doc, "profile", password);
    EXPECT_EQ(CredentialVault::decrypt(doc, "profile", a), password);
    EXPECT_NE(a["nonce"], b["nonce"]);
    EXPECT_EQ(a["algorithm"], "AES-256-GCM");
    EXPECT_EQ(doc["credentialKey"]["protection"], "DPAPI-CurrentUser");
    EXPECT_THROW(CredentialVault::decrypt(doc, "other-profile", a), std::runtime_error);
    auto damaged = a;
    std::string tag = damaged["tag"].asString(); tag[0] = tag[0] == 'A' ? 'B' : 'A';
    damaged["tag"] = tag;
    EXPECT_THROW(CredentialVault::decrypt(doc, "profile", damaged), std::runtime_error);
  }
}

TEST(CredentialVaultTest, DamagedOrMissingKeyDoesNotRegenerate) {
  Json::Value doc(Json::objectValue);
  auto encrypted = CredentialVault::encrypt(doc, "profile", "secret");
  auto damaged = doc;
  damaged["credentialKey"]["wrappedKey"] = "AAAA";
  EXPECT_THROW(CredentialVault::decrypt(damaged, "profile", encrypted), std::runtime_error);
  EXPECT_THROW(CredentialVault::encrypt(damaged, "profile", "replacement"), std::runtime_error);
  doc.removeMember("credentialKey");
  doc["connections"][0]["password"] = encrypted;
  EXPECT_THROW(CredentialVault::encrypt(doc, "profile", "replacement"), std::runtime_error);
}

TEST_F(ConnectionStoreTest, NestedFoldersAndPortableState) {
  ConnectionStore store(path);
  auto root = store.saveFolder("", "Office", "");
  auto sub = store.saveFolder("", "Macs / laptops", root);
  auto id = store.saveConnection("", "Work Mac", "10.3.1.13", "Administrator", sub,
    ConnectionStore::SetPassword, "unit-test-password");
  store.setExpanded(true);
  auto doc = ConnectionStore(path).read();
  EXPECT_TRUE(doc["manager"]["expanded"].asBool());
  EXPECT_EQ(ConnectionStore::folderPath(doc, sub), "Office / Macs / laptops");
  auto entry = store.connection(id);
  EXPECT_EQ(CredentialVault::decrypt(doc, id, entry["password"]), "unit-test-password");
  std::ifstream input(path); std::string raw((std::istreambuf_iterator<char>(input)), {});
  input.close();
  EXPECT_EQ(raw.find("unit-test-password"), std::string::npos);
  EXPECT_THROW(store.saveFolder(root, "Office", sub), std::runtime_error);
  EXPECT_THROW(store.remove(root, true), std::runtime_error);
  EXPECT_THROW(store.remove(sub, true), std::runtime_error);
  store.remove(id, false); store.remove(sub, true); store.remove(root, true);
  EXPECT_TRUE(store.read()["folders"].empty());
}

TEST_F(ConnectionStoreTest, EditingKeepsUnknownFieldsAndPasswordUntilForgotten) {
  ConnectionStore store(path);
  auto id = store.saveConnection("", "Mac", "localhost:1", "user", "", ConnectionStore::SetPassword, "original");
  auto doc = store.read();
  auto encrypted = doc["connections"][0]["password"];
  doc["viewer"]["ScaleToWindow"] = true;
  doc["connections"][0]["custom"]["asset"] = 42;
  PortableConfig(path).write(doc);
  store.saveConnection(id, "Renamed", "localhost::5901", "new-user", "", ConnectionStore::KeepPassword, "");
  doc = store.read();
  EXPECT_EQ(doc["connections"][0]["custom"]["asset"].asInt(), 42);
  EXPECT_TRUE(doc["viewer"]["ScaleToWindow"].asBool());
  EXPECT_EQ(store.connection(id)["password"], encrypted);
  store.saveConnection(id, "Renamed", "localhost", "new-user", "", ConnectionStore::SetPassword, "new");
  EXPECT_EQ(CredentialVault::decrypt(store.read(), id, store.connection(id)["password"]), "new");
  store.saveConnection(id, "Renamed", "localhost", "new-user", "", ConnectionStore::ForgetPassword, "");
  EXPECT_TRUE(store.connection(id)["password"].isNull());
}

TEST_F(ConnectionStoreTest, InvalidChangesKeepFileUnchanged) {
  ConnectionStore store(path);
  auto id = store.saveFolder("", "Root", "");
  auto original = store.read();
  EXPECT_THROW(store.saveFolder(id, "", ""), std::runtime_error);
  EXPECT_THROW(store.saveFolder(id, "Root", "missing"), std::runtime_error);
  EXPECT_THROW(store.saveConnection("", "\n", "localhost", "", "", ConnectionStore::SetPassword, "x"), std::runtime_error);
  EXPECT_THROW(store.saveConnection("", "Test", "localhost", "", "missing", ConnectionStore::SetPassword, "x"), std::runtime_error);
  EXPECT_EQ(store.read(), original);
}

TEST(ConnectionStoreEndpointTest, CredentialsStayBoundToEndpoint) {
  EXPECT_TRUE(ConnectionStore::sameEndpoint("MAC:1", "mac", 5901));
  EXPECT_TRUE(ConnectionStore::sameEndpoint("mac::5900", "MAC", 5900));
  EXPECT_FALSE(ConnectionStore::sameEndpoint("mac", "other", 5900));
  EXPECT_FALSE(ConnectionStore::sameEndpoint("mac:1", "mac", 5900));
  ConnectionStore::clearActive();
  ConnectionStore::activate("any", "mac");
  ConnectionCredentials result;
  EXPECT_FALSE(ConnectionStore::activeCredentials("other", 5900, result));
  ConnectionStore::clearActive();
}

TEST_F(ConnectionStoreTest, RebuildsVisibleTreeWithFoldersAfterClearAndReload) {
  ConnectionStore store(path);
  auto root = store.saveFolder("", "Office", "");
  auto child = store.saveFolder("", "Nested / literal slash", root);
  auto id = store.saveConnection("", "Computer", "localhost", "test-user", child,
    ConnectionStore::ForgetPassword, "");
  Fl_Tree tree(0, 0, 400, 400);
  std::list<ConnectionTreeEntry> entries;
  for (int iteration = 0; iteration < 30; ++iteration) {
    populateConnectionTree(tree, ConnectionStore(path).read(), entries);
    ASSERT_NE(tree.root(), nullptr);
    ASSERT_EQ(tree.root()->children(), 1);
    auto folder = tree.root()->child(0);
    EXPECT_STREQ(folder->label(), "Office");
    ASSERT_NE(folder->usericon(), nullptr);
    ASSERT_EQ(folder->children(), 1);
    auto nested = folder->child(0);
    EXPECT_STREQ(nested->label(), "Nested / literal slash");
    ASSERT_EQ(nested->children(), 1);
    auto computer = nested->child(0);
    ASSERT_NE(computer->usericon(), nullptr);
    EXPECT_NE(computer->usericon(), folder->usericon());
    EXPECT_EQ(static_cast<ConnectionTreeEntry*>(computer->user_data())->id, id);
    EXPECT_EQ(entries.size(), 3u);
  }
  store.saveFolder(root, "Renamed", "");
  populateConnectionTree(tree, store.read(), entries);
  EXPECT_STREQ(tree.root()->child(0)->label(), "Renamed");
  store.remove(id, false); store.remove(child, true); store.remove(root, true);
  populateConnectionTree(tree, store.read(), entries);
  EXPECT_EQ(tree.root()->children(), 0);
}

TEST_F(ConnectionStoreTest, RejectsOrphanedAndCyclicFoldersOnLoad) {
  ConnectionStore store(path);
  auto root = store.saveFolder("", "Root", "");
  auto child = store.saveFolder("", "Child", root);
  auto doc = store.read();
  doc["folders"][0]["parentId"] = child;
  PortableConfig(path).write(doc);
  EXPECT_THROW(store.read(), std::runtime_error);
  doc["folders"][0]["parentId"] = "missing";
  PortableConfig(path).write(doc);
  EXPECT_THROW(store.read(), std::runtime_error);
}

TEST_F(ConnectionStoreTest, ConnectStubReceivesSelectedAddressUsernameAndPassword) {
  ConnectionStore store(path);
  auto folder = store.saveFolder("", "Office", "");
  auto id = store.saveConnection("", "Computer", "dummy.example:2", "test-user", folder,
    ConnectionStore::SetPassword, "synthetic-password");
  int calls = 0;
  auto connectStub = [&](const std::string& address) {
    ConnectionCredentials credentials;
    bool selected = store.prepareConnection(id, address, credentials);
    ++calls;
    EXPECT_TRUE(selected);
    EXPECT_EQ(address, "dummy.example::5902");
    EXPECT_EQ(credentials.username, "test-user");
    EXPECT_TRUE(credentials.hasPassword);
    EXPECT_EQ(credentials.password, "synthetic-password");
    ConnectionCredentials authentication;
    EXPECT_TRUE(ConnectionStore::activeCredentials("dummy.example", 5902, authentication));
    EXPECT_EQ(authentication.password, credentials.password);
  };
  connectStub("dummy.example::5902");
  EXPECT_EQ(calls, 1);
  ConnectionCredentials credentials;
  EXPECT_FALSE(store.prepareConnection(id, "other.example", credentials));
  EXPECT_TRUE(credentials.password.empty());
  EXPECT_FALSE(ConnectionStore::activeCredentials("dummy.example", 5902, credentials));
  store.prepareConnection(id, "dummy.example:2", credentials);
  ConnectionStore::rejectActivePassword();
  EXPECT_TRUE(ConnectionStore::activeCredentials("dummy.example", 5902, credentials));
  EXPECT_FALSE(credentials.hasPassword);
  EXPECT_TRUE(credentials.password.empty());
  ConnectionStore::clearActive();
}
