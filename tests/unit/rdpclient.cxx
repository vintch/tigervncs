// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "RdpClient.h"
#include "ConnectionProtocol.h"
#include "RdpDefaults.h"
#include <core/string.h>
#include <windows.h>
#include <wincrypt.h>
#include <wincred.h>
#include <fstream>
#include <thread>
#include <cstdio>
namespace {
bool finished(const std::shared_ptr<rdpClient::Job>& job) {
  auto end=GetTickCount64()+4000;
  while(!job->done.load() && GetTickCount64()<end) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  return job->done.load();
}
}
TEST(RdpClient, ParsesNativeRdpPortsAndRejectsPropertyInjection) {
  EXPECT_EQ(connectionProtocol::rdpEndpoint("host").port,3389u);
  EXPECT_EQ(connectionProtocol::rdpEndpoint("host:22").port,22u);
  EXPECT_EQ(connectionProtocol::rdpEndpoint("[2001:db8::1]:3390").host,"2001:db8::1");
  EXPECT_TRUE(connectionProtocol::sameRdpEndpoint("HOST","host:3389"));
  for(auto value:{"", "host:0", "host:65536", "host:", "host:abc", "host\r\nusername:s:someone", "http://host", "host /admin", "[::1", "user@host"})
    EXPECT_THROW(connectionProtocol::rdpEndpoint(value),std::runtime_error) << value;
}
TEST(RdpClient, NativeLaunchArgumentsNeedNoConnectionFileOrPassword) {
  rdpClient::Settings settings; settings.address="host:3390"; settings.username="DOMAIN\\user";
  settings.password="synthetic-password"; settings.hasPassword=true;
  EXPECT_EQ(rdpClient::arguments(settings),"/v:host:3390 /w:1024 /h:600");
  EXPECT_EQ(rdpClient::arguments(settings).find(settings.password),std::string::npos);
  EXPECT_EQ(rdpClient::arguments(settings).find(settings.username),std::string::npos);
  settings.address="host /admin"; EXPECT_THROW(rdpClient::arguments(settings),std::runtime_error);
}
TEST(RdpClient, ConfigurableStartingDimensionsArePassedToMstsc) {
  int oldWidth=rdpClient::windowWidth,oldHeight=rdpClient::windowHeight;
  rdpClient::windowWidth.setParam(1600); rdpClient::windowHeight.setParam(900);
  rdpClient::Settings settings; settings.address="host";
  EXPECT_EQ(rdpClient::arguments(settings),"/v:host /w:1600 /h:900");
  rdpClient::windowWidth.setParam(oldWidth); rdpClient::windowHeight.setParam(oldHeight);
}
TEST(RdpClient, SavedProtocolAndPasswordStayBoundToTheirEndpoint) {
  const char* path="rdp-store-test.json"; std::remove(path); ConnectionStore store(path);
  auto id=store.saveConnection("","PC","HOST:3390","user","",ConnectionStore::SetPassword,"secret",
    "user-session",{}, {},ConnectionStore::KeepPassword,"","rdp");
  auto settings=rdpClient::savedSettings(store.read(),id,"host:3390");
  EXPECT_EQ(settings.password,"secret"); EXPECT_EQ(settings.username,"user"); EXPECT_TRUE(settings.hasPassword);
  EXPECT_FALSE(rdpClient::savedSettings(store.read(),id,"other:3390").hasPassword);
  EXPECT_FALSE(rdpClient::savedSettings(store.read(),id,"host:3389").hasPassword);
  ConnectionCredentials vnc; EXPECT_FALSE(store.prepareConnection(id,"HOST:3390",vnc));
  auto original=store.read();
  EXPECT_THROW(store.saveConnection(id,"PC","host","user","",ConnectionStore::KeepPassword,"","",{}, {},ConnectionStore::KeepPassword,"","invalid"),std::runtime_error);
  EXPECT_EQ(original,store.read());
  store.saveConnection(id,"Edited","HOST:3390","user","",ConnectionStore::KeepPassword,"");
  EXPECT_EQ(store.connection(id)["connectionType"],"rdp");
  EXPECT_EQ(store.connection(id)["password"],original["connections"][0]["password"]);
  original["connections"][0].removeMember("connectionType"); PortableConfig(path).write(original);
  EXPECT_EQ(connectionProtocol::type(store.connection(id)),"vnc");
  EXPECT_FALSE(rdpClient::savedSettings(store.read(),id,"host:3390").hasPassword); std::remove(path);
}
TEST(RdpClient, WatchesTheClientLifetimeAndRemovesTemporaryCredential) {
  wchar_t executable[32768]; ASSERT_GT(GetModuleFileNameW(nullptr,executable,32768),0u);
  rdpClient::Settings settings; settings.address=CredentialVault::newId()+".invalid"; settings.username="stub-user";
  settings.password="synthetic-stub-password"; settings.hasPassword=true;
  auto job=rdpClient::startForTest(settings,executable);
  EXPECT_FALSE(job->done.load()); ASSERT_TRUE(finished(job));
  EXPECT_TRUE(job->launched); EXPECT_TRUE(job->error.empty())<<job->error; EXPECT_EQ(job->exitCode,0u);
  PCREDENTIALW credential=nullptr;
  auto target=core::utf8ToUTF16(("TERMSRV/"+settings.address).c_str());
  EXPECT_FALSE(CredReadW(target.c_str(),CRED_TYPE_GENERIC,0,&credential));
  if(credential) { CredFree(credential); CredDeleteW(target.c_str(),CRED_TYPE_GENERIC,0); }
}
TEST(RdpClient, PreviousWindowsCredentialIsRestoredAfterClientExit) {
  wchar_t executable[32768]; ASSERT_GT(GetModuleFileNameW(nullptr,executable,32768),0u);
  rdpClient::Settings settings; settings.address=CredentialVault::newId()+".invalid"; settings.username="stub-user";
  settings.password="synthetic-stub-password"; settings.hasPassword=true;
  auto target=core::utf8ToUTF16(("TERMSRV/"+settings.address).c_str());
  std::wstring previousPassword=L"previous-password";
  CREDENTIALW previous{}; previous.Type=CRED_TYPE_GENERIC; previous.TargetName=&target[0];
  previous.UserName=const_cast<wchar_t*>(L"previous-user"); previous.Persist=CRED_PERSIST_SESSION;
  previous.CredentialBlobSize=DWORD(previousPassword.size()*sizeof(wchar_t)); previous.CredentialBlob=reinterpret_cast<BYTE*>(&previousPassword[0]);
  ASSERT_TRUE(CredWriteW(&previous,0));
  auto job=rdpClient::startForTest(settings,executable); EXPECT_TRUE(finished(job)); EXPECT_EQ(job->exitCode,0u);
  PCREDENTIALW restored=nullptr; EXPECT_TRUE(CredReadW(target.c_str(),CRED_TYPE_GENERIC,0,&restored));
  if(restored) {
    EXPECT_STREQ(restored->UserName,L"previous-user");
    EXPECT_EQ(restored->CredentialBlobSize,previous.CredentialBlobSize);
    EXPECT_EQ(memcmp(restored->CredentialBlob,previous.CredentialBlob,previous.CredentialBlobSize),0);
    CredFree(restored);
  }
  CredDeleteW(target.c_str(),CRED_TYPE_GENERIC,0);
}
TEST(RdpClient, FailedLaunchCompletes) {
  rdpClient::Settings settings; settings.address="host";
  auto job=rdpClient::startForTest(settings,L"C:\\no-such-rdp-client.exe");
  ASSERT_TRUE(finished(job)); EXPECT_FALSE(job->launched); EXPECT_FALSE(job->error.empty());
}
TEST(RdpClient, NativeDefaultFlagsRestoreExactlyForUtf8AndUtf16) {
  std::string path="rdp-default-flags-test.rdp";
  auto encoded=[](const std::string& text,bool unicode) {
    if(!unicode) return text;
    auto wide=core::utf8ToUTF16(text.c_str()); wide.insert(wide.begin(),wchar_t(0xfeff));
    return std::string(reinterpret_cast<const char*>(wide.data()),wide.size()*sizeof(wchar_t));
  };
  auto read=[&]() { std::ifstream file(path,std::ios::binary); return std::string((std::istreambuf_iterator<char>(file)),{}); };
  const std::string original="full address:s:unrelated.example\r\nprompt for credentials:i:1\r\nauthentication level:i:2\r\ncustom:s:keep this\r\n";
  const std::string temporary="full address:s:unrelated.example\r\nprompt for credentials:i:0\r\nauthentication level:i:0\r\ncustom:s:keep this\r\n";
  for(bool unicode:{false,true}) {
    { std::ofstream file(path,std::ios::binary); file<<encoded(original,unicode); }
    { rdpClient::DefaultSettingsLease lease(core::utf8ToUTF16(path.c_str())); EXPECT_EQ(read(),encoded(temporary,unicode)); }
    EXPECT_EQ(read(),encoded(original,unicode));
  }
  std::remove(path.c_str());
}
TEST(RdpClient, NativeDefaultRestorationPreservesUnrelatedEdits) {
  const char* path="rdp-default-edit-test.rdp";
  { std::ofstream file(path); file<<"prompt for credentials:i:1\nauthentication level:i:2\ncustom:s:before\n"; }
  {
    rdpClient::DefaultSettingsLease lease(core::utf8ToUTF16(path));
    std::ofstream file(path); file<<"prompt for credentials:i:0\nauthentication level:i:0\ncustom:s:after\n";
  }
  std::ifstream file(path); std::string text((std::istreambuf_iterator<char>(file)),{}); file.close();
  EXPECT_EQ(text,"prompt for credentials:i:1\nauthentication level:i:2\ncustom:s:after\n");
  std::remove(path);
}
TEST(RdpClient, MissingNativeFlagsRestoreTheExactOriginalFile) {
  const char* path="rdp-default-absent-flags.rdp";
  const std::string original="custom:s:keep without trailing newline";
  { std::ofstream file(path); file<<original; }
  { rdpClient::DefaultSettingsLease lease(core::utf8ToUTF16(path)); }
  std::ifstream file(path); std::string restored((std::istreambuf_iterator<char>(file)),{}); file.close();
  EXPECT_EQ(restored,original); std::remove(path);
}
TEST(RdpClient, MissingNativeDefaultIsTemporary) {
  const char* path="rdp-default-missing-test.rdp"; std::remove(path);
  { rdpClient::DefaultSettingsLease lease(core::utf8ToUTF16(path)); std::ifstream file(path); EXPECT_TRUE(file.good()); }
  std::ifstream file(path); EXPECT_FALSE(file.good());
}
TEST(RdpClient, RecoverySnapshotSurvivesAnInterruptedSession) {
  const char* path="rdp-recovery-native.rdp"; const char* config="rdp-recovery.json";
  std::remove(config);
  const std::string original="prompt for credentials:i:1\nauthentication level:i:3\ncustom:s:keep\n";
  { std::ofstream file(path); file<<original; }
  {
    rdpClient::DefaultSettingsLease lease(core::utf8ToUTF16(path),config);
    EXPECT_EQ(PortableConfig(config).read()["rdpRecovery"]["version"],1);
    EXPECT_THROW(rdpClient::restoreDefaultSettingsForTest(core::utf8ToUTF16(path),config),std::runtime_error);
    lease.abandonForTest();
  }
  EXPECT_TRUE(rdpClient::restoreDefaultSettingsForTest(core::utf8ToUTF16(path),config));
  std::ifstream file(path); std::string restored((std::istreambuf_iterator<char>(file)),{}); file.close();
  EXPECT_EQ(restored,original); EXPECT_TRUE(PortableConfig(config).read()["rdpRecovery"].isNull());
  std::remove(path); std::remove(config);
}
TEST(RdpClient, NewSessionRecoversPendingSettingsBeforeSavingItsSnapshot) {
  const char* path="rdp-recover-reconnect.rdp"; const char* config="rdp-reconnect.json";
  std::remove(config);
  const std::string original="prompt for credentials:i:1\nauthentication level:i:2\n";
  { std::ofstream file(path); file<<original; }
  { rdpClient::DefaultSettingsLease lease(core::utf8ToUTF16(path),config); lease.abandonForTest(); }
  { rdpClient::DefaultSettingsLease lease(core::utf8ToUTF16(path),config); }
  std::ifstream file(path); std::string restored((std::istreambuf_iterator<char>(file)),{}); file.close();
  EXPECT_EQ(restored,original); EXPECT_TRUE(PortableConfig(config).read()["rdpRecovery"].isNull());
  std::remove(path); std::remove(config);
}
TEST(RdpClient, RecoveryRemovesADefaultFileCreatedByAnInterruptedSession) {
  const char* path="rdp-recovery-created.rdp"; const char* config="rdp-recovery-created.json";
  std::remove(path); std::remove(config);
  { rdpClient::DefaultSettingsLease lease(core::utf8ToUTF16(path),config); lease.abandonForTest(); }
  EXPECT_TRUE(rdpClient::restoreDefaultSettingsForTest(core::utf8ToUTF16(path),config));
  std::ifstream file(path); EXPECT_FALSE(file.good());
  EXPECT_TRUE(PortableConfig(config).read()["rdpRecovery"].isNull());
  std::remove(config);
}
TEST(RdpClient, ManualRestoreWithoutSnapshotEnablesPromptsAndKeepsOtherFields) {
  const char* path="rdp-reset-native.rdp"; const char* config="rdp-reset.json";
  std::remove(config);
  { std::ofstream file(path); file<<"prompt for credentials:i:0\nauthentication level:i:0\ncustom:s:keep\n"; }
  EXPECT_FALSE(rdpClient::restoreDefaultSettingsForTest(core::utf8ToUTF16(path),config));
  std::ifstream file(path); std::string restored((std::istreambuf_iterator<char>(file)),{}); file.close();
  EXPECT_EQ(restored,"prompt for credentials:i:1\nauthentication level:i:2\ncustom:s:keep\n");
  std::remove(path); std::remove(config);
}
int main(int argc,char** argv) {
  if(argc==4 && std::string(argv[1]).find("/v:")==0) {
    try {
      auto endpoint=connectionProtocol::rdpEndpoint(std::string(argv[1]).substr(3));
      auto target=core::utf8ToUTF16(("TERMSRV/"+endpoint.host).c_str());
      PCREDENTIALW credential=nullptr;
      if(!CredReadW(target.c_str(),CRED_TYPE_GENERIC,0,&credential)) return 5;
      std::wstring expected=L"synthetic-stub-password";
      bool matches=credential->UserName && std::wstring(credential->UserName)==L"stub-user" &&
        credential->CredentialBlobSize==expected.size()*sizeof(wchar_t) && !memcmp(credential->CredentialBlob,expected.data(),credential->CredentialBlobSize);
      CredFree(credential); if(!matches) return 6;
      std::this_thread::sleep_for(std::chrono::milliseconds(300)); return 0;
    } catch(...) { return 4; }
  }
  testing::InitGoogleTest(&argc,argv); return RUN_ALL_TESTS();
}
