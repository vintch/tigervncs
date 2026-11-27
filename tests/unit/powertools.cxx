// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "PowerTools.h"
#include "CredentialVault.h"
#include <thread>
#include <windows.h>
#include <chrono>
#include <filesystem>
namespace {
std::string stubPath() {
  wchar_t path[32768]; DWORD size = GetModuleFileNameW(nullptr, path, 32768);
  auto stub = std::filesystem::path(std::wstring(path, size)).parent_path() / "plink_stub.exe";
  return stub.u8string();
}
struct Mode {
  explicit Mode(const char* value) { SetEnvironmentVariableA("TIGERVNCS_PLINK_STUB_MODE", value); }
  ~Mode() { SetEnvironmentVariableA("TIGERVNCS_PLINK_STUB_MODE", nullptr); }
};
powerTools::Request request() {
  powerTools::Request value; value.host = "127.0.0.1"; value.username = "user name\"quote";
  value.password = "p@ss ' quote \\ special!"; return value;
}
}
TEST(PowerTools, FixedMacCommandsAndValidatedAcknowledgements) {
  EXPECT_NE(powerTools::remoteCommand(powerTools::Action::PowerOff, "abcdef").find("/sbin/shutdown -h now"), std::string::npos);
  EXPECT_NE(powerTools::remoteCommand(powerTools::Action::Reboot, "abcdef").find("/sbin/shutdown -r now"), std::string::npos);
  EXPECT_NE(powerTools::remoteCommand(powerTools::Action::ForcePowerOff, "abcdef").find("/sbin/halt -q"), std::string::npos);
  EXPECT_NE(powerTools::remoteCommand(powerTools::Action::ForceReboot, "abcdef").find("/sbin/reboot -q"), std::string::npos);
  EXPECT_THROW(powerTools::remoteCommand(powerTools::Action::Reboot, "bad;token"), std::runtime_error);
  EXPECT_THROW(powerTools::remoteCommand(static_cast<powerTools::Action>(99), "abcd"), std::runtime_error);
}
TEST(PowerTools, SshHostIgnoresVncPortAndRejectsOptions) {
  EXPECT_EQ(powerTools::sshHost("127.0.0.1::5909"), "127.0.0.1");
  EXPECT_EQ(powerTools::sshHost("mac.local:2"), "mac.local");
  EXPECT_EQ(powerTools::sshHost("[::1]::5909"), "::1");
  EXPECT_THROW(powerTools::sshHost(std::string("host\0suffix", 11)), std::runtime_error);
  EXPECT_THROW(powerTools::sshHost("-load"), std::runtime_error);
  EXPECT_THROW(powerTools::sshHost("bad host"), std::runtime_error);
}
TEST(PowerTools, AvailabilityRequiresAnExecutable) {
  EXPECT_TRUE(powerTools::executableAvailable(stubPath()));
  EXPECT_FALSE(powerTools::executableAvailable("C:\\does-not-exist\\plink.exe"));
  EXPECT_FALSE(powerTools::executableAvailable("C:\\Windows"));
}
TEST(PowerTools, MenuRequiresBothSavedCredentialsAndPlinkWithoutUsingPing) {
  Json::Value computer(Json::objectValue);
  EXPECT_FALSE(powerTools::menuEnabled(computer, true));
  computer["username"] = "Administrator";
  EXPECT_FALSE(powerTools::menuEnabled(computer, true));
  computer["password"] = Json::Value(Json::objectValue);
  EXPECT_TRUE(powerTools::menuEnabled(computer, true));
  EXPECT_FALSE(powerTools::menuEnabled(computer, false));
  EXPECT_FALSE(powerTools::menuEnabled(computer, true, true));
  computer["online"] = false; EXPECT_TRUE(powerTools::menuEnabled(computer, true));
  computer["online"] = true; EXPECT_TRUE(powerTools::menuEnabled(computer, true));
  computer["username"] = ""; EXPECT_FALSE(powerTools::menuEnabled(computer, true));
}
TEST(PowerTools, HiddenProcessReceivesCredentialsWithoutPasswordArgumentsOrFiles) {
  Mode mode("success");
  for (auto action : {powerTools::Action::PowerOff, powerTools::Action::Reboot,
                     powerTools::Action::ForcePowerOff, powerTools::Action::ForceReboot}) {
    auto value = request(); value.action = action;
    ASSERT_TRUE(powerTools::execute(stubPath(), value, 2000));
  }
}
TEST(PowerTools, AcknowledgementSurvivesSshExitAfterAcceptedDispatch) {
  Mode mode("ack-drop"); auto value = request();
  EXPECT_TRUE(powerTools::execute(stubPath(), value, 2000));
}
TEST(PowerTools, NoSuccessForExitZeroStderrWrongOrEmbeddedAcknowledgements) {
  for (const char* text : {"no-ack", "stderr", "wrong-ack", "embedded-ack", "early-exit"}) {
    Mode mode(text); auto value = request();
    EXPECT_FALSE(powerTools::execute(stubPath(), value, 2000)) << text;
  }
}
TEST(PowerTools, ConnectionAndCommandTimeoutsAreBounded) {
  for (const char* text : {"timeout-connect", "hang"}) {
    Mode mode(text); auto value = request(); auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(powerTools::execute(stubPath(), value, 150));
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(2));
  }
}
TEST(PowerTools, LaunchFailuresAndInvalidCredentialsStayEncapsulated) {
  auto value = request(); EXPECT_FALSE(powerTools::execute("missing.exe", value, 150));
  value.password = "line\nbreak"; EXPECT_FALSE(powerTools::execute(stubPath(), value, 150));
}

TEST(PowerTools, AsyncDispatchUsesAnImmutableEncryptedCredentialSnapshot) {
  Mode mode("success");
  auto previous = powerTools::plinkExecutable.getValueStr();
  powerTools::plinkExecutable.setParam(stubPath().c_str());
  Json::Value document(Json::objectValue), computer(Json::objectValue);
  computer["id"] = "saved"; computer["address"] = "127.0.0.1::5909";
  computer["username"] = "user name\"quote";
  computer["password"] = CredentialVault::encrypt(document, "saved", "p@ss ' quote \\ special!");
  document["connections"].append(computer);
  auto job = powerTools::start(document, "saved", powerTools::Action::Reboot);
  powerTools::plinkExecutable.setParam(previous.c_str());
  document["connections"][0]["username"] = "changed-after-dispatch";
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (!job->done.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  ASSERT_TRUE(job->done.load(std::memory_order_acquire)); EXPECT_TRUE(job->success);
}

TEST(PowerTools, ParsesOnlyCompleteTemporaryServerFingerprints) {
  const std::string key = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  EXPECT_EQ(powerTools::fingerprintFromOutput("Host key fingerprint is:\r\nssh-ed25519 255 " + key + "\r\n"), key);
  EXPECT_EQ(powerTools::fingerprintFromOutput("unrelated " + key), "");
  EXPECT_EQ(powerTools::fingerprintFromOutput("Host key fingerprint is:\nSHA256:short"), "");
  EXPECT_EQ(powerTools::fingerprintFromOutput("Host key fingerprint is:\n" + key + "unexpected"), "");
}

TEST(PowerTools, FileVaultRequiresAuthenticationAndRemoteDisconnectWithoutCommands) {
  for (const char* scenario : {"unlock-success", "unlock-denied", "unlock-before-auth", "unlock-no-close", "unlock-open"}) {
    Mode mode(scenario); auto value=request(); value.action=powerTools::Action::UnlockFileVault;
    std::string error;
    bool success=powerTools::execute(stubPath(),value,1500,&error);
    EXPECT_EQ(success,std::string(scenario)=="unlock-success") << scenario;
    if (!success) EXPECT_FALSE(error.empty()) << scenario;
    if (std::string(scenario)=="unlock-denied") EXPECT_NE(error.find("authentication failed"),std::string::npos);
  }
}
