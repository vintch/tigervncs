// SPDX-License-Identifier: GPL-2.0-or-later
// This explicit test binary launches an unelevated, non-networking broker.
#include <gtest/gtest.h>
#include "VpnElevation.h"
#include <windows.h>
#include <iostream>
#include <thread>
namespace {
vpnControl::Settings settings() { vpnControl::Settings value; value.wireguardDirectory = "C:\\fixture directory"; return value; }
struct Cleanup { ~Cleanup() { vpnElevation::release(); } };
Json::Value request() {
  Json::Value value; value["version"] = 1; value["action"] = "connect"; value["directory"] = "C:\\fixtures";
  value["profiles"].append("office"); return value;
}
}
TEST(VpnElevation, RequiresConsentBeforeStartingASession) {
  Cleanup cleanup; vpnElevation::release();
  EXPECT_EQ(vpnElevation::execute(settings(), true, {"office"}, false), vpnControl::Result::NeedElevation);
  EXPECT_FALSE(vpnElevation::active()); EXPECT_EQ(vpnElevation::processId(), 0);
}
TEST(VpnElevation, ReusesOneHelperAcrossMultipleCommands) {
  Cleanup cleanup; vpnElevation::release();
  ASSERT_EQ(vpnElevation::execute(settings(), true, {"office"}, true), vpnControl::Result::Ok);
  auto process = vpnElevation::processId(); ASSERT_NE(process, 0);
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(vpnElevation::execute(settings(), i % 2 == 0, {"other"}, false), vpnControl::Result::Ok);
    EXPECT_EQ(vpnElevation::processId(), process);
  }
}
TEST(VpnElevation, ReleasingSessionStopsTheHelperWithoutStoppingTheParent) {
  Cleanup cleanup; vpnElevation::release();
  ASSERT_EQ(vpnElevation::execute(settings(), true, {"office"}, true), vpnControl::Result::Ok);
  HANDLE helper = OpenProcess(SYNCHRONIZE, FALSE, vpnElevation::processId()); ASSERT_NE(helper, nullptr);
  vpnElevation::release();
  EXPECT_EQ(WaitForSingleObject(helper, 3000), WAIT_OBJECT_0); CloseHandle(helper);
  EXPECT_FALSE(vpnElevation::active());
}
TEST(VpnElevation, LostHelperDoesNotSilentlyLaunchAnotherElevation) {
  Cleanup cleanup; vpnElevation::release();
  ASSERT_EQ(vpnElevation::execute(settings(), true, {"office"}, true), vpnControl::Result::Ok);
  HANDLE helper = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, vpnElevation::processId()); ASSERT_NE(helper, nullptr);
  ASSERT_TRUE(TerminateProcess(helper, 1)); ASSERT_EQ(WaitForSingleObject(helper, 3000), WAIT_OBJECT_0); CloseHandle(helper);
  EXPECT_FALSE(vpnElevation::active());
  EXPECT_EQ(vpnElevation::execute(settings(), false, {"office"}, false), vpnControl::Result::NeedElevation);
  EXPECT_EQ(vpnElevation::processId(), 0);
}
TEST(VpnElevation, RejectsMalformedAndUnrelatedPrivilegedRequests) {
  auto value = request(); vpnControl::Settings decoded; bool connect; std::vector<std::string> profiles;
  ASSERT_TRUE(vpnElevation::decode(value, decoded, connect, profiles)); EXPECT_TRUE(connect);
  value["action"] = "run arbitrary program"; EXPECT_FALSE(vpnElevation::decode(value, decoded, connect, profiles));
  value = request(); value["profiles"][0] = "../escape"; EXPECT_FALSE(vpnElevation::decode(value, decoded, connect, profiles));
  value = request(); value["profiles"].append("second"); EXPECT_FALSE(vpnElevation::decode(value, decoded, connect, profiles));
  value = request(); value["directory"] = std::string("C:\\fixture\0bad",14); EXPECT_FALSE(vpnElevation::decode(value, decoded, connect, profiles));
  value = request(); value["version"] = 2; EXPECT_FALSE(vpnElevation::decode(value, decoded, connect, profiles));
  vpnElevation::release();
  EXPECT_EQ(vpnElevation::execute(settings(), true, {"../escape"}, true), vpnControl::Result::Error);
  EXPECT_EQ(vpnElevation::processId(), 0);
}
TEST(VpnElevation, HelperExitsWhenParentDiesWithoutCleanup) {
  for (const std::wstring mode : {L"--vpn-test-parent", L"--vpn-test-parent-busy"}) {
  wchar_t file[32768]; ASSERT_GT(GetModuleFileNameW(nullptr, file, 32768), 0);
  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE}; HANDLE reader = nullptr, writer = nullptr;
  ASSERT_TRUE(CreatePipe(&reader, &writer, &inherit, 0));
  SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = writer; startup.hStdError = GetStdHandle(STD_ERROR_HANDLE); startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  auto line = L"\"" + std::wstring(file) + L"\" " + mode;
  PROCESS_INFORMATION process{};
  ASSERT_TRUE(CreateProcessW(file, &line[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process));
  CloseHandle(writer);
  ASSERT_EQ(WaitForSingleObject(process.hProcess, 15000), WAIT_OBJECT_0);
  char buffer[128]{}; DWORD read = 0; ASSERT_TRUE(ReadFile(reader, buffer, sizeof(buffer)-1, &read, nullptr));
  CloseHandle(reader); CloseHandle(process.hProcess); CloseHandle(process.hThread);
  auto pid = std::strtoul(buffer, nullptr, 10); ASSERT_NE(pid, 0);
  HANDLE helper = OpenProcess(SYNCHRONIZE, FALSE, DWORD(pid));
  if (helper) { EXPECT_EQ(WaitForSingleObject(helper, 3000), WAIT_OBJECT_0); CloseHandle(helper); }
  }
}
int main(int argc, char** argv) {
  int result;
  if (vpnControl::helper(argc, argv, result)) return result;
  if (argc == 2 && (std::string(argv[1]) == "--vpn-test-parent" || std::string(argv[1]) == "--vpn-test-parent-busy")) {
    if (vpnElevation::execute(settings(), true, {"office"}, true) != vpnControl::Result::Ok) return 1;
    auto helperId = vpnElevation::processId();
    if (std::string(argv[1]) == "--vpn-test-parent-busy") {
      std::thread([]() { auto value = settings(); value.wireguardDirectory = "C:\\fixture hang"; vpnElevation::execute(value, true, {"office"}, false); }).detach();
      Sleep(100);
    }
    std::cout << helperId << std::endl;
    ExitProcess(0); // Deliberately skip all C++ destructors.
  }
  testing::InitGoogleTest(&argc, argv); return RUN_ALL_TESTS();
}
