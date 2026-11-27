// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "VpnControl.h"
#include "ConnectionStore.h"
#include <cstdio>
#include "OpenVpnWindow.h"
#include <windows.h>
#include <filesystem>
using namespace vpnControl;
TEST(VpnControl, NoAssociationNeverEnablesButton) {
  Snapshot status; status.wireguard.valid = status.openvpn.valid = true;
  auto target = association(Json::Value());
  EXPECT_FALSE(presentation(target, status, false).enabled);
  EXPECT_EQ(presentation(target, status, false).colour, Colour::Grey);
}
TEST(VpnControl, DisabledAssociationDoesNotFollowOtherProtocols) {
  Json::Value computer; computer["vpn"]["enabled"] = false; computer["vpn"]["provider"] = "wireguard"; computer["vpn"]["profileId"] = "office";
  EXPECT_FALSE(association(computer).enabled);
  computer["vpn"]["enabled"] = true; auto target = association(computer);
  Snapshot status; status.wireguard.valid = true; status.openvpn.connected = true; status.openvpn.profiles.push_back("unrelated");
  auto result = presentation(target, status, false);
  EXPECT_TRUE(result.enabled); EXPECT_EQ(result.colour, Colour::Grey);
}
TEST(VpnControl, GreyAmberGreenAndFailuresAreIndependentOfPing) {
  Association target; target.enabled = true; target.provider = "wireguard"; target.profile = "office";
  Snapshot status;
  EXPECT_FALSE(presentation(target, status, false).enabled);
  status.wireguard.valid = true;
  EXPECT_TRUE(presentation(target, status, false).enabled);
  EXPECT_EQ(presentation(target, status, false).colour, Colour::Grey);
  status.wireguard.connected = true; status.wireguard.profiles.push_back("other");
  EXPECT_EQ(presentation(target, status, false).colour, Colour::Amber);
  status.wireguard.profiles.push_back("office");
  EXPECT_EQ(presentation(target, status, false).colour, Colour::Green);
  EXPECT_FALSE(presentation(target, status, true).enabled);
  status.wireguard.transitioning = true; EXPECT_FALSE(presentation(target, status, false).enabled);
  status.wireguard.valid = false; EXPECT_EQ(presentation(target, status, false).colour, Colour::Grey);
}
TEST(VpnControl, OpenVpnLogUsesLastConnectedEndpointAndUsername) {
  std::vector<vpnProfiles::Profile> profiles{{"a", "Office", "office.example", "alice"}, {"b", "Other", "other.example", "bob"}};
  EXPECT_EQ(profileFromLog("EVENT: CONNECTED alice@office.example:1194 (1.2.3.4)", profiles), "a");
  EXPECT_EQ(profileFromLog("EVENT: CONNECTED alice@office.example:1194\nEVENT: CONNECTED bob@other.example:443\n", profiles), "b");
  EXPECT_EQ(profileFromLog("EVENT: CONNECTED alice@office.example:1194\nEVENT: DISCONNECTED", profiles), "");
  EXPECT_EQ(profileFromLog("EVENT: CONNECTED wrong@office.example:1194", profiles), "");
  EXPECT_EQ(profileFromLog("EVENT: CONNECTED bob@unknown.example:1194", profiles), "");
  profiles.push_back({"ambiguous", "Duplicate", "office.example", "alice"});
  EXPECT_EQ(profileFromLog("EVENT: CONNECTED alice@office.example:1194", profiles), "");
}
TEST(VpnControl, ReconnectingDoesNotInventADisconnectedAdapterState) {
  std::vector<vpnProfiles::Profile> profiles{{"a", "Office", "office.example", ""}};
  EXPECT_EQ(profileFromLog("EVENT: CONNECTED office.example:1194\nEVENT: RECONNECTING\n", profiles), "a");
  EXPECT_EQ(profileFromLog("EVENT: CONNECTING office.example:1194", profiles), "");
}
TEST(VpnControl, WireguardNamesCannotEscapeTheirConfigurationDirectory) {
  EXPECT_TRUE(validWireguardProfile("eshagzaiy_versatel_wg_config"));
  EXPECT_TRUE(validWireguardProfile("Hautaerzte-wg_config"));
  for (const auto& text : {"", "..", "../escape", "..\\escape", "C:escape", "profile\"injection", "profile.", "profile "})
    EXPECT_FALSE(validWireguardProfile(text)) << text;
}
TEST(VpnControl, InvalidCommandsFailWithoutStartingAnyConnection) {
  Settings settings;
  EXPECT_EQ(command(settings, "unknown", true, {"profile"}), Result::Error);
  EXPECT_EQ(command(settings, "openvpn", true, {}), Result::Error);
  EXPECT_EQ(command(settings, "wireguard", true, {"../escape"}), Result::Error);
  EXPECT_EQ(command(settings, "openvpn", true, {"one", "two"}), Result::Error);
}
TEST(VpnControl, OpenVpnCliIsHiddenAndPreservesLiteralProfileArguments) {
  wchar_t file[32768]; DWORD length = GetModuleFileNameW(nullptr, file, 32768);
  Settings settings;
  settings.openvpnExe = (std::filesystem::path(std::wstring(file, length)).parent_path() / "vpn_cli_stub.exe").u8string();
  EXPECT_EQ(command(settings, "openvpn", true, {"profile \"quoted\"\\"}), Result::Ok);
  EXPECT_EQ(command(settings, "openvpn", false, {"profile \"quoted\"\\"}), Result::Ok);
  SetEnvironmentVariableW(L"VPN_CLI_STUB_FAIL", L"1");
  auto result = command(settings, "openvpn", true, {"profile \"quoted\"\\"});
  SetEnvironmentVariableW(L"VPN_CLI_STUB_FAIL", nullptr);
  EXPECT_EQ(result, Result::Error);
}
TEST(VpnControl, MissingOpenVpnExecutableDisablesItsStatusWithoutACommand) {
  Settings settings; settings.openvpnExe = "C:\\missing-vpn-client.exe";
  auto snapshot = query(settings);
  EXPECT_FALSE(snapshot.openvpn.valid);
  Association target; target.enabled = true; target.provider = "openvpn"; target.profile = "profile";
  EXPECT_FALSE(presentation(target, snapshot, false).enabled);
}

TEST(VpnControl, OpenVpnServerOverrideMatchesTheActualConnectionLog) {
  auto profiles = vpnProfiles::parseOpenVpn(R"([{"id":"hautaerzte","name":"Hautarzt","host":"62.27.228.85","server-override":"practice.myfritz.net","username":"user"}])");
  EXPECT_EQ(profileFromLog("EVENT: CONNECTED user@practice.myfritz.net:1194 (195.52.57.24) via /UDP", profiles), "hautaerzte");
}

TEST(VpnControl, WrongProfileOnlyDisconnectsAfterConfirmationNeverAutoConnects) {
  Association target; target.enabled = true; target.provider = "openvpn"; target.profile = "selected";
  Snapshot status; status.openvpn.valid = true;
  auto grey = plan(target, status);
  EXPECT_TRUE(grey.available); EXPECT_TRUE(grey.connect); EXPECT_FALSE(grey.confirmation);
  ASSERT_EQ(grey.profiles.size(), 1); EXPECT_EQ(grey.profiles.front(), "selected");
  status.openvpn.connected = true; status.openvpn.profiles.push_back("currently-active");
  auto amber = plan(target, status);
  EXPECT_TRUE(amber.available); EXPECT_FALSE(amber.connect); EXPECT_TRUE(amber.confirmation);
  ASSERT_EQ(amber.profiles.size(), 1); EXPECT_EQ(amber.profiles.front(), "currently-active");
  status.openvpn.profiles[0] = "selected";
  auto green = plan(target, status);
  EXPECT_TRUE(green.available); EXPECT_FALSE(green.connect); EXPECT_FALSE(green.confirmation);
}

TEST(VpnControl, MinimizesOnlyWindowsOwnedByTheRequestedExecutable) {
  HWND window=CreateWindowExW(0,L"STATIC",L"TigerVNCs VPN window test",WS_OVERLAPPEDWINDOW,0,0,160,80,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
  ASSERT_NE(window,nullptr);
  // Model an Electron window that ignores the ordinary minimize system command.
  SetWindowLongPtrW(window,GWLP_WNDPROC,reinterpret_cast<LONG_PTR>(+[](HWND hwnd,UINT message,WPARAM wParam,LPARAM lParam)->LRESULT {
    if (message==WM_SYSCOMMAND && (wParam & 0xfff0)==SC_MINIMIZE) return 0;
    return DefWindowProcW(hwnd,message,wParam,lParam);
  }));
  ShowWindow(window,SW_SHOWNOACTIVATE);
  auto pump=[]() { MSG message; while (PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessageW(&message); } };
  openVpnWindow::minimizeOnce("C:\\not-the-owner.exe"); pump(); EXPECT_FALSE(IsIconic(window));
  wchar_t path[32768]; GetModuleFileNameW(nullptr,path,32768);
  openVpnWindow::minimizeOnce(std::filesystem::path(path).u8string()); pump(); EXPECT_TRUE(IsIconic(window));
  DestroyWindow(window);
}

TEST(VpnControl, MinimizesWindowsAppearingAfterTheCliHasExited) {
  wchar_t path[32768]; GetModuleFileNameW(nullptr,path,32768);
  openVpnWindow::minimize(std::filesystem::path(path).u8string());
  Sleep(1300);
  HWND window=CreateWindowExW(0,L"STATIC",L"Delayed VPN test",WS_OVERLAPPEDWINDOW,0,0,160,80,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
  ASSERT_NE(window,nullptr); ShowWindow(window,SW_SHOWNOACTIVATE);
  auto deadline=GetTickCount64()+2000;
  while (!IsIconic(window) && GetTickCount64()<deadline) {
    MSG message; while (PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) { TranslateMessage(&message); DispatchMessageW(&message); }
    Sleep(20);
  }
  EXPECT_TRUE(IsIconic(window)); openVpnWindow::cancelPending(); DestroyWindow(window);
}

TEST(VpnControl, AzureUsesIndependentGreyAmberGreenAndTransitionStates) {
  Json::Value computer; computer["vpn"]["enabled"]=true; computer["vpn"]["provider"]="azure"; computer["vpn"]["profileId"]="Saved Azure profile";
  auto target=association(computer); EXPECT_TRUE(target.enabled);
  Snapshot status; status.openvpn.valid=true; status.openvpn.connected=true;
  EXPECT_FALSE(presentation(target,status,false).enabled);
  status.azure.valid=true;
  EXPECT_EQ(presentation(target,status,false).colour,Colour::Grey);
  EXPECT_TRUE(plan(target,status).connect);
  status.azure.connected=true; status.azure.profiles={"Other Azure profile"};
  EXPECT_EQ(presentation(target,status,false).colour,Colour::Amber);
  auto different=plan(target,status); EXPECT_TRUE(different.confirmation); EXPECT_FALSE(different.connect);
  EXPECT_EQ(different.profiles.front(),"Other Azure profile");
  status.azure.profiles={target.profile};
  EXPECT_EQ(presentation(target,status,false).colour,Colour::Green);
  EXPECT_FALSE(plan(target,status).connect);
  status.azure.transitioning=true; EXPECT_FALSE(presentation(target,status,false).enabled);
  status.azure.transitioning=false; EXPECT_FALSE(presentation(target,status,true).enabled);
}
TEST(VpnControl, AzureAssociationSurvivesSavedComputerReload) {
  const char* path="azure-profile-store-test.json"; std::remove(path);
  Json::Value vpn; vpn["enabled"]=true; vpn["provider"]="azure"; vpn["profileId"]="Profile with spaces";
  std::string id;
  { ConnectionStore store(path); id=store.saveConnection("","Azure computer","host","","",ConnectionStore::KeepPassword,"","current-screen",vpn); }
  { ConnectionStore store(path); auto target=association(store.connection(id)); EXPECT_TRUE(target.enabled); EXPECT_EQ(target.provider,"azure"); EXPECT_EQ(target.profile,"Profile with spaces"); }
  std::remove(path);
}
