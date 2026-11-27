// SPDX-License-Identifier: GPL-2.0-or-later
#include "VpnControl.h"
#include "VpnElevation.h"
#include "PortableConfig.h"
#include <chrono>
#include <thread>
#include <iostream>
int main(int argc, char** argv) {
  int helperResult;
  if (vpnControl::helper(argc, argv, helperResult)) return helperResult;
  if (argc < 3) return 2;
  try {
    auto document = PortableConfig(argv[1]).read();
    for (auto entry : {std::make_pair("OpenVPNConnectExecutable", &vpnProfiles::openVpnExecutable),
                       std::make_pair("WireGuardConfigurationDirectory", &vpnProfiles::wireGuardDirectory),
                       std::make_pair("OpenVPNConnectLogFile", &vpnProfiles::openVpnLog)})
      if (document["viewer"][entry.first].isString()) entry.second->setParam(document["viewer"][entry.first].asCString());
    if (std::string(argv[2]) == "query") {
      vpnProfiles::refresh();
      auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
      while (vpnProfiles::snapshot().loading && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      auto state = vpnControl::query(vpnControl::settings());
      Json::Value output;
      for (auto entry : {std::make_pair("wireguard", state.wireguard), std::make_pair("openvpn", state.openvpn), std::make_pair("azure", state.azure)}) {
        output[entry.first]["valid"] = entry.second.valid; output[entry.first]["connected"] = entry.second.connected;
        output[entry.first]["transitioning"] = entry.second.transitioning;
        output[entry.first]["profiles"] = Json::Value(Json::arrayValue);
        for (const auto& id : entry.second.profiles) output[entry.first]["profiles"].append(id);
      }
      std::cout << output << '\n'; return 0;
    }
    if (argc == 4 && std::string(argv[2]) == "session") {
      const std::string profile = argv[3];
      auto settings = vpnControl::settings();
      auto initial = vpnControl::query(settings);
      if (!initial.wireguard.valid || initial.wireguard.connected || !vpnControl::validWireguardProfile(profile)) return 2;
      unsigned long helper = 0;
      for (int attempt = 0; attempt < 4; ++attempt) {
        // Only the first request permits launching UAC; subsequent requests
        // must succeed using the already-approved privileged process.
        auto job = vpnControl::startCommand(settings, "wireguard", attempt % 2 == 0, {profile}, attempt == 0);
        while (!job->done.load(std::memory_order_acquire)) std::this_thread::sleep_for(std::chrono::milliseconds(20));
        if (job->result != vpnControl::Result::Ok) { std::cout << "Session operation failed\n"; return 1; }
        auto pid = vpnElevation::processId();
        if (!pid || (helper && pid != helper)) return 1;
        helper = pid;
        std::cout << "Operation " << attempt + 1 << " completed with the same helper\n" << std::flush;
      }
      vpnElevation::release();
      auto final = vpnControl::query(settings);
      if (final.wireguard.connected) return 1;
      std::cout << "Session reused; final VPN state is disconnected\n"; return 0;
    }
    if (argc < 6 || std::string(argv[2]) != "command" ||
        (std::string(argv[4]) != "connect" && std::string(argv[4]) != "disconnect")) return 2;
    std::vector<std::string> profiles;
    for (int i = 5; i < argc; ++i) profiles.push_back(argv[i]);
    auto result = vpnControl::command(vpnControl::settings(), argv[3], std::string(argv[4]) == "connect", profiles);
    std::cout << (result == vpnControl::Result::Ok ? "OK" : result == vpnControl::Result::NeedElevation ? "NEEDS_ELEVATION" : "ERROR") << '\n';
    return result == vpnControl::Result::Ok ? 0 : result == vpnControl::Result::NeedElevation ? 5 : 1;
  } catch (...) { return 1; }
}
