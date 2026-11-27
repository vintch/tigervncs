// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_VPN_CONTROL_H
#define TIGERVNCS_VPN_CONTROL_H
#include "VpnProfiles.h"
#include <atomic>
#include <memory>
#include <string>
#include <vector>
namespace vpnControl {
struct Association { std::string provider, profile; bool enabled = false; };
struct State {
  bool valid = false, connected = false, transitioning = false;
  std::vector<std::string> profiles;
};
struct Snapshot { State wireguard, openvpn, azure; };
struct Settings { std::string openvpnExe, wireguardDirectory, openvpnLog; std::vector<vpnProfiles::Profile> profiles; };
enum class Colour { Grey, Amber, Green };
struct Presentation { Colour colour = Colour::Grey; bool enabled = false; };
enum class Result { Ok, Error, NeedElevation, Cancelled };
struct Plan {
  bool available = false, connect = false, confirmation = false;
  std::vector<std::string> profiles;
};
Plan plan(const Association&, const Snapshot&);
struct QueryJob { std::atomic<bool> done{false}; Snapshot snapshot; };
struct CommandJob { std::atomic<bool> done{false}; Result result = Result::Error; };
Association association(const Json::Value& computer);
Presentation presentation(const Association&, const Snapshot&, bool busy);
std::string profileFromLog(const std::string& text, const std::vector<vpnProfiles::Profile>& profiles);
bool validWireguardProfile(const std::string& profile);
Settings settings();
Snapshot query(const Settings&);
Result command(const Settings&, const std::string& provider, bool connect, const std::vector<std::string>& profiles);
std::shared_ptr<QueryJob> startQuery(const Settings&);
std::shared_ptr<CommandJob> startCommand(const Settings&, const std::string& provider, bool connect,
                                      const std::vector<std::string>& profiles, bool elevate = false);
// Runs before normal startup so elevated helpers never load/write preferences.
bool helper(int argc, char** argv, int& result);
}
#endif
