// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_VPN_PROFILES_H
#define TIGERVNCS_VPN_PROFILES_H
#include <core/Configuration.h>
#include <json/json.h>
#include <string>
#include <vector>
namespace vpnProfiles {
extern core::StringParameter openVpnExecutable, wireGuardDirectory, openVpnLog;
struct Profile {
  std::string id, name, host, username;
  Profile(const std::string& identifier = "", const std::string& label = "", const std::string& server = "", const std::string& user = "")
    : id(identifier), name(label), host(server), username(user) {}
};
struct Catalog { std::vector<Profile> wireguard, openvpn, azure; std::string wireguardError, openvpnError, azureError; bool loading = false; };
void refresh();
Catalog snapshot();
std::vector<Profile> parseOpenVpn(const std::string& text);
std::string wireGuardName(const std::string& filename);
void validateAssociation(const Json::Value& value);
}
#endif
