// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_VPN_PROFILES_H
#define TIGERVNCS_VPN_PROFILES_H
#include <core/Configuration.h>
#include <json/json.h>
#include <string>
#include <vector>
namespace vpnProfiles {
extern core::StringParameter openVpnExecutable, wireGuardDirectory;
struct Profile { std::string id, name; };
struct Catalog { std::vector<Profile> wireguard, openvpn; std::string wireguardError, openvpnError; bool loading = false; };
void refresh();
Catalog snapshot();
std::vector<Profile> parseOpenVpn(const std::string& text);
std::string wireGuardName(const std::string& filename);
void validateAssociation(const Json::Value& value);
}
#endif
