// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_VPN_ELEVATION_H
#define TIGERVNCS_VPN_ELEVATION_H
#include "VpnControl.h"
namespace vpnElevation {
bool active();
unsigned long processId();
void release();
vpnControl::Result execute(const vpnControl::Settings&, bool connect,
                           const std::vector<std::string>& profiles, bool allowLaunch);
bool helper(int argc, char** argv, int& result);
// Shared by both sides of the private channel; no arbitrary commands/executables.
bool decode(const Json::Value&, vpnControl::Settings&, bool& connect, std::vector<std::string>& profiles);
}
#endif
