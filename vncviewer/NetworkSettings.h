// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_NETWORK_SETTINGS_H
#define TIGERVNCS_NETWORK_SETTINGS_H
#include <core/Configuration.h>
namespace networkSettings {
extern core::IntParameter connectTimeout, sessionTimeout, pingTimeout, pingPeriod, pingMinimum;
extern core::BoolParameter pingEnabled;
int connectTimeoutMs();
int sessionTimeoutMs();
int pingTimeoutMs();
int pingPeriodMs();
int pingMinimumMs();
void loadLegacyRegistry(const wchar_t* key = L"Software\\TigerVNC\\vncviewer\\Network");
}
#endif
