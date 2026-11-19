// SPDX-License-Identifier: GPL-2.0-or-later
#include "NetworkSettings.h"
#include <stdexcept>
#include <string>
#ifdef WIN32
#include <windows.h>
#endif
namespace networkSettings {
core::IntParameter connectTimeout("ConnectTimeoutSeconds", "Connection establishment timeout in seconds", 4, 1, 120);
core::IntParameter sessionTimeout("SessionTimeoutSeconds", "Active session response timeout in seconds", 4, 1, 120);
core::IntParameter pingTimeout("PingTimeoutSeconds", "ICMP reply timeout in seconds", 3, 1, 60);
core::IntParameter pingPeriod("PingPeriodSeconds", "Target polling period per visible computer in seconds", 3, 1, 3600);
core::IntParameter pingMinimum("PingMinimumIntervalSeconds", "Minimum interval between ICMP packets in seconds", 1, 1, 3600);
core::BoolParameter pingEnabled("PingEnabled", "Monitor visible computers using ICMP while the manager is open", true);
int connectTimeoutMs() { return int(connectTimeout) * 1000; }
int sessionTimeoutMs() { return int(sessionTimeout) * 1000; }
int pingTimeoutMs() { return int(pingTimeout) * 1000; }
int pingPeriodMs() { return int(pingPeriod) * 1000; }
int pingMinimumMs() { return int(pingMinimum) * 1000; }
#ifdef WIN32
namespace {
struct Entry { core::IntParameter* value; const wchar_t* name; int minimum, maximum; };
Entry entries[] = {
  {&connectTimeout, L"ConnectTimeoutSeconds", 1,120}, {&sessionTimeout, L"SessionTimeoutSeconds",1,120},
  {&pingTimeout, L"PingTimeoutSeconds",1,60}, {&pingPeriod, L"PingPeriodSeconds",1,3600},
  {&pingMinimum, L"PingMinimumIntervalSeconds",1,3600}
};
struct RegistryKey { HKEY value = nullptr; ~RegistryKey() { if (value) RegCloseKey(value); } };
}
#endif
void loadLegacyRegistry(const wchar_t* path) {
#ifdef WIN32
  RegistryKey key;
  auto status = RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_QUERY_VALUE, &key.value);
  if (status == ERROR_FILE_NOT_FOUND) return;
  if (status != ERROR_SUCCESS) throw std::runtime_error("Cannot read network settings from the Windows registry");
  auto read = [&](const wchar_t* name, DWORD& value) {
    DWORD size = sizeof(value), type = 0;
    return RegQueryValueExW(key.value, name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &size) == ERROR_SUCCESS &&
      type == REG_DWORD && size == sizeof(value);
  };
  DWORD value;
  for (auto& entry : entries)
    if (read(entry.name, value) && value >= DWORD(entry.minimum) && value <= DWORD(entry.maximum)) entry.value->setParam(int(value));
  if (read(L"PingEnabled", value) && value <= 1) pingEnabled.setParam(bool(value));
#else
  (void)path;
#endif
}
}
