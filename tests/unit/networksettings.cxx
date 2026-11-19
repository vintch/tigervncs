// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "NetworkSettings.h"
#include <windows.h>
TEST(NetworkSettingsTest, ReadOnlyLegacyMigrationRejectsInvalidValues) {
  std::wstring path = L"Software\\TigerVNCs\\Tests\\Network-" + std::to_wstring(GetCurrentProcessId());
  struct Cleanup { std::wstring path; ~Cleanup() { RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str()); } } cleanup{path};
  HKEY key = nullptr;
  ASSERT_EQ(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(),0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr), ERROR_SUCCESS);
  DWORD valid = 8, invalid = 0;
  RegSetValueExW(key,L"ConnectTimeoutSeconds",0,REG_DWORD,reinterpret_cast<BYTE*>(&valid),sizeof(valid));
  RegSetValueExW(key,L"PingMinimumIntervalSeconds",0,REG_DWORD,reinterpret_cast<BYTE*>(&invalid),sizeof(invalid));
  invalid = 0xffffffff;
  RegSetValueExW(key,L"SessionTimeoutSeconds",0,REG_DWORD,reinterpret_cast<BYTE*>(&invalid),sizeof(invalid)); RegCloseKey(key);
  networkSettings::connectTimeout.setParam(4); networkSettings::sessionTimeout.setParam(4); networkSettings::pingMinimum.setParam(1);
  ASSERT_NO_THROW(networkSettings::loadLegacyRegistry(path.c_str()));
  EXPECT_EQ(networkSettings::connectTimeoutMs(),8000);
  EXPECT_EQ(networkSettings::sessionTimeoutMs(),4000); EXPECT_EQ(networkSettings::pingMinimumMs(),1000);
  networkSettings::connectTimeout.setParam(4);
}
