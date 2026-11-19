// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_RDP_DEFAULTS_H
#define TIGERVNCS_RDP_DEFAULTS_H
#include <memory>
#include <string>
namespace rdpClient {
bool settingsInUse();
// Returns true when a saved recovery snapshot was restored; otherwise reset
// only the two native prompt flags to their normal interactive defaults.
bool restoreDefaultSettings();
// mstsc /v reads its own Default.rdp. Temporarily clear its prompt flags;
// automatic display also ignores cached dimensions/placement and enables
// resizing. Restore prior values on exit, preserving unrelated settings.
class DefaultSettingsLease {
  struct State; std::unique_ptr<State> state;
  void initialize(const std::wstring& path, const std::string& recoveryConfig = "", bool automaticDisplay = false);
public:
  explicit DefaultSettingsLease(bool automaticDisplay = false);
  ~DefaultSettingsLease();
#ifdef TIGERVNCS_RDP_TEST
  explicit DefaultSettingsLease(const std::wstring& path);
  DefaultSettingsLease(const std::wstring& path,const std::string& recoveryConfig,bool automaticDisplay = false);
  void abandonForTest();
#endif
};
#ifdef TIGERVNCS_RDP_TEST
bool restoreDefaultSettingsForTest(const std::wstring& path,const std::string& recoveryConfig);
#endif
}
#endif
