// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_RDP_DEFAULTS_H
#define TIGERVNCS_RDP_DEFAULTS_H
#include <memory>
#include <string>
namespace rdpClient {
// mstsc /v reads its own Default.rdp. Temporarily clear only its password
// prompt and server-authentication flags, preserving every other setting and
// restoring the flags on exit.
class DefaultSettingsLease {
  struct State; std::unique_ptr<State> state;
  void initialize(const std::wstring& path);
public:
  DefaultSettingsLease();
  ~DefaultSettingsLease();
#ifdef TIGERVNCS_RDP_TEST
  explicit DefaultSettingsLease(const std::wstring& path);
#endif
};
}
#endif
