// SPDX-License-Identifier: GPL-2.0-or-later
// No network/service operations. Checks hidden launch and literal arguments.
#include <windows.h>
#include <cstdlib>
#include <string>
int wmain(int argc, wchar_t** argv) {
  if (GetConsoleWindow() || argc != 2) return 20;
  std::wstring argument = argv[1];
  if (argument != L"--connect-shortcut=profile \"quoted\"\\" &&
      argument != L"--disconnect-shortcut=profile \"quoted\"\\") return 21;
  return std::getenv("VPN_CLI_STUB_FAIL") ? 7 : 0;
}
