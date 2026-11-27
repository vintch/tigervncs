// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_OPENVPN_WINDOW_H
#define TIGERVNCS_OPENVPN_WINDOW_H
#include <string>
#ifdef WIN32
#include <windows.h>
#include <core/string.h>
#endif
namespace openVpnWindow {
inline void minimize(const std::string& executable) {
#ifdef WIN32
  auto expected = core::utf8ToUTF16(executable.c_str());
  // CLI commands can raise an existing GUI or create one after returning.
  for (int attempt = 0; attempt < 5; ++attempt) {
    EnumWindows([](HWND window, LPARAM parameter) -> BOOL {
      DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
      HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
      if (!process) return TRUE;
      wchar_t path[32768]; DWORD size = 32768;
      bool matches = QueryFullProcessImageNameW(process, 0, path, &size) &&
        _wcsicmp(path, reinterpret_cast<const std::wstring*>(parameter)->c_str()) == 0;
      CloseHandle(process);
      if (matches && IsWindowVisible(window)) PostMessageW(window, WM_SYSCOMMAND, SC_MINIMIZE, 0);
      return TRUE;
    }, reinterpret_cast<LPARAM>(&expected));
    Sleep(200);
  }
#else
  (void)executable;
#endif
}
}
#endif
