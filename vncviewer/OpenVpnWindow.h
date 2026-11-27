// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_OPENVPN_WINDOW_H
#define TIGERVNCS_OPENVPN_WINDOW_H
#include <string>
#include <atomic>
#include <thread>
#ifdef WIN32
#include <windows.h>
#include <core/string.h>
#endif
namespace openVpnWindow {
inline void minimizeOnce(const std::string& executable) {
#ifdef WIN32
  auto expected = core::utf8ToUTF16(executable.c_str());

  EnumWindows([](HWND window, LPARAM parameter) -> BOOL {
    DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return TRUE;
    wchar_t path[32768]; DWORD size = 32768;
    bool matches = QueryFullProcessImageNameW(process, 0, path, &size) &&
      _wcsicmp(path, reinterpret_cast<const std::wstring*>(parameter)->c_str()) == 0;
    CloseHandle(process);
    if (matches && IsWindowVisible(window) && !IsIconic(window)) ShowWindowAsync(window, SW_MINIMIZE);
    return TRUE;
  }, reinterpret_cast<LPARAM>(&expected));

#else
  (void)executable;
#endif
}
inline std::atomic<unsigned>& generation() { static std::atomic<unsigned> value{0}; return value; }
inline void cancelPending() { ++generation(); }
inline void minimize(const std::string& executable) {
  unsigned token = ++generation();
  minimizeOnce(executable);
#ifdef WIN32
  try {
    std::thread([executable, token]() {
      // Electron may raise the GUI well after its CLI process has exited.
      // Bound observation, cancel older requests, and keep the caller responsive.
      for (int attempt = 0; attempt < 60; ++attempt) {
        Sleep(250);
        if (generation().load() != token) return;
        minimizeOnce(executable);
      }
    }).detach();
  } catch (...) {}
#endif
}
}
#endif
