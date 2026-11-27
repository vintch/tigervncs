// SPDX-License-Identifier: GPL-2.0-or-later
// Test-only process: it never opens a network connection or runs a command.
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <string>
int wmain(int argc, wchar_t** argv) {
  if (GetConsoleWindow()) return 20;
  const char* setting = std::getenv("TIGERVNCS_PLINK_STUB_MODE");
  std::string mode = setting ? setting : "success";
  if (mode == "early-exit") return 1;
  if (mode == "timeout-connect") { Sleep(10000); return 1; }
  bool discovery = false;
  for (int i = 1; i < argc; ++i) if (std::wstring(argv[i]) == L"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") discovery = true;
  if (discovery) {
    const char output[] = "Host key fingerprint is:\r\nssh-ed25519 255 SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\n";
    DWORD count;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), output, sizeof(output)-1, &count, nullptr);
    return 1;
  }
  const std::string expected = "p@ss ' quote \\ special!";
  if (std::wstring(GetCommandLineW()).find(L"p@ss") != std::wstring::npos) return 21;
  std::wstring pipe, user, host; std::string command;
  bool unlock = false;
  bool batch = false, noAgent = false, noShare = false, temporaryKey = false;
  for (int i = 1; i < argc; ++i) {
    std::wstring arg = argv[i];
    if (arg == L"-N") unlock = true;
    else if (arg == L"-pwfile" && i + 1 < argc) pipe = argv[++i];
    else if (arg == L"-l" && i + 1 < argc) user = argv[++i];
    else if (arg == L"-P" && i + 1 < argc) ++i;
    else if (arg == L"-hostkey" && i + 1 < argc) temporaryKey = std::wstring(argv[++i]) == L"SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    else if (arg == L"-batch") batch = true;
    else if (arg == L"-noagent") noAgent = true;
    else if (arg == L"-noshare") noShare = true;
    else if (!arg.empty() && arg[0] != L'-') {
      if (host.empty()) host = arg;
      else command.assign(arg.begin(), arg.end());
    }
  }
  if (!batch || !noAgent || !noShare || !temporaryKey || user != L"user name\"quote" || host != L"127.0.0.1") return 22;
  FILE* file = _wfopen(pipe.c_str(), L"rb");
  if (!file) return 23;
  char buffer[8192]{};
  bool passwordMatches = std::fgets(buffer, sizeof(buffer), file) && std::string(buffer) == expected + "\n";
  fclose(file);
  if (!passwordMatches) return 24;
  DWORD count = 0;
  if (unlock) {
    if (!command.empty()) return 30;
    std::string trace = mode == "unlock-denied" ? "Access denied\r\n" : mode == "unlock-before-auth" ? "Remote side unexpectedly closed network connection\r\n" : "Access granted\r\n";
    if (mode == "unlock-success") trace += "FATAL ERROR: Remote side unexpectedly closed network connection\r\n";
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), trace.data(), DWORD(trace.size()), &count, nullptr);
    if (mode == "unlock-open") Sleep(10000);
    return 1;
  }
  if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), buffer, sizeof(buffer), &count, nullptr) || std::string(buffer, count) != expected + "\n") return 25;
  if (mode == "hang") { Sleep(10000); return 1; }
  if (mode == "no-ack") return 0;
  const std::string prefix = "TIGERVNCS_ACCEPTED_";
  auto at = command.find(prefix);
  if (at == std::string::npos) return 26;
  auto acknowledgement = command.substr(at, prefix.size() + 32) + "\r\n";
  if (mode == "wrong-ack") acknowledgement = prefix + "wrong\r\n";
  if (mode == "embedded-ack") acknowledgement = "untrusted prefix " + acknowledgement;
  HANDLE output = GetStdHandle(mode == "stderr" ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
  WriteFile(output, acknowledgement.data(), DWORD(acknowledgement.size()), &count, nullptr);
  return mode == "ack-drop" ? 1 : 0;
}
