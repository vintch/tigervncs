// SPDX-License-Identifier: GPL-2.0-or-later
#include "VpnElevation.h"
#include <core/string.h>
#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <memory>
#include <mutex>
#ifdef WIN32
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shellapi.h>
#endif
namespace vpnElevation {
bool decode(const Json::Value& value, vpnControl::Settings& settings, bool& connect, std::vector<std::string>& profiles) {
  if (!value.isObject() || value["version"] != 1 || !value["directory"].isString() ||
      (value["action"] != "connect" && value["action"] != "disconnect") ||
      !value["profiles"].isArray() || value["profiles"].empty() || value["profiles"].size() > 128) return false;
  auto directory = value["directory"].asString();
  if (directory.empty() || directory.size() > 32768 || directory.find('\0') != std::string::npos || !core::isValidUTF8(directory.c_str())) return false;
  connect = value["action"] == "connect";
  if (connect && value["profiles"].size() != 1) return false;
  std::vector<std::string> validated;
  for (const auto& entry : value["profiles"]) {
    if (!entry.isString() || !vpnControl::validWireguardProfile(entry.asString())) return false;
    validated.push_back(entry.asString());
  }
  settings.wireguardDirectory = directory; profiles.swap(validated); return true;
}
#ifdef WIN32
namespace {
const DWORD maxFrame = 65536;
struct Handle {
  HANDLE value = nullptr;
  void close() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); value = nullptr; }
  ~Handle() { close(); }
};
struct LocalMemory { void* value = nullptr; ~LocalMemory() { if (value) LocalFree(value); } };
struct Session {
  std::mutex mutex; Handle pipe, process;
  bool alive() const { return pipe.value && process.value && WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT; }
  void close() { pipe.close(); process.close(); }
};
// Workers hold their own shared reference. Static destruction cannot invalidate
// an in-flight request; the helper also watches the original process handle.
auto session = std::make_shared<Session>();
std::wstring quote(const std::wstring& text) {
  std::wstring value = L"\""; unsigned slashes = 0;
  for (wchar_t c : text) {
    if (c == L'\\') { ++slashes; continue; }
    value.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\'); slashes = 0; value += c;
  }
  value.append(slashes * 2, L'\\'); return value + L'"';
}
bool finish(HANDLE pipe, OVERLAPPED& operation, HANDLE parent, DWORD timeout, DWORD& count) {
  HANDLE waits[] = {operation.hEvent, parent};
  DWORD result = WaitForMultipleObjects(parent ? 2 : 1, waits, FALSE, timeout);
  if (result == WAIT_OBJECT_0) return GetOverlappedResult(pipe, &operation, &count, FALSE) != FALSE;
  CancelIoEx(pipe, &operation);
  GetOverlappedResult(pipe, &operation, &count, TRUE); // operation storage stays alive until cancellation completes
  return false;
}
bool transfer(HANDLE pipe, void* bytes, DWORD size, bool writing, HANDLE parent, DWORD timeout) {
  Handle event; event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!event.value) return false;
  auto cursor = static_cast<unsigned char*>(bytes);
  auto deadline = timeout == INFINITE ? 0 : GetTickCount64() + timeout;
  while (size) {
    OVERLAPPED operation{}; operation.hEvent = event.value; ResetEvent(event.value);
    DWORD count = 0;
    BOOL complete = writing ? WriteFile(pipe, cursor, size, &count, &operation) : ReadFile(pipe, cursor, size, &count, &operation);
    if (!complete) {
      if (GetLastError() != ERROR_IO_PENDING) return false;
      DWORD remaining = INFINITE;
      if (timeout != INFINITE) {
        auto now = GetTickCount64(); remaining = now < deadline ? DWORD(deadline - now) : 0;
      }
      if (!finish(pipe, operation, parent, remaining, count)) return false;
    }
    if (!count || count > size) return false;
    cursor += count; size -= count;
  }
  return true;
}
bool sameImage(HANDLE parent) {
  wchar_t parentImage[32768], ownImage[32768]; DWORD parentSize = 32768, ownSize = 32768;
  return QueryFullProcessImageNameW(parent, 0, parentImage, &parentSize) &&
    QueryFullProcessImageNameW(GetCurrentProcess(), 0, ownImage, &ownSize) && _wcsicmp(parentImage, ownImage) == 0;
}
void CALLBACK parentExited(void*, BOOLEAN) {
  // Also terminate if a native service call is still blocked. The helper has
  // no user data to save and must never outlive its authorization owner.
  TerminateProcess(GetCurrentProcess(), 0);
}
vpnControl::Result launch(Session& owner) {
  owner.close();
  unsigned char random[16];
  if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return vpnControl::Result::Error;
  std::wstring name = L"\\\\.\\pipe\\TigerVNCs-vpn-" + std::to_wstring(GetCurrentProcessId()) + L"-";
  const wchar_t digits[] = L"0123456789abcdef";
  for (auto c : random) { name += digits[c >> 4]; name += digits[c & 15]; }
  Handle token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) return vpnControl::Result::Error;
  DWORD needed = 0; GetTokenInformation(token.value, TokenUser, nullptr, 0, &needed);
  std::vector<unsigned char> user(needed);
  if (!GetTokenInformation(token.value, TokenUser, user.data(), needed, &needed)) return vpnControl::Result::Error;
  LocalMemory sid, descriptor;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, reinterpret_cast<LPWSTR*>(&sid.value))) return vpnControl::Result::Error;
  // Administrator access permits UAC with a separate admin account, while the
  // actual client must still be exactly the process returned by ShellExecute.
  auto dacl = L"D:P(A;;GA;;;" + std::wstring(static_cast<wchar_t*>(sid.value)) + L")(A;;GA;;;BA)(A;;GA;;;SY)";
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl.c_str(), SDDL_REVISION_1, &descriptor.value, nullptr)) return vpnControl::Result::Error;
  SECURITY_ATTRIBUTES access{sizeof(access), descriptor.value, FALSE};
  owner.pipe.value = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, maxFrame, maxFrame, 0, &access);
  if (owner.pipe.value == INVALID_HANDLE_VALUE) { owner.pipe.value = nullptr; return vpnControl::Result::Error; }
  Handle event; event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!event.value) { owner.close(); return vpnControl::Result::Error; }
  OVERLAPPED connection{}; connection.hEvent = event.value;
  if (ConnectNamedPipe(owner.pipe.value, &connection) || GetLastError() != ERROR_IO_PENDING) {
    owner.close(); return vpnControl::Result::Error;
  }
  struct Pending {
    HANDLE pipe; OVERLAPPED* operation; bool done;
    ~Pending() { if (!done) { CancelIoEx(pipe, operation); DWORD count; GetOverlappedResult(pipe, operation, &count, TRUE); } }
  } pending{owner.pipe.value, &connection, false};
  wchar_t executable[32768]; DWORD size = GetModuleFileNameW(nullptr, executable, 32768);
  if (!size || size == 32768) return vpnControl::Result::Error;
  auto arguments = L"--vpn-wireguard-broker " + quote(name) + L" " + std::to_wstring(GetCurrentProcessId());
#ifdef TIGERVNCS_VPN_BROKER_TEST
  std::wstring line = quote(executable) + L" " + arguments;
  STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
  bool started = CreateProcessW(executable, &line[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE;
  DWORD error = GetLastError();
  if (started) { owner.process.value = process.hProcess; CloseHandle(process.hThread); }
#else
  HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  SHELLEXECUTEINFOW info{}; info.cbSize = sizeof(info); info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  info.lpVerb = L"runas"; info.lpFile = executable; info.lpParameters = arguments.c_str(); info.nShow = SW_HIDE;
  bool started = ShellExecuteExW(&info) != FALSE; DWORD error = GetLastError();
  if (started) owner.process.value = info.hProcess;
  if (SUCCEEDED(initialized)) CoUninitialize();
#endif
  if (!started) return error == ERROR_CANCELLED ? vpnControl::Result::Cancelled : vpnControl::Result::Error;
  DWORD count = 0;
  bool connected = finish(owner.pipe.value, connection, owner.process.value, 10000, count);
  pending.done = true;
  ULONG client = 0;
  if (!connected || !owner.process.value || !GetNamedPipeClientProcessId(owner.pipe.value, &client) || client != GetProcessId(owner.process.value)) return vpnControl::Result::Error;
  return vpnControl::Result::Ok;
}
int serve(const std::wstring& name, DWORD parentId) {
  if (name.find(L"\\\\.\\pipe\\TigerVNCs-vpn-") != 0 || name.size() > 256 || !parentId || parentId == GetCurrentProcessId()) return 1;
  Handle parent; parent.value = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentId);
  if (!parent.value || !sameImage(parent.value) || WaitForSingleObject(parent.value, 0) != WAIT_TIMEOUT) return 1;
  HANDLE parentWait = nullptr;
  if (!RegisterWaitForSingleObject(&parentWait, parent.value, parentExited, nullptr, INFINITE, WT_EXECUTEONLYONCE)) return 1;
  struct ParentWait { HANDLE value; ~ParentWait() { UnregisterWaitEx(value, INVALID_HANDLE_VALUE); } } parentWatch{parentWait};
  if (!WaitNamedPipeW(name.c_str(), 10000)) return 1;
  Handle pipe; pipe.value = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
  if (pipe.value == INVALID_HANDLE_VALUE) { pipe.value = nullptr; return 1; }
  ULONG server = 0;
  if (!GetNamedPipeServerProcessId(pipe.value, &server) || server != parentId) return 1;
  for (;;) {
    DWORD size = 0;
    // Idle sessions last for the parent application's lifetime, not a timeout.
    if (!transfer(pipe.value, &size, sizeof(size), false, parent.value, INFINITE)) return 0;
    if (!size || size > maxFrame) return 1;
    std::string text(size, '\0');
    if (!transfer(pipe.value, &text[0], size, false, parent.value, 10000)) return 1;
    Json::CharReaderBuilder builder; builder["rejectDupKeys"] = true; builder["failIfExtra"] = true;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value value; std::string error; vpnControl::Settings settings; bool connect = false; std::vector<std::string> profiles;
    if (!reader->parse(text.data(), text.data() + text.size(), &value, &error) || !decode(value, settings, connect, profiles)) return 1;
    if (WaitForSingleObject(parent.value, 0) != WAIT_TIMEOUT) return 0;
#ifdef TIGERVNCS_VPN_BROKER_TEST
    if (settings.wireguardDirectory == "C:\\fixture hang") Sleep(10000);
    auto result = vpnControl::Result::Ok; // Explicit test binary never controls services.
#else
    auto result = vpnControl::command(settings, "wireguard", connect, profiles);
#endif
    DWORD response = result == vpnControl::Result::Ok ? 0 : 1;
    if (!transfer(pipe.value, &response, sizeof(response), true, parent.value, 10000)) return 0;
  }
}
}
#endif
bool active() {
#ifdef WIN32
  auto owner = session; std::lock_guard<std::mutex> lock(owner->mutex); return owner->alive();
#else
  return false;
#endif
}
unsigned long processId() {
#ifdef WIN32
  auto owner = session; std::lock_guard<std::mutex> lock(owner->mutex);
  return owner->alive() ? GetProcessId(owner->process.value) : 0;
#else
  return 0;
#endif
}
void release() {
#ifdef WIN32
  auto owner = session; std::lock_guard<std::mutex> lock(owner->mutex); owner->close();
#endif
}
vpnControl::Result execute(const vpnControl::Settings& settings, bool connect, const std::vector<std::string>& profiles, bool allowLaunch) {
  Json::Value request; request["version"] = 1; request["action"] = connect ? "connect" : "disconnect";
  request["directory"] = settings.wireguardDirectory; request["profiles"] = Json::Value(Json::arrayValue);
  for (const auto& profile : profiles) request["profiles"].append(profile);
  vpnControl::Settings validated; bool checkedConnect; std::vector<std::string> checkedProfiles;
  if (!decode(request, validated, checkedConnect, checkedProfiles)) return vpnControl::Result::Error;
#ifdef WIN32
  auto owner = session; std::lock_guard<std::mutex> lock(owner->mutex);
  if (!owner->alive()) {
    if (!allowLaunch) { owner->close(); return vpnControl::Result::NeedElevation; }
    auto result = launch(*owner);
    if (result != vpnControl::Result::Ok) { owner->close(); return result; }
  }
  Json::StreamWriterBuilder builder; builder["indentation"] = "";
  auto text = Json::writeString(builder, request);
  if (text.size() > maxFrame) return vpnControl::Result::Error;
  DWORD size = DWORD(text.size()), response = 1;
  bool sent = transfer(owner->pipe.value, &size, sizeof(size), true, owner->process.value, 10000) &&
    transfer(owner->pipe.value, &text[0], size, true, owner->process.value, 10000) &&
    transfer(owner->pipe.value, &response, sizeof(response), false, owner->process.value, 45000);
  if (!sent) { owner->close(); return vpnControl::Result::Error; }
  return response == 0 ? vpnControl::Result::Ok : vpnControl::Result::Error;
#else
  (void)allowLaunch; return vpnControl::Result::Error;
#endif
}
bool helper(int argc, char** argv, int& result) {
  if (argc < 2 || std::string(argv[1]) != "--vpn-wireguard-broker") return false;
  result = 1;
#ifdef WIN32
  int count = 0; auto args = CommandLineToArgvW(GetCommandLineW(), &count);
  if (!args) return true;
  try {
    if (count == 4) {
      wchar_t* end = nullptr; unsigned long parent = std::wcstoul(args[3], &end, 10);
      if (end && !*end) result = serve(args[2], DWORD(parent));
    }
  } catch (...) { result = 1; }
  LocalFree(args);
#endif
  return true;
}
}
