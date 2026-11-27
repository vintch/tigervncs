// SPDX-License-Identifier: GPL-2.0-or-later
#include "VpnProfiles.h"
#include "OpenVpnWindow.h"
#include <core/string.h>
#include <algorithm>
#include <cctype>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
#ifdef WIN32
#include <windows.h>
#endif
namespace vpnProfiles {
namespace {
std::string defaultLogPath() {
#ifdef WIN32
  wchar_t path[32768]; DWORD size = GetEnvironmentVariableW(L"APPDATA", path, 32768);
  if (size && size < 32768) return core::utf16ToUTF8(path) + "\\OpenVPN Connect\\log\\ovpn.log";
#endif
  return "";
}
}
core::StringParameter openVpnLog("OpenVPNConnectLogFile", "OpenVPN Connect log file", defaultLogPath().c_str());
core::StringParameter openVpnExecutable("OpenVPNConnectExecutable", "OpenVPN Connect executable", "C:\\Program Files\\OpenVPN Connect\\OpenVPNConnect.exe");
core::StringParameter wireGuardDirectory("WireGuardConfigurationDirectory", "WireGuard configuration directory", "C:\\Program Files\\WireGuard\\Data\\Configurations");
namespace {
struct State { std::mutex mutex; Catalog catalog; unsigned generation = 0; bool running = false, pending = false; std::string executable, directory; };
// A detached worker owns this state until it finishes, including during exit.
auto state = std::make_shared<State>();
void sortProfiles(std::vector<Profile>& profiles) {
  std::sort(profiles.begin(), profiles.end(), [](const Profile& a, const Profile& b) { return a.name < b.name; });
}
#ifdef WIN32
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
std::string listOpenVpn(const std::string& executable) {
  if (executable.empty()) throw std::runtime_error("OpenVPN Connect executable is not configured.");
  auto path = core::utf8ToUTF16(executable.c_str());
  if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
    throw std::runtime_error("OpenVPN Connect executable was not found.");
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
  Handle output, input;
  if (!CreatePipe(&output.value, &input.value, &attributes, 0)) throw std::runtime_error("Cannot capture OpenVPN profile list.");
  if (!SetHandleInformation(output.value, HANDLE_FLAG_INHERIT, 0))
    throw std::runtime_error("Cannot isolate OpenVPN output pipe.");
  Handle nullInput;
  nullInput.value = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, OPEN_EXISTING, 0, nullptr);
  if (nullInput.value == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot initialize OpenVPN profile discovery.");
  STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = input.value; startup.StartupInfo.hStdInput = nullInput.value;
  // Only these two handles may reach the helper. Inheriting our caller's
  // redirected streams can keep its pipes open after TigerVNCs has exited.
  SIZE_T attributeSize = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
  std::vector<unsigned char> storage(attributeSize);
  startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attributeSize))
    throw std::runtime_error("Cannot initialize OpenVPN process attributes.");
  struct Attributes { LPPROC_THREAD_ATTRIBUTE_LIST list; ~Attributes() { DeleteProcThreadAttributeList(list); } } cleanup{startup.lpAttributeList};
  HANDLE inherited[] = {input.value, nullInput.value};
  if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                inherited, sizeof(inherited), nullptr, nullptr))
    throw std::runtime_error("Cannot isolate OpenVPN process handles.");
  PROCESS_INFORMATION process{};
  std::wstring command = L"\"" + path + L"\" --list-profiles";
  auto slash = path.find_last_of(L"\\/");
  std::wstring directory = slash == std::wstring::npos ? L"" : path.substr(0, slash);
  if (!CreateProcessW(path.c_str(), &command[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                      nullptr, directory.empty() ? nullptr : directory.c_str(), &startup.StartupInfo, &process))
    throw std::runtime_error("Cannot start OpenVPN Connect profile discovery.");
  Handle child, thread; child.value = process.hProcess; thread.value = process.hThread;
  CloseHandle(input.value); input.value = nullptr;
  std::string result;
  auto deadline = GetTickCount64() + 4000;
  for (;;) {
    DWORD available = 0;
    if (PeekNamedPipe(output.value, nullptr, 0, nullptr, &available, nullptr) && available) {
      char buffer[4096]; DWORD count = 0;
      if (ReadFile(output.value, buffer, std::min<DWORD>(available, sizeof(buffer)), &count, nullptr)) result.append(buffer, count);
      if (result.size() > 1024 * 1024) { TerminateProcess(child.value, 1); throw std::runtime_error("OpenVPN profile list exceeds 1 MiB."); }
      continue;
    }
    if (WaitForSingleObject(child.value, 20) == WAIT_OBJECT_0) {
      // Drain any bytes written just before the process exited.
      if (PeekNamedPipe(output.value, nullptr, 0, nullptr, &available, nullptr) && available) continue;
      DWORD code = 1; GetExitCodeProcess(child.value, &code);
      if (code != 0) throw std::runtime_error("OpenVPN Connect could not list profiles.");
      return result;
    }
    if (GetTickCount64() >= deadline) { TerminateProcess(child.value, 1); throw std::runtime_error("OpenVPN profile discovery timed out."); }
  }
}
Catalog discover(const std::string& executable, const std::string& directory) {
  Catalog result;
  auto pattern = core::utf8ToUTF16((directory + "\\*").c_str());
  WIN32_FIND_DATAW data{};
  HANDLE search = FindFirstFileW(pattern.c_str(), &data);
  if (search == INVALID_HANDLE_VALUE) result.wireguardError = "Wireguard configuration directory is missing or inaccessible.";
  else {
    do {
      if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
      auto name = wireGuardName(core::utf16ToUTF8(data.cFileName));
      if (!name.empty()) result.wireguard.push_back({name, name});
    } while (FindNextFileW(search, &data));
    FindClose(search);
    sortProfiles(result.wireguard);
    result.wireguard.erase(std::unique(result.wireguard.begin(), result.wireguard.end(), [](const Profile& a, const Profile& b) { return a.id == b.id; }), result.wireguard.end());
  }
  try { result.openvpn = parseOpenVpn(listOpenVpn(executable)); }
  catch (const std::exception& error) { result.openvpnError = error.what(); }
  openVpnWindow::minimize(executable);
  return result;
}
#endif
}
std::string wireGuardName(const std::string& filename) {
  auto lower = filename;
  std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return char(std::tolower(c)); });
  for (const std::string suffix : {".conf.dpapi", ".conf"})
    if (lower.size() > suffix.size() && lower.compare(lower.size() - suffix.size(), suffix.size(), suffix) == 0)
      return filename.substr(0, filename.size() - suffix.size());
  return "";
}
std::vector<Profile> parseOpenVpn(const std::string& text) {
  if (text.size() > 1024 * 1024) throw std::runtime_error("OpenVPN profile list exceeds 1 MiB.");
  Json::CharReaderBuilder builder; builder["rejectDupKeys"] = true; builder["failIfExtra"] = true;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  Json::Value value; std::string errors;
  if (!reader->parse(text.data(), text.data() + text.size(), &value, &errors) || !value.isArray())
    throw std::runtime_error("OpenVPN Connect returned an invalid profile list.");
  std::vector<Profile> result; std::set<std::string> seen;
  for (const auto& entry : value) {
    if (!entry.isObject() || !entry["id"].isString() || !entry["name"].isString())
      throw std::runtime_error("OpenVPN Connect returned an invalid profile entry.");
    auto id = entry["id"].asString(), name = entry["name"].asString();
    if (id.empty() || name.empty() || id.size() > 1024 || name.size() > 1024 || !core::isValidUTF8(id.c_str()) || !core::isValidUTF8(name.c_str()) ||
        std::any_of(id.begin(), id.end(), [](unsigned char c) { return c < 32; }) ||
        std::any_of(name.begin(), name.end(), [](unsigned char c) { return c < 32; }))
      throw std::runtime_error("OpenVPN Connect returned an invalid profile identity.");
    std::string host = entry["host"].isString() ? entry["host"].asString() : "";
    if (entry["server-override"].isString() && !entry["server-override"].asString().empty() && entry["server-override"] != "none")
      host = entry["server-override"].asString();
    if (seen.insert(id).second) result.push_back({id, name, host,
                                                   entry["username"].isString() ? entry["username"].asString() : ""});
  }
  sortProfiles(result); return result;
}
void validateAssociation(const Json::Value& value) {
  if (value.isNull()) return;
  if (!value.isObject() || !value["enabled"].isBool() ||
      (value["provider"] != "wireguard" && value["provider"] != "openvpn") ||
      !value["profileId"].isString() || value["profileId"].asString().size() > 1024 ||
      value["profileId"].asString().find('\0') != std::string::npos ||
      (value["enabled"].asBool() && value["profileId"].asString().empty()))
    throw std::runtime_error("Invalid VPN association. Select a provider and profile.");
}
Catalog snapshot() { std::lock_guard<std::mutex> lock(state->mutex); return state->catalog; }
void refresh() {
  auto shared = state;
  {
    std::lock_guard<std::mutex> lock(shared->mutex);
    shared->executable = std::string(openVpnExecutable); shared->directory = std::string(wireGuardDirectory);
    ++shared->generation; shared->catalog.loading = true;
    if (shared->running) { shared->pending = true; return; }
    shared->running = true;
  }
  try {
    std::thread([shared]() {
      for (;;) {
        std::string executable, directory; unsigned generation;
        { std::lock_guard<std::mutex> lock(shared->mutex); executable = shared->executable; directory = shared->directory; generation = shared->generation; shared->pending = false; }
        Catalog result;
        try {
#ifdef WIN32
          result = discover(executable, directory);
#endif
        } catch (...) { result.wireguardError = result.openvpnError = "VPN profile discovery failed."; }
        std::lock_guard<std::mutex> lock(shared->mutex);
        if (generation == shared->generation) shared->catalog = std::move(result);
        if (!shared->pending) { shared->running = false; return; }
      }
    }).detach();
  } catch (...) {
    std::lock_guard<std::mutex> lock(shared->mutex); shared->running = false; shared->catalog.loading = false;
    shared->catalog.openvpnError = "Cannot start VPN profile discovery.";
  }
}
}
