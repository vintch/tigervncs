// SPDX-License-Identifier: GPL-2.0-or-later
#include "VpnControl.h"
#include "VpnElevation.h"
#include <core/string.h>
#include <algorithm>
#include <cctype>
#include <thread>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <shlobj.h>
#endif
namespace vpnControl {
Association association(const Json::Value& computer) {
  Association value;
  if (!computer.isObject()) return value;
  const auto& vpn = computer["vpn"];
  if (!vpn.isObject() || vpn["enabled"] != true || !vpn["profileId"].isString() ||
      (vpn["provider"] != "wireguard" && vpn["provider"] != "openvpn")) return value;
  value.profile = vpn["profileId"].asString(); value.provider = vpn["provider"].asString();
  value.enabled = !value.profile.empty(); return value;
}
Presentation presentation(const Association& target, const Snapshot& status, bool busy) {
  Presentation value;
  if (!target.enabled || busy) return value;
  const State& state = target.provider == "wireguard" ? status.wireguard : status.openvpn;
  if (!state.valid || state.transitioning) return value;
  value.enabled = true;
  if (state.connected) value.colour = std::find(state.profiles.begin(), state.profiles.end(), target.profile) != state.profiles.end() ? Colour::Green : Colour::Amber;
  return value;
}
Plan plan(const Association& target, const Snapshot& status) {
  Plan value;
  auto appearance = presentation(target, status, false);
  if (!appearance.enabled) return value;
  value.connect = appearance.colour == Colour::Grey;
  value.confirmation = appearance.colour == Colour::Amber;
  if (value.confirmation) value.profiles = (target.provider == "wireguard" ? status.wireguard : status.openvpn).profiles;
  else value.profiles.push_back(target.profile);
  value.available = !value.profiles.empty(); return value;
}
namespace {
std::string lower(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return char(std::tolower(c)); }); return text;
}
std::string hostname(std::string text) {
  if (!text.empty() && text.front() == '[') {
    auto end = text.find(']'); if (end != std::string::npos) return lower(text.substr(1, end - 1));
  }
  auto colon = text.rfind(':');
  if (colon != std::string::npos && text.find(':') == colon) text.resize(colon);
  return lower(text);
}
}
std::string profileFromLog(const std::string& text, const std::vector<vpnProfiles::Profile>& profiles) {
  auto connected = text.rfind("EVENT: CONNECTED ");
  if (connected == std::string::npos) return "";
  auto disconnected = text.rfind("EVENT: DISCONNECTED");
  if (disconnected != std::string::npos && disconnected > connected) return "";
  auto start = connected + std::string("EVENT: CONNECTED ").size();
  auto end = text.find_first_of(" \r\n", start);
  auto endpoint = text.substr(start, end == std::string::npos ? end : end - start);
  std::string user;
  auto at = endpoint.rfind('@');
  if (at != std::string::npos) { user = endpoint.substr(0, at); endpoint.erase(0, at + 1); }
  std::vector<std::string> matches;
  for (const auto& profile : profiles) {
    if (profile.host.empty() || hostname(profile.host) != hostname(endpoint)) continue;
    if (!profile.username.empty() && !user.empty() && profile.username != user) continue;
    matches.push_back(profile.id);
  }
  return matches.size() == 1 ? matches.front() : "";
}
bool validWireguardProfile(const std::string& value) {
  return !value.empty() && value.size() <= 128 && value != "." && value != ".." &&
    value.back() != '.' && value.back() != ' ' && core::isValidUTF8(value.c_str()) &&
    std::none_of(value.begin(), value.end(), [](unsigned char c) { return c < 32 || c == 127 || std::string("<>:\"/\\|?*").find(char(c)) != std::string::npos; });
}
Settings settings() {
  Settings value; value.openvpnExe = std::string(vpnProfiles::openVpnExecutable);
  value.wireguardDirectory = std::string(vpnProfiles::wireGuardDirectory);
  value.openvpnLog = std::string(vpnProfiles::openVpnLog);
  auto catalog = vpnProfiles::snapshot();
  if (!catalog.loading && catalog.openvpnError.empty()) value.profiles = catalog.openvpn;
  return value;
}
#ifdef WIN32
namespace {
struct Handle { HANDLE value = nullptr; ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct Service { SC_HANDLE value = nullptr; ~Service() { if (value) CloseServiceHandle(value); } };
std::wstring argument(const std::string& text) {
  auto wide = core::utf8ToUTF16(text.c_str()); std::wstring value = L"\""; unsigned slashes = 0;
  for (wchar_t c : wide) {
    if (c == L'\\') { ++slashes; continue; }
    value.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\'); slashes = 0; value += c;
  }
  value.append(slashes * 2, L'\\'); return value + L'"';
}
bool exists(const std::string& path) {
  auto attributes = GetFileAttributesW(core::utf8ToUTF16(path.c_str()).c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}
bool run(const std::string& executable, const std::vector<std::string>& args, unsigned timeout = 8000) {
  if (!exists(executable)) return false;
  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
  Handle nullInput, nullOutput;
  nullInput.value = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);
  nullOutput.value = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);
  if (nullInput.value == INVALID_HANDLE_VALUE || nullOutput.value == INVALID_HANDLE_VALUE) return false;
  STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdInput = nullInput.value; startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = nullOutput.value;
  SIZE_T bytes = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
  std::vector<unsigned char> storage(bytes);
  startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes)) return false;
  struct Attributes { LPPROC_THREAD_ATTRIBUTE_LIST value; ~Attributes() { DeleteProcThreadAttributeList(value); } } cleanup{startup.lpAttributeList};
  HANDLE handles[] = {nullInput.value, nullOutput.value};
  if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr)) return false;
  std::wstring line = argument(executable);
  for (const auto& arg : args) line += L" " + argument(arg);
  auto exePath = core::utf8ToUTF16(executable.c_str());
  auto slash = exePath.find_last_of(L"\\/");
  std::wstring directory = slash == std::wstring::npos ? L"" : exePath.substr(0, slash);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(core::utf8ToUTF16(executable.c_str()).c_str(), &line[0], nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, directory.empty() ? nullptr : directory.c_str(), &startup.StartupInfo, &process)) return false;
  Handle child, thread; child.value = process.hProcess; thread.value = process.hThread;
  if (WaitForSingleObject(child.value, timeout) != WAIT_OBJECT_0) { TerminateProcess(child.value, 1); return false; }
  DWORD code = 1; return GetExitCodeProcess(child.value, &code) && code == 0;
}
State wireguardState() {
  State value; Service manager; manager.value = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
  if (!manager.value) return value;
  DWORD needed = 0, count = 0, resume = 0;
  if (EnumServicesStatusExW(manager.value, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &needed, &count, &resume, nullptr)) {
    value.valid = true; return value;
  }
  if (GetLastError() != ERROR_MORE_DATA || needed == 0) return value;
  std::vector<unsigned char> data(needed + 4096); resume = 0;
  if (!EnumServicesStatusExW(manager.value, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, data.data(), DWORD(data.size()), &needed, &count, &resume, nullptr)) return value;
  auto services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(data.data());
  const std::wstring prefix = L"WireGuardTunnel$";
  for (DWORD i = 0; i < count; ++i) {
    std::wstring name = services[i].lpServiceName;
    if (name.compare(0, prefix.size(), prefix) != 0) continue;
    DWORD state = services[i].ServiceStatusProcess.dwCurrentState;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING || state == SERVICE_CONTINUE_PENDING || state == SERVICE_PAUSE_PENDING)
      value.transitioning = true;
    if (state == SERVICE_RUNNING || state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
      value.profiles.push_back(core::utf16ToUTF8(name.substr(prefix.size()).c_str()));
  }
  value.valid = true; value.connected = !value.profiles.empty(); return value;
}
bool openvpnAdapter(bool& connected) {
  ULONG size = 16384; std::vector<unsigned char> buffer(size);
  ULONG code;
  for (int retry = 0; retry < 3; ++retry) {
    code = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                               nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    if (code != ERROR_BUFFER_OVERFLOW) break;
    if (size > 4 * 1024 * 1024) return false;
    buffer.resize(size);
  }
  if (code == ERROR_NO_DATA) { connected = false; return true; }
  if (code != NO_ERROR) return false;
  connected = false;
  for (auto adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter; adapter = adapter->Next) {
    auto description = lower(core::utf16ToUTF8(adapter->Description ? adapter->Description : L""));
    auto name = lower(core::utf16ToUTF8(adapter->FriendlyName ? adapter->FriendlyName : L""));
    bool owned = description.find("openvpn") != std::string::npos || name.find("openvpn") != std::string::npos;
    if (owned && adapter->OperStatus == IfOperStatusUp && adapter->FirstUnicastAddress) connected = true;
  }
  return true;
}
bool readLog(const std::string& path, std::string& text) {
  Handle file; file.value = CreateFileW(core::utf8ToUTF16(path.c_str()).c_str(), GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file.value == INVALID_HANDLE_VALUE) return false;
  LARGE_INTEGER size, offset;
  if (!GetFileSizeEx(file.value, &size)) return false;
  offset.QuadPart = std::max<LONGLONG>(0, size.QuadPart - 1024 * 1024);
  if (!SetFilePointerEx(file.value, offset, nullptr, FILE_BEGIN)) return false;
  std::vector<char> data(size_t(size.QuadPart - offset.QuadPart)); DWORD count = 0;
  if (!data.empty() && !ReadFile(file.value, data.data(), DWORD(data.size()), &count, nullptr)) return false;
  if (count) text.assign(data.data(), count); else text.clear();
  return true;
}
State openvpnState(const Settings& settings) {
  State value;
  if (!exists(settings.openvpnExe) || !openvpnAdapter(value.connected)) return value;
  if (value.connected) {
    std::string log;
    if (!readLog(settings.openvpnLog, log)) return State();
    auto profile = profileFromLog(log, settings.profiles);
    if (profile.empty()) return State();
    value.profiles.push_back(profile);
  }
  value.valid = true; return value;
}
std::string wireguardExecutable() {
  wchar_t folder[MAX_PATH];
  if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, SHGFP_TYPE_CURRENT, folder))) return "";
  return core::utf16ToUTF8(folder) + "\\WireGuard\\wireguard.exe";
}
Result controlWireguard(const Settings& settings, bool connect, const std::vector<std::string>& profiles) {
  if (profiles.empty() || (connect && profiles.size() != 1)) return Result::Error;
  for (const auto& profile : profiles) if (!validWireguardProfile(profile)) return Result::Error;
  Service manager; manager.value = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager.value) return GetLastError() == ERROR_ACCESS_DENIED ? Result::NeedElevation : Result::Error;
  for (const auto& profile : profiles) {
    auto name = core::utf8ToUTF16(("WireGuardTunnel$" + profile).c_str());
    Service service; service.value = OpenServiceW(manager.value, name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | (connect ? SERVICE_START : SERVICE_STOP));
    if (!service.value) {
      DWORD error = GetLastError();
      if (error == ERROR_ACCESS_DENIED) return Result::NeedElevation;
      if (error != ERROR_SERVICE_DOES_NOT_EXIST) return Result::Error;
      if (!connect) continue;
      Service writable; writable.value = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
      if (!writable.value) return GetLastError() == ERROR_ACCESS_DENIED ? Result::NeedElevation : Result::Error;
      std::string file = settings.wireguardDirectory + "\\" + profile + ".conf.dpapi";
      if (!exists(file)) file = settings.wireguardDirectory + "\\" + profile + ".conf";
      if (!exists(file) || !run(wireguardExecutable(), {"/installtunnelservice", file})) return Result::Error;
      service.value = OpenServiceW(manager.value, name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START);
      if (!service.value) return Result::Error;
    }
    // wireguard /installtunnelservice defaults to automatic Windows startup.
    // This separate, manual tool must never leave that side effect behind.
    DWORD configBytes = 0;
    QueryServiceConfigW(service.value, nullptr, 0, &configBytes);
    if (!configBytes || configBytes > 65536) return Result::Error;
    std::vector<unsigned char> configData(configBytes);
    auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configData.data());
    if (!QueryServiceConfigW(service.value, config, configBytes, &configBytes)) return Result::Error;
    if (config->dwStartType != SERVICE_DEMAND_START) {
      Service editable; editable.value = OpenServiceW(manager.value, name.c_str(), SERVICE_CHANGE_CONFIG);
      if (!editable.value) return GetLastError() == ERROR_ACCESS_DENIED ? Result::NeedElevation : Result::Error;
      if (!ChangeServiceConfigW(editable.value, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) return Result::Error;
    }
    SERVICE_STATUS_PROCESS status{}; DWORD size = 0;
    if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &size)) return Result::Error;
    if (connect && status.dwCurrentState != SERVICE_RUNNING && status.dwCurrentState != SERVICE_START_PENDING) {
      if (!StartServiceW(service.value, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        return GetLastError() == ERROR_ACCESS_DENIED ? Result::NeedElevation : Result::Error;
    } else if (!connect && status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING) {
      SERVICE_STATUS ignored;
      if (!ControlService(service.value, SERVICE_CONTROL_STOP, &ignored) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
        return GetLastError() == ERROR_ACCESS_DENIED ? Result::NeedElevation : Result::Error;
    }
    auto deadline = GetTickCount64() + 10000;
    for (;;) {
      if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &size)) return Result::Error;
      if (status.dwCurrentState == (connect ? SERVICE_RUNNING : SERVICE_STOPPED)) break;
      if (GetTickCount64() >= deadline || (connect && status.dwCurrentState == SERVICE_STOPPED)) return Result::Error;
      Sleep(100);
    }
  }
  return Result::Ok;
}

}
#endif
Snapshot query(const Settings& settings) {
  Snapshot value;
#ifdef WIN32
  try { value.wireguard = wireguardState(); } catch (...) {}
  try { value.openvpn = openvpnState(settings); } catch (...) {}
#else
  (void)settings;
#endif
  return value;
}
Result command(const Settings& settings, const std::string& provider, bool connect, const std::vector<std::string>& profiles) {
  try {
#ifdef WIN32
    if (provider == "wireguard") return controlWireguard(settings, connect, profiles);
    if (provider != "openvpn" || profiles.size() != 1 || profiles.front().empty() || profiles.front().size() > 1024 || profiles.front().find('\0') != std::string::npos) return Result::Error;
    return run(settings.openvpnExe, {(connect ? "--connect-shortcut=" : "--disconnect-shortcut=") + profiles.front()}) ? Result::Ok : Result::Error;
#else
    (void)settings; (void)provider; (void)connect; (void)profiles; return Result::Error;
#endif
  } catch (...) { return Result::Error; }
}
std::shared_ptr<QueryJob> startQuery(const Settings& settings) {
  auto job = std::make_shared<QueryJob>();
  try { std::thread([settings, job]() { job->snapshot = query(settings); job->done.store(true, std::memory_order_release); }).detach(); }
  catch (...) { job->done.store(true, std::memory_order_release); }
  return job;
}
std::shared_ptr<CommandJob> startCommand(const Settings& settings, const std::string& provider, bool connect,
                                      const std::vector<std::string>& profiles, bool elevate) {
  auto job = std::make_shared<CommandJob>();
  try {
    std::thread([settings, provider, connect, profiles, elevate, job]() {
      try {
#ifdef WIN32
        job->result = provider == "wireguard" && (elevate || vpnElevation::active()) ?
          vpnElevation::execute(settings, connect, profiles, elevate) : command(settings, provider, connect, profiles);
#else
        job->result = command(settings, provider, connect, profiles);
#endif
      } catch (...) { job->result = Result::Error; }
      job->done.store(true, std::memory_order_release);
    }).detach();
  } catch (...) { job->done.store(true, std::memory_order_release); }
  return job;
}
bool helper(int argc, char** argv, int& result) {
  if (vpnElevation::helper(argc, argv, result)) return true;
  if (argc < 2 || std::string(argv[1]) != "--vpn-wireguard-control") return false;
#ifdef WIN32
  int wideCount = 0; auto wide = CommandLineToArgvW(GetCommandLineW(), &wideCount);
  if (!wide) { result = 1; return true; }
  std::vector<std::string> utf8;
  for (int i = 0; i < wideCount; ++i) utf8.push_back(core::utf16ToUTF8(wide[i]));
  LocalFree(wide);
  std::vector<char*> pointers;
  for (auto& value : utf8) pointers.push_back(&value[0]);
  argc = wideCount; argv = pointers.data();
#endif
  result = 1;
  if (argc < 5 || argc > 132 || (std::string(argv[2]) != "connect" && std::string(argv[2]) != "disconnect")) return true;
  Settings settings; settings.wireguardDirectory = argv[3];
  std::vector<std::string> profiles;
  for (int i = 4; i < argc; ++i) { if (!validWireguardProfile(argv[i])) return true; profiles.push_back(argv[i]); }
  result = command(settings, "wireguard", std::string(argv[2]) == "connect", profiles) == Result::Ok ? 0 : 1;
  return true;
}
}
