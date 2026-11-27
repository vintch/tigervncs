// SPDX-License-Identifier: GPL-2.0-or-later
#include "PowerTools.h"
#include "CredentialVault.h"
#include <core/string.h>
#include <network/TcpSocket.h>
#include <algorithm>
#include <cctype>
#include <thread>
#include <stdexcept>
#include <vector>
#ifdef WIN32
#include <windows.h>
#include <sddl.h>
#endif
namespace powerTools {
core::StringParameter plinkExecutable("PlinkExecutable", "PuTTY plink executable", "C:\\Program Files\\PuTTY\\plink.exe");
Request::~Request() { CredentialVault::erase(password); }
const char* label(Action action) {
  switch (action) {
    case Action::UnlockFileVault: return "Unlock FileVault";
    case Action::PowerOff: return "Power Off";
    case Action::Reboot: return "Reboot";
    case Action::ForcePowerOff: return "Force Power Off";
    case Action::ForceReboot: return "Force Reboot";
  }
  return "";
}
bool actionForLabel(const std::string& text, Action& action) {
  for (auto candidate : {Action::PowerOff, Action::Reboot, Action::ForcePowerOff, Action::ForceReboot, Action::UnlockFileVault})
    if (text == label(candidate)) { action = candidate; return true; }
  return false;
}
std::string sshHost(const std::string& address) {
  if (address.find('\0') != std::string::npos) throw std::runtime_error("Invalid SSH address");
  std::string host; int ignoredPort;
  network::getHostAndPort(address.c_str(), &host, &ignoredPort);
  if (host.empty() || host[0] == '-' || !core::isValidUTF8(host.c_str()) ||
      std::any_of(host.begin(), host.end(), [](unsigned char c) { return c <= 32 || c == 127; }))
    throw std::runtime_error("Invalid SSH host");
  return host;
}
namespace {
std::string shellQuote(const std::string& text) {
  std::string result = "'";
  for (char c : text) result += c == '\'' ? "'\"'\"'" : std::string(1, c);
  return result + "'";
}
}
std::string remoteCommand(Action action, const std::string& token) {
  if (token.empty() || !std::all_of(token.begin(), token.end(), [](unsigned char c) { return std::isxdigit(c); }))
    throw std::runtime_error("Invalid command acknowledgement token");
  std::string command, binary;
  switch (action) {
    case Action::PowerOff: binary = "/sbin/shutdown"; command = binary + " -h now"; break;
    case Action::Reboot: binary = "/sbin/shutdown"; command = binary + " -r now"; break;
    case Action::ForcePowerOff: binary = "/sbin/halt"; command = binary + " -q"; break;
    case Action::ForceReboot: binary = "/sbin/reboot"; command = binary + " -q"; break;
    default: throw std::runtime_error("Invalid power action");
  }
  // Acknowledge a privileged dispatch, not the eventual hardware state. The
  // small delay lets SSH deliver this acknowledgement before power is lost.
  std::string privileged = "trap '' HUP; test -x " + binary + " || exit 1; "
    "/usr/bin/nohup /bin/sh -c " + shellQuote("/bin/sleep 1; exec " + command) +
    " </dev/null >/dev/null 2>&1 & printf '%s\\n' TIGERVNCS_ACCEPTED_" + token;
  return "test \"$(/usr/bin/uname -s)\" = Darwin || exit 1; "
    "/usr/bin/sudo -S -p '' -- /bin/sh -c " + shellQuote(privileged);
}
std::string fingerprintFromOutput(const std::string& output) {
  auto marker = output.find("Host key fingerprint is:");
  if (marker == std::string::npos) return "";
  auto start = output.find("SHA256:", marker);
  if (start == std::string::npos || output.size() - start < 50) return "";
  for (size_t i = start + 7; i < start + 50; ++i) {
    unsigned char c = output[i];
    if (!std::isalnum(c) && c != '+' && c != '/') return "";
  }
  if (output.size() > start + 50 && output[start + 50] != '\r' && output[start + 50] != '\n' && output[start + 50] != ' ') return "";
  return output.substr(start, 50);
}
#ifdef WIN32
namespace {
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct LocalMemory { void* value = nullptr; ~LocalMemory() { if (value) LocalFree(value); } };
std::wstring argument(const std::string& text) {
  auto wide = core::utf8ToUTF16(text.c_str());
  std::wstring result = L"\""; unsigned slashes = 0;
  for (wchar_t c : wide) {
    if (c == L'\\') { ++slashes; continue; }
    result.append(c == L'"' ? 2 * slashes + 1 : slashes, L'\\'); slashes = 0;
    result += c;
  }
  result.append(2 * slashes, L'\\'); return result + L'"';
}
std::string discoverHostKey(const std::string& executable, const Request& request, ULONGLONG deadline, std::string* diagnostic) {
  // PuTTY 0.83 has no accept-any-key switch. A deliberately nonmatching
  // temporary key makes a credential-free probe report the presented key,
  // even when a different key is already cached. Nothing is persisted.
  SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
  Handle output, writer, input;
  if (!CreatePipe(&output.value, &writer.value, &inherit, 0) ||
      !SetHandleInformation(output.value, HANDLE_FLAG_INHERIT, 0)) return "";
  input.value = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);
  if (input.value == INVALID_HANDLE_VALUE) return "";
  STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdInput = input.value; startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = writer.value;
  SIZE_T size = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<unsigned char> storage(size);
  startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size)) return "";
  struct Attributes { LPPROC_THREAD_ATTRIBUTE_LIST value; ~Attributes() { DeleteProcThreadAttributeList(value); } } attributes{startup.lpAttributeList};
  HANDLE inherited[] = {input.value, writer.value};
  if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) return "";
  auto path = core::utf8ToUTF16(executable.c_str());
  auto command = argument(executable) + L" -v -ssh -batch -T -noagent -noshare -no-antispoof -P 22 -l " + argument(request.username) +
    L" -hostkey SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA " + argument(request.host) + L" /usr/bin/true";
  PROCESS_INFORMATION process{};
  Handle job; job.value = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job.value || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return "";
  if (!CreateProcessW(path.c_str(), &command[0], nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &process)) return "";
  Handle child, thread; child.value = process.hProcess; thread.value = process.hThread;
  struct ChildGuard { HANDLE value; ~ChildGuard() { if (WaitForSingleObject(value, 0) != WAIT_OBJECT_0) { TerminateProcess(value, 1); WaitForSingleObject(value, 1000); } } } childGuard{child.value};
  if (!AssignProcessToJobObject(job.value, child.value) || ResumeThread(thread.value) == DWORD(-1)) return "";
  CloseHandle(writer.value); writer.value = nullptr;
  std::string response;
  for (;;) {
    DWORD available = 0;
    if (PeekNamedPipe(output.value, nullptr, 0, nullptr, &available, nullptr) && available) {
      char buffer[4096]; DWORD count = 0;
      if (!ReadFile(output.value, buffer, std::min<DWORD>(available, sizeof(buffer)), &count, nullptr)) return "";
      response.append(buffer, count);
      if (response.size() > 65536) return "";
    }
    if (GetTickCount64() >= deadline) { if (diagnostic) *diagnostic = "timed out"; return ""; }
    if (WaitForSingleObject(child.value, 20) == WAIT_OBJECT_0) {
      DWORD remaining = 0;
      if (PeekNamedPipe(output.value, nullptr, 0, nullptr, &remaining, nullptr) && remaining) continue;
      if (diagnostic) *diagnostic = response;
      return fingerprintFromOutput(response);
    }
  }
}
bool writeOverlapped(HANDLE pipe, HANDLE event, const std::string& text, ULONGLONG deadline) {
  ResetEvent(event); OVERLAPPED operation{}; operation.hEvent = event;
  DWORD written = 0;
  if (!WriteFile(pipe, text.data(), DWORD(text.size()), &written, &operation)) {
    if (GetLastError() != ERROR_IO_PENDING) return false;
    auto now = GetTickCount64();
    if (now >= deadline || WaitForSingleObject(event, DWORD(deadline - now)) != WAIT_OBJECT_0) {
      CancelIoEx(pipe, &operation); GetOverlappedResult(pipe, &operation, &written, TRUE); return false;
    }
    if (!GetOverlappedResult(pipe, &operation, &written, FALSE)) return false;
  }
  return written == text.size();
}
std::string sshError(const std::string& trace) {
  if (trace.find("Access denied") != std::string::npos || trace.find("authentication failed") != std::string::npos || trace.find("No supported authentication") != std::string::npos)
    return "SSH authentication failed. Check the saved username, password and FileVault unlock permission.";
  if (trace.find("Host does not exist") != std::string::npos || trace.find("getaddrinfo") != std::string::npos)
    return "Unable to resolve the SSH server address.";
  if (trace.find("Connection refused") != std::string::npos) return "The SSH server refused the connection. Check Remote Login.";
  if (trace.find("timed out") != std::string::npos) return "The SSH connection timed out.";
  return "Unable to establish the SSH connection or complete authentication.";
}
bool run(const std::string& executable, const Request& request, unsigned timeoutMs, std::string* error) {
  bool unlocking = request.action == Action::UnlockFileVault;
  if (error) *error = "Unable to start or communicate with PuTTY plink.";
  if (!executableAvailable(executable) || request.host.empty() || request.host[0] == '-' || request.username.empty() ||
      request.password.find_first_of("\r\n") != std::string::npos || request.password.find('\0') != std::string::npos ||
      request.password.size() > 4096 || request.username.find('\0') != std::string::npos || request.host.find('\0') != std::string::npos) return false;
  auto deadline = GetTickCount64() + timeoutMs;
  std::string diagnostic;
  const auto hostKey = discoverHostKey(executable, request, deadline, &diagnostic);
  if (hostKey.empty()) { if (error) *error = sshError(diagnostic); return false; }
  diagnostic.clear();
  Handle token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) return false;
  DWORD needed = 0; GetTokenInformation(token.value, TokenUser, nullptr, 0, &needed);
  std::vector<unsigned char> user(needed);
  if (!GetTokenInformation(token.value, TokenUser, user.data(), needed, &needed)) return false;
  LocalMemory sid;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, reinterpret_cast<LPWSTR*>(&sid.value))) return false;
  std::wstring dacl = L"D:P(A;;GA;;;" + std::wstring(static_cast<wchar_t*>(sid.value)) + L")(A;;GA;;;SY)";
  LocalMemory descriptor;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl.c_str(), SDDL_REVISION_1, &descriptor.value, nullptr)) return false;
  SECURITY_ATTRIBUTES privateAccess{sizeof(SECURITY_ATTRIBUTES), descriptor.value, FALSE};
  auto nonce = CredentialVault::newId();
  std::string pipeName = "\\\\.\\pipe\\TigerVNCs-plink-" + nonce;
  Handle passwordPipe, pipeEvent;
  passwordPipe.value = CreateNamedPipeW(core::utf8ToUTF16(pipeName.c_str()).c_str(),
    PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 8192, 8192, 0, &privateAccess);
  pipeEvent.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (passwordPipe.value == INVALID_HANDLE_VALUE || !pipeEvent.value) return false;
  OVERLAPPED connection{}; connection.hEvent = pipeEvent.value;
  bool connected = ConnectNamedPipe(passwordPipe.value, &connection) != FALSE;
  if (!connected && GetLastError() != ERROR_IO_PENDING) return false;
  // The connection operation must outlive cancellation on every return path.
  struct ConnectionGuard { HANDLE pipe; OVERLAPPED* operation; bool completed; ~ConnectionGuard() { if (!completed) { CancelIoEx(pipe, operation); DWORD count; GetOverlappedResult(pipe, operation, &count, TRUE); } } } connectionGuard{passwordPipe.value, &connection, false};
  SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
  Handle output, outputWriter, input, inputWriter, errors;
  if (!CreatePipe(&output.value, &outputWriter.value, &inherit, 0) ||
      !CreatePipe(&input.value, &inputWriter.value, &inherit, 8192) ||
      !SetHandleInformation(output.value, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(inputWriter.value, HANDLE_FLAG_INHERIT, 0)) return false;
  errors.value = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);
  if (errors.value == INVALID_HANDLE_VALUE) return false;
  STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdInput = input.value; startup.StartupInfo.hStdOutput = outputWriter.value; startup.StartupInfo.hStdError = unlocking ? outputWriter.value : errors.value;
  SIZE_T size = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<unsigned char> attributes(size);
  startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
  if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size)) return false;
  struct Attributes { LPPROC_THREAD_ATTRIBUTE_LIST value; ~Attributes() { DeleteProcThreadAttributeList(value); } } attributeGuard{startup.lpAttributeList};
  HANDLE inherited[] = {input.value, outputWriter.value, errors.value};
  if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) return false;
  std::wstring line = argument(executable) + L" -ssh -batch -T -noagent -noshare -no-antispoof -P 22 -l " + argument(request.username) + L" -pwfile " + argument(pipeName);
  // Accept the key discovered for this invocation, without a persistent pin.
  line += L" -hostkey " + argument(hostKey);
  if (unlocking) line += L" -v -N " + argument(request.host);
  else line += L" " + argument(request.host) + L" " + argument(remoteCommand(request.action, nonce));
  Handle job; job.value = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job.value || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return false;
  PROCESS_INFORMATION process{};
  auto path = core::utf8ToUTF16(executable.c_str());
  if (!CreateProcessW(path.c_str(), &line[0], nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &process)) return false;
  Handle child, thread; child.value = process.hProcess; thread.value = process.hThread;
  struct ChildGuard { HANDLE value; ~ChildGuard() { if (WaitForSingleObject(value, 0) != WAIT_OBJECT_0) { TerminateProcess(value, 1); WaitForSingleObject(value, 1000); } } } childGuard{child.value};
  if (!AssignProcessToJobObject(job.value, child.value) || ResumeThread(thread.value) == DWORD(-1)) return false;
  CloseHandle(outputWriter.value); outputWriter.value = nullptr;
  CloseHandle(input.value); input.value = nullptr;
  std::string secret = request.password + "\n";
  struct SecretGuard { std::string& value; ~SecretGuard() { CredentialVault::erase(value); } } secretGuard{secret};
  DWORD count = 0;
  // Fits the explicitly sized, empty stdin pipe; the child receives only the
  // sudo password here. Its SSH password uses the private named pipe instead.
  if (!unlocking && (!WriteFile(inputWriter.value, secret.data(), DWORD(secret.size()), &count, nullptr) || count != secret.size())) return false;
  CloseHandle(inputWriter.value); inputWriter.value = nullptr;
  while (!connected) {
    if (WaitForSingleObject(pipeEvent.value, 20) == WAIT_OBJECT_0) {
      if (!GetOverlappedResult(passwordPipe.value, &connection, &count, FALSE)) return false;
      connected = true;
    } else if (GetTickCount64() >= deadline || WaitForSingleObject(child.value, 0) == WAIT_OBJECT_0) return false;
  }
  connectionGuard.completed = true;
  ULONG client = 0;
  if (!GetNamedPipeClientProcessId(passwordPipe.value, &client) || client != process.dwProcessId) return false;
  if (!writeOverlapped(passwordPipe.value, pipeEvent.value, secret, deadline)) return false;
  // Closing the server supplies EOF to password-file readers without leaving
  // plaintext on disk. The pending-connect guard has already completed.
  CloseHandle(passwordPipe.value); passwordPipe.value = nullptr;
  std::string response;
  bool authenticated = false, disconnected = false;
  const std::string acknowledgement = "TIGERVNCS_ACCEPTED_" + nonce;
  for (;;) {
    DWORD available = 0;
    if (PeekNamedPipe(output.value, nullptr, 0, nullptr, &available, nullptr) && available) {
      char buffer[4096]; DWORD read = 0;
      if (!ReadFile(output.value, buffer, std::min<DWORD>(available, sizeof(buffer)), &read, nullptr)) return false;
      response.append(buffer, read);
      // Only a complete, exact stdout line from our privileged command counts.
      size_t end;
      while ((end = response.find('\n')) != std::string::npos) {
        auto lineText = response.substr(0, end);
        if (!lineText.empty() && lineText.back() == '\r') lineText.pop_back();
        if (unlocking) {
          if (lineText == "Access granted") authenticated = true;
          if (lineText.find("Remote side unexpectedly closed network connection") != std::string::npos || lineText.find("Server sent disconnect message") != std::string::npos || lineText.find("Connection closed by remote host") != std::string::npos) disconnected = true;
          diagnostic += lineText + "\n";
          if (diagnostic.size() > 65536) return false;
        } else if (lineText == acknowledgement) return true;
        response.erase(0, end + 1);
      }
      if (response.size() > 65536) return false;
    }
    if (GetTickCount64() >= deadline) { if (error) *error = authenticated ? "SSH login succeeded, but the server did not disconnect. FileVault may already be unlocked." : "The SSH connection or authentication timed out."; return false; }
    if (WaitForSingleObject(child.value, 20) == WAIT_OBJECT_0) {
      DWORD remaining = 0;
      if (PeekNamedPipe(output.value, nullptr, 0, nullptr, &remaining, nullptr) && remaining) continue;
      DWORD code = 1; GetExitCodeProcess(child.value, &code);
      if (unlocking && authenticated && (disconnected || code == 0)) return true;
      if (error) *error = authenticated ? "SSH login succeeded, but the expected FileVault disconnect was not observed." : sshError(diagnostic);
      return false;
    }
  }
}
}
#endif
bool executableAvailable(const std::string& path) {
#ifdef WIN32
  if (path.empty() || path.find('\0') != std::string::npos) return false;
  auto wide = core::utf8ToUTF16(path.c_str()); DWORD binaryType;
  DWORD attributes = GetFileAttributesW(wide.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY) && GetBinaryTypeW(wide.c_str(), &binaryType);
#else
  (void)path; return false;
#endif
}
bool available() { try { return executableAvailable(std::string(plinkExecutable)); } catch (...) { return false; } }
bool menuEnabled(const Json::Value& computer, bool plinkPresent, bool busy) {
  return plinkPresent && !busy && computer.isObject() && computer["username"].isString() &&
    !computer["username"].asString().empty() && computer["password"].isObject();
}
bool execute(const std::string& executable, const Request& request, unsigned timeoutMs, std::string* error) {
  try {
#ifdef WIN32
    return run(executable, request, timeoutMs, error);
#else
    (void)executable; (void)request; (void)timeoutMs; return false;
#endif
  } catch (...) { return false; }
}
std::shared_ptr<Job> start(Json::Value document, const std::string& computerId, Action action) {
  auto job = std::make_shared<Job>(); job->action = action; job->error = "Saved SSH credentials are unavailable."; std::string executable(plinkExecutable);
  try {
    std::thread([document, computerId, action, executable, job]() {
      try {
        for (const auto& computer : document["connections"]) if (computer["id"] == computerId) {
          Request request; request.host = sshHost(computer["address"].asString());
          request.username = computer["username"].asString(); request.action = action;
          if (computer["password"].isNull()) break;
          request.password = CredentialVault::decrypt(document, computerId, computer["password"]);
          job->success = execute(executable, request, 15000, &job->error); break;
        }
      } catch (...) { job->success = false; }
      job->done.store(true, std::memory_order_release);
    }).detach();
  } catch (...) { job->done.store(true, std::memory_order_release); }
  return job;
}
}
