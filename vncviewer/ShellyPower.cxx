// SPDX-License-Identifier: GPL-2.0-or-later
#include "ShellyPower.h"
#include "CredentialVault.h"
#include <core/string.h>
#include <network/TcpSocket.h>
#include <algorithm>
#include <chrono>
#include <map>
#include <vector>
#include <thread>
#include <stdexcept>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#endif
namespace shellyPower {
core::IntParameter delaySeconds("ShellyPlugDelaySeconds", "Delay between switching a Shelly Plug off and on, in seconds", 15, 1, 3600);
Credentials::~Credentials() { CredentialVault::erase(password); }
bool configured(const Json::Value& computer) {
  return computer.isObject() && computer["powerOn"].isObject() && computer["powerOn"]["mode"] == "shelly-plug";
}
Credentials credentials(const Json::Value& document, const std::string& id) {
  for (const auto& computer : document["connections"]) if (computer["id"] == id) {
    if (!configured(computer)) throw std::runtime_error("Power On is not configured");
    const auto& plug = computer["powerOn"]; Credentials value;
    value.address = plug["address"].asString(); value.username = plug["username"].asString();
    if (!plug["password"].isNull()) value.password = CredentialVault::decrypt(document, id + "::shelly", plug["password"]);
    parseAddress(value.address); return value;
  }
  throw std::runtime_error("Saved computer no longer exists");
}
Address parseAddress(const std::string& value) {
  if (value.empty() || value.size() > 256 || value.find_first_of("/\\@?# \r\n\t") != std::string::npos || value.find('\0') != std::string::npos)
    throw std::runtime_error("Enter a valid Shelly Plug IP address");
  Address parsed; std::string port; bool explicitPort = false;
  if (value[0] == '[') {
    auto end = value.find(']'); if (end == std::string::npos) throw std::runtime_error("Invalid Shelly Plug IP address");
    parsed.host = value.substr(1, end - 1);
    if (end + 1 < value.size()) { if (value[end + 1] != ':') throw std::runtime_error("Invalid Shelly Plug port"); port = value.substr(end + 2); explicitPort = true; }
  } else {
    auto colon = value.find(':');
    if (colon != std::string::npos && value.find(':', colon + 1) == std::string::npos) { parsed.host = value.substr(0, colon); port = value.substr(colon + 1); explicitPort = true; }
    else parsed.host = value;
  }
  if (!port.empty()) {
    if (port.size() > 5 || !std::all_of(port.begin(), port.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) throw std::runtime_error("Invalid Shelly Plug port");
    int number = std::stoi(port); if (number < 1 || number > 65535) throw std::runtime_error("Invalid Shelly Plug port"); parsed.port = static_cast<unsigned short>(number);
  } else if (explicitPort) throw std::runtime_error("Invalid Shelly Plug port");
#ifdef WIN32
  network::initSockets(); in_addr v4; in6_addr v6;
  if (InetPtonA(AF_INET, parsed.host.c_str(), &v4) != 1 && InetPtonA(AF_INET6, parsed.host.c_str(), &v6) != 1)
    throw std::runtime_error("Enter an IP address, not a URL or hostname");
#endif
  return parsed;
}
int64_t clockMs() { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
#ifdef WIN32
namespace {
struct Internet { HINTERNET value = nullptr; ~Internet() { if (value) WinHttpCloseHandle(value); } };
struct Wipe { std::string& value; ~Wipe() { CredentialVault::erase(value); } };
std::string base64(const std::string& text) {
  DWORD size = 0; CryptBinaryToStringA(reinterpret_cast<const BYTE*>(text.data()), DWORD(text.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size);
  std::string value(size, '\0');
  if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(text.data()), DWORD(text.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &value[0], &size)) throw std::runtime_error("Authentication failed");
  value.resize(size); while (!value.empty() && value.back() == '\0') value.pop_back(); return value;
}
std::string sha256(const std::string& text) {
  BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) throw std::runtime_error("Authentication failed");
  struct Cleanup { BCRYPT_ALG_HANDLE algorithm; BCRYPT_HASH_HANDLE* hash; ~Cleanup() { if (*hash) BCryptDestroyHash(*hash); BCryptCloseAlgorithmProvider(algorithm,0); } } cleanup{algorithm,&hash};
  if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0 ||
      BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())), ULONG(text.size()), 0) < 0) throw std::runtime_error("Authentication failed");
  unsigned char digest[32]; if (BCryptFinishHash(hash, digest, sizeof(digest), 0) < 0) throw std::runtime_error("Authentication failed");
  std::string value; const char digits[] = "0123456789abcdef";
  for (auto c : digest) { value += digits[c >> 4]; value += digits[c & 15]; } return value;
}
std::string quoted(const std::string& text) {
  std::string result = "\"";
  for (unsigned char c : text) {
    if (c < 32 || c == 127) throw std::runtime_error("Invalid authentication data");
    if (c == '\\' || c == '"') result += '\\';
    result += char(c);
  }
  return result + '"';
}
std::map<std::string,std::string> challengeFields(const std::string& text) {
  std::map<std::string,std::string> values; size_t at = text.find(' ');
  while (at != std::string::npos && at < text.size()) {
    at = text.find_first_not_of(" ,\t", at); if (at == std::string::npos) break;
    auto equal = text.find('=', at); if (equal == std::string::npos) break;
    std::string name = text.substr(at, equal - at); at = equal + 1; std::string value;
    if (at < text.size() && text[at] == '"') {
      ++at;
      while (at < text.size() && text[at] != '"') { if (text[at] == '\\' && at + 1 < text.size()) ++at; value += text[at++]; }
      if (at == text.size()) throw std::runtime_error("Invalid authentication challenge");
      ++at;
    } else { auto end = text.find(',', at); value = text.substr(at, end == std::string::npos ? end : end - at); at = end; }
    values[name] = value;
  }
  return values;
}
std::string authorization(const std::string& challenge, const Credentials& credentials, const std::string& uri) {
  if (challenge.compare(0, 5, "Basic") == 0) {
    if (credentials.username.find(':') != std::string::npos) throw std::runtime_error("Invalid username");
    std::string secret = credentials.username + ":" + credentials.password; Wipe wipe{secret}; return "Basic " + base64(secret);
  }
  if (challenge.compare(0, 6, "Digest") != 0) throw std::runtime_error("Unsupported authentication");
  auto fields = challengeFields(challenge);
  if (fields["algorithm"] != "SHA-256" || fields["realm"].empty() || fields["nonce"].empty() || fields["qop"] != "auth") throw std::runtime_error("Unsupported authentication");
  unsigned char random[16]; if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) throw std::runtime_error("Authentication failed");
  std::string cnonce; const char digits[] = "0123456789abcdef";
  for (auto c : random) { cnonce += digits[c >> 4]; cnonce += digits[c & 15]; }
  std::string secret = credentials.username + ":" + fields["realm"] + ":" + credentials.password; Wipe wipe{secret};
  std::string ha1 = sha256(secret); Wipe wipeHa1{ha1};
  auto response = sha256(ha1 + ":" + fields["nonce"] + ":00000001:" + cnonce + ":auth:" + sha256("GET:" + uri));
  std::string value = "Digest username=" + quoted(credentials.username) + ", realm=" + quoted(fields["realm"]) +
    ", nonce=" + quoted(fields["nonce"]) + ", uri=" + quoted(uri) + ", algorithm=SHA-256, qop=auth, nc=00000001, cnonce=" + quoted(cnonce) + ", response=" + quoted(response);
  if (!fields["opaque"].empty()) value += ", opaque=" + quoted(fields["opaque"]);
  return value;
}
class NativeTransport : public Transport {
public:
  bool setPower(const Credentials& credentials, bool on, int flipBackSeconds) override {
    try {
      auto address = parseAddress(credentials.address);
      if (credentials.username.size() > 1024 || credentials.password.size() > 4096) return false;
      std::string uri = std::string("/relay/0?turn=") + (on ? "on&timer=0" : "off&timer=" + std::to_string(flipBackSeconds));
      Internet session; session.value = WinHttpOpen(L"TigerVNCs", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
      if (!session.value || !WinHttpSetTimeouts(session.value, 2000, 2000, 2000, 2000)) return false;
      Internet connection; connection.value = WinHttpConnect(session.value, core::utf8ToUTF16(address.host.c_str()).c_str(), address.port, 0);
      if (!connection.value) return false;
      std::string auth; Wipe wipeAuth{auth};
      auto deadline = clockMs() + 6000;
      for (int attempt = 0; attempt < 3; ++attempt) {
        if (clockMs() >= deadline) return false;
        Internet request; request.value = WinHttpOpenRequest(connection.value, L"GET", core::utf8ToUTF16(uri.c_str()).c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if (!request.value || !WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof(redirects))) return false;
        if (!auth.empty()) {
          auto header = core::utf8ToUTF16(("Authorization: " + auth).c_str());
          if (!WinHttpAddRequestHeaders(request.value, header.c_str(), DWORD(-1), WINHTTP_ADDREQ_FLAG_ADD)) return false;
        }
        if (!WinHttpSendRequest(request.value, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request.value, nullptr)) return false;
        DWORD status = 0, bytes = sizeof(status);
        if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &bytes, WINHTTP_NO_HEADER_INDEX)) return false;
        if (status == 401) {
          DWORD size = 0; WinHttpQueryHeaders(request.value, WINHTTP_QUERY_WWW_AUTHENTICATE, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &size, WINHTTP_NO_HEADER_INDEX);
          if (!size || size > 16384) return false;
          std::vector<wchar_t> challenge(size / sizeof(wchar_t) + 1);
          if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_WWW_AUTHENTICATE, WINHTTP_HEADER_NAME_BY_INDEX, challenge.data(), &size, WINHTTP_NO_HEADER_INDEX)) return false;
          CredentialVault::erase(auth); auth = authorization(core::utf16ToUTF8(challenge.data()), credentials, uri); continue;
        }
        if (status != 200) return false;
        std::string text; char buffer[4096]; DWORD count;
        do {
          if (clockMs() >= deadline) return false;
          if (!WinHttpReadData(request.value, buffer, sizeof(buffer), &count)) return false;
          text.append(buffer, count); if (text.size() > 65536) return false;
        } while (count);
        Json::CharReaderBuilder builder; builder["failIfExtra"] = true;
        std::unique_ptr<Json::CharReader> reader(builder.newCharReader()); Json::Value value; std::string error;
        return reader->parse(text.data(), text.data()+text.size(), &value, &error) && value.isObject() &&
          value["ison"].isBool() && value["ison"].asBool() == on &&
          (on || (value["has_timer"].isBool() && value["has_timer"].asBool()));
      }
    } catch (...) {}
    return false;
  }
};
}
#endif
std::shared_ptr<Transport> transport() {
#ifdef WIN32
  return std::make_shared<NativeTransport>();
#else
  throw std::runtime_error("Shelly Plug control requires Windows");
#endif
}
std::shared_ptr<Cycle> start(Credentials credentials, int seconds, const std::shared_ptr<Transport>& client) {
  if (!client || seconds < 1 || seconds > 3600) throw std::runtime_error("Invalid Shelly Plug delay");
  auto cycle = std::make_shared<Cycle>();
  try {
    std::thread([credentials, seconds, client, cycle]() {
      try {
        cycle->offSucceeded = cycle->cancelled.load() || client->setPower(credentials, false, seconds);
        if (cycle->offSucceeded && !cycle->cancelled.load()) {
          cycle->waitStarted.store(clockMs()); cycle->phase.store(Phase::Waiting, std::memory_order_release);
          std::unique_lock<std::mutex> lock(cycle->mutex);
          cycle->wake.wait_for(lock, std::chrono::seconds(seconds), [cycle]() { return cycle->cancelled.load(); });
        }
      } catch (...) { cycle->offSucceeded = false; }
      cycle->phase.store(Phase::Restoring, std::memory_order_release);
      for (int attempt = 0; attempt < 2 && !cycle->onSucceeded; ++attempt)
        try { cycle->onSucceeded = client->setPower(credentials, true, 0); } catch (...) {}
      cycle->phase.store(Phase::Done, std::memory_order_release);
    }).detach();
  } catch (...) { cycle->phase.store(Phase::Done, std::memory_order_release); }
  return cycle;
}
}
