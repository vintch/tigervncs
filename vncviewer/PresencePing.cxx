// SPDX-License-Identifier: GPL-2.0-or-later
#include "PresenceMonitor.h"
#include <network/TcpSocket.h>
#include <atomic>
#include <condition_variable>
#include <list>
#include <mutex>
#include <thread>
#include <chrono>
#include <cstring>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#endif

namespace {
struct Job {
  uint64_t token;
  std::atomic<bool> cancelled{false}, sent{false}, done{false};
  bool success = false, reportedSent = false;
  int64_t sentAt = 0;
};
struct Limits {
  std::atomic<unsigned> workers{0};
  std::mutex mutex;
  std::condition_variable wake;
  int64_t lastSend = -1000000;
  std::map<std::string, int64_t> lastById;
};
// Shared across dialog lifetimes: returning to the main window cannot create
// an unbounded number of DNS/ICMP workers or reset the packet rate limit.
std::shared_ptr<Limits> limits() {
  static auto value = std::make_shared<Limits>();
  return value;
}

#ifdef WIN32
struct EventHandle {
  HANDLE value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  ~EventHandle() { if (value) CloseHandle(value); }
};
struct EchoHandle {
  HANDLE value;
  explicit EchoHandle(bool ipv6) : value(ipv6 ? Icmp6CreateFile() : IcmpCreateFile()) {}
  ~EchoHandle() { if (value != INVALID_HANDLE_VALUE) IcmpCloseHandle(value); }
};
bool resolve(const std::string& host, sockaddr_storage& result) {
  auto v4 = reinterpret_cast<sockaddr_in*>(&result);
  auto v6 = reinterpret_cast<sockaddr_in6*>(&result);
  if (InetPtonA(AF_INET, host.c_str(), &v4->sin_addr) == 1) { v4->sin_family = AF_INET; return true; }
  result = sockaddr_storage{};
  if (InetPtonA(AF_INET6, host.c_str(), &v6->sin6_addr) == 1) { v6->sin6_family = AF_INET6; return true; }
  int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host.c_str(), -1, nullptr, 0);
  if (count <= 0) return false;
  std::vector<wchar_t> name(count);
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host.c_str(), -1, name.data(), count)) return false;
  ADDRINFOEXW hints{};
  hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
  ADDRINFOEXW* addresses = nullptr;
  timeval timeout{3, 0};
  int status = GetAddrInfoExW(name.data(), nullptr, NS_DNS, nullptr, &hints,
                              &addresses, &timeout, nullptr, nullptr, nullptr);
  std::unique_ptr<ADDRINFOEXW, decltype(&FreeAddrInfoExW)> owner(addresses, FreeAddrInfoExW);
  if (status != 0) return false;
  // Exactly one address and one echo per attempt; never ping every DNS result.
  for (int family : {AF_INET, AF_INET6})
    for (auto address = addresses; address; address = address->ai_next)
      if (address->ai_family == family && address->ai_addrlen <= sizeof(result)) {
        result = sockaddr_storage{};
        std::memcpy(&result, address->ai_addr, address->ai_addrlen);
        return true;
      }
  return false;
}

bool echo(const PingTarget& target, const std::shared_ptr<Job>& job, const std::shared_ptr<Limits>& shared) {
  std::string host; int port;
  network::getHostAndPort(target.address.c_str(), &host, &port);
  sockaddr_storage destination{};
  if (!resolve(host, destination) || job->cancelled.load()) return false;
  bool ipv6 = destination.ss_family == AF_INET6;
  EventHandle event;
  EchoHandle handle(ipv6);
  if (!event.value || handle.value == INVALID_HANDLE_VALUE) return false;
  char payload[] = "TigerVNCs presence";
  std::vector<unsigned char> reply((ipv6 ? sizeof(ICMPV6_ECHO_REPLY) : sizeof(ICMP_ECHO_REPLY)) + sizeof(payload) + 8);
  sockaddr_in6 source{}; source.sin6_family = AF_INET6;
  DWORD count, error;
  {
    std::unique_lock<std::mutex> lock(shared->mutex);
    while (!job->cancelled.load() && (pingClockMs() - shared->lastSend < 1000 ||
           (shared->lastById.count(target.id) && pingClockMs() - shared->lastById[target.id] < 3000)))
      shared->wake.wait_for(lock, std::chrono::milliseconds(50));
    if (job->cancelled.load()) return false;
    job->sentAt = pingClockMs();
    if (ipv6)
      count = Icmp6SendEcho2(handle.value, event.value, nullptr, nullptr, &source,
        reinterpret_cast<sockaddr_in6*>(&destination), payload, sizeof(payload), nullptr,
        reply.data(), DWORD(reply.size()), 3000);
    else
      count = IcmpSendEcho2(handle.value, event.value, nullptr, nullptr,
        reinterpret_cast<sockaddr_in*>(&destination)->sin_addr.s_addr, payload, sizeof(payload), nullptr,
        reply.data(), DWORD(reply.size()), 3000);
    error = GetLastError();
    shared->lastSend = pingClockMs();
    shared->lastById[target.id] = shared->lastSend;
    job->sent.store(true, std::memory_order_release);
  }
  if (count == 0 && error != ERROR_IO_PENDING) return false;
  if (count == 0) {
    // Windows completes this operation after its 3000 ms timeout. Keep all
    // native buffers alive until completion, even if the UI cancelled it.
    // Workers are globally capped at four; the UI never waits for them.
    if (WaitForSingleObject(event.value, INFINITE) != WAIT_OBJECT_0) return false;
    count = ipv6 ? Icmp6ParseReplies(reply.data(), DWORD(reply.size())) : IcmpParseReplies(reply.data(), DWORD(reply.size()));
  }
  if (!count) return false;
  return ipv6 ? reinterpret_cast<ICMPV6_ECHO_REPLY*>(reply.data())->Status == IP_SUCCESS :
                reinterpret_cast<ICMP_ECHO_REPLY*>(reply.data())->Status == IP_SUCCESS;
}
#endif

class NativePingTransport : public PingTransport {
  std::list<std::shared_ptr<Job>> jobs;
  std::shared_ptr<Limits> shared = limits();
public:
  bool enabled = true;
  ~NativePingTransport() override {
    for (auto& job : jobs) job->cancelled.store(true);
    shared->wake.notify_all();
  }
  bool start(const PingTarget& target, uint64_t token) override {
    if (!enabled) return false;
    if (shared->workers.fetch_add(1) >= 4) { shared->workers.fetch_sub(1); return false; }
    try {
      auto job = std::make_shared<Job>(); job->token = token;
      auto limiter = shared;
      jobs.push_back(job);
      try {
        std::thread([job, limiter, target] {
          bool success = false;
          try {
#ifdef WIN32
            success = echo(target, job, limiter);
#endif
          } catch (...) { success = false; }
          job->success = success;
          job->done.store(true, std::memory_order_release);
          limiter->workers.fetch_sub(1);
        }).detach();
      } catch (...) { jobs.pop_back(); throw; }
      return true;
    } catch (...) { shared->workers.fetch_sub(1); return false; }
  }
  std::vector<PingEvent> poll() override {
    std::vector<PingEvent> result;
    for (auto iterator = jobs.begin(); iterator != jobs.end();) {
      auto& job = *iterator;
      if (!job->reportedSent && job->sent.load(std::memory_order_acquire)) {
        result.push_back({job->token, false, false, job->sentAt}); job->reportedSent = true;
      }
      if (job->done.load(std::memory_order_acquire)) {
        result.push_back({job->token, true, job->success, pingClockMs()});
        iterator = jobs.erase(iterator);
      } else ++iterator;
    }
    return result;
  }
  void cancel(uint64_t token) override {
    for (auto& job : jobs) if (job->token == token) job->cancelled.store(true);
    shared->wake.notify_all();
  }
};
}

std::unique_ptr<PingTransport> createPingTransport() {
  auto transport = new NativePingTransport();
  try { network::initSockets(); } catch (...) { transport->enabled = false; }
  return std::unique_ptr<PingTransport>(transport);
}
