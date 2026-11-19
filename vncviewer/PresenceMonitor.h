// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_PRESENCE_MONITOR_H
#define TIGERVNCS_PRESENCE_MONITOR_H
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

struct PingTarget { std::string id, address; };
struct PingEvent {
  uint64_t token;
  bool completed, success;
  int64_t time;
};
class PingTransport {
public:
  virtual ~PingTransport() {}
  virtual bool start(const PingTarget&, uint64_t token) = 0;
  virtual std::vector<PingEvent> poll() = 0;
  virtual void cancel(uint64_t token) = 0;
};
std::unique_ptr<PingTransport> createPingTransport();
int64_t pingClockMs();

// Main-thread scheduler; the transport owns all network work. No callbacks
// from worker threads can access a window, tree item or this object.
class PresenceMonitor {
public:
  explicit PresenceMonitor(std::unique_ptr<PingTransport> transport);
  ~PresenceMonitor();
  void tick(int64_t now, const std::vector<PingTarget>& visible);
  bool online(const std::string& id) const;
private:
  struct State {
    std::string address;
    bool active = false, online = false, sent = false;
    unsigned misses = 0;
    uint64_t token = 0;
    int64_t attempted = -1000000, pendingSince = 0;
  };
  void finish(State&, bool success);
  std::unique_ptr<PingTransport> transport;
  std::map<std::string, State> states;
  uint64_t nextToken = 1;
  int64_t lastDispatch = -1000000;
};
#endif
