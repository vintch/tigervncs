// SPDX-License-Identifier: GPL-2.0-or-later
// Explicit test utility: only IDs and addresses are read; no credentials.
#include "PresenceMonitor.h"
#include <json/json.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>

class TracingPing : public PingTransport {
public:
  std::unique_ptr<PingTransport> native = createPingTransport();
  Json::Value events{Json::arrayValue};
  std::map<uint64_t, std::string> ids;
  bool start(const PingTarget& target, uint64_t token) override {
    ids[token] = target.id;
    return native->start(target, token);
  }
  std::vector<PingEvent> poll() override {
    auto result = native->poll();
    for (const auto& event : result) {
      Json::Value item;
      item["id"] = ids[event.token]; item["event"] = event.completed ? "completed" : "sent";
      item["success"] = event.success; item["time"] = Json::Int64(event.time);
      events.append(item);
    }
    return result;
  }
  void cancel(uint64_t token) override { native->cancel(token); }
};

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  try {
    Json::Value fixture;
    std::ifstream input(argv[1]); input >> fixture;
    std::vector<PingTarget> targets;
    for (const auto& value : fixture["targets"])
      targets.push_back({value["id"].asString(), value["address"].asString()});
    auto tracer = new TracingPing();
    PresenceMonitor monitor{std::unique_ptr<PingTransport>(tracer)};
    auto start = pingClockMs();
    while (pingClockMs() - start < 15000) {
      monitor.tick(pingClockMs(), targets);
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    Json::Value result;
    result["events"] = tracer->events;
    for (const auto& target : targets) result["online"][target.id] = monitor.online(target.id);
    std::cout << result << '\n';
    return 0;
  } catch (std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
