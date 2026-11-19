// SPDX-License-Identifier: GPL-2.0-or-later
#include "PresenceMonitor.h"
#include <algorithm>
#include <chrono>
#include <set>

int64_t pingClockMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now().time_since_epoch()).count();
}
PresenceMonitor::PresenceMonitor(std::unique_ptr<PingTransport> value) : transport(std::move(value)) {}
PresenceMonitor::~PresenceMonitor() {
  for (auto& item : states) if (item.second.token) transport->cancel(item.second.token);
}
void PresenceMonitor::finish(State& state, bool success) {
  state.token = 0; state.sent = false;
  if (success) { state.online = true; state.misses = 0; }
  else { state.misses = std::min(2u, state.misses + 1); if (state.misses == 2) state.online = false; }
}
bool PresenceMonitor::online(const std::string& id) const {
  auto found = states.find(id);
  return found != states.end() && found->second.online;
}
void PresenceMonitor::tick(int64_t now, const std::vector<PingTarget>& visible) {
  std::set<std::string> active;
  for (const auto& target : visible) {
    active.insert(target.id);
    auto& state = states[target.id];
    if (state.address != target.address) {
      if (state.token) transport->cancel(state.token);
      state = State(); state.address = target.address;
    }
    state.active = true;
  }
  for (auto& item : states) {
    auto& state = item.second;
    if (!active.count(item.first)) {
      if (state.token) transport->cancel(state.token);
      state.token = 0; state.sent = false; state.active = false; state.misses = 0;
    }
  }
  for (const auto& event : transport->poll()) {
    for (auto& item : states) {
      auto& state = item.second;
      if (!state.active || state.token != event.token) continue;
      if (event.completed) finish(state, event.success);
      else { state.sent = true; state.pendingSince = event.time; state.attempted = event.time; }
      break;
    }
  }
  for (auto& item : states) {
    auto& state = item.second;
    // Both unresolved jobs and sent packets have bounded waits. Late results
    // are ignored by token, including after a folder closes or address edits.
    if (state.active && state.token && now - state.pendingSince >= timeoutMs) {
      transport->cancel(state.token); finish(state, false);
    }
  }
  if (visible.empty()) return;
  int64_t interval = std::max<int64_t>(minimumMs, (periodMs + int64_t(visible.size()) - 1) / int64_t(visible.size()));
  if (now - lastDispatch < interval) return;
  const PingTarget* next = nullptr;
  int64_t oldest = now + 1;
  for (const auto& target : visible) {
    const auto& state = states.at(target.id);
    if (!state.token && now - state.attempted >= periodMs && state.attempted < oldest) {
      next = &target; oldest = state.attempted;
    }
  }
  if (!next) return;
  auto& state = states.at(next->id);
  state.attempted = now; state.pendingSince = now; state.sent = false;
  state.token = nextToken++;
  lastDispatch = now;
  try {
    if (!transport->start(*next, state.token)) finish(state, false);
  } catch (...) { finish(state, false); }
}
