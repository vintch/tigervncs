// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "PresenceMonitor.h"
#include <stdexcept>

namespace {
class FakePing : public PingTransport {
public:
  struct Call { PingTarget target; uint64_t token; int64_t time; };
  std::vector<Call> calls;
  std::vector<PingEvent> events;
  std::vector<uint64_t> cancelled;
  int64_t now = 0;
  bool autoReply = false, failStart = false, throwStart = false;
  bool start(const PingTarget& target, uint64_t token) override {
    if (throwStart) throw std::runtime_error("network failure");
    if (failStart) return false;
    calls.push_back({target, token, now});
    events.push_back({token, false, false, now});
    if (autoReply) events.push_back({token, true, true, now});
    return true;
  }
  std::vector<PingEvent> poll() override { auto result = events; events.clear(); return result; }
  void cancel(uint64_t token) override { cancelled.push_back(token); }
  void reply(size_t index, bool success) { events.push_back({calls.at(index).token, true, success, now}); }
};
}

TEST(PresenceTest, EvenSpacingAndFairCyclesForOneTwoThreeAndMoreComputers) {
  for (int count : {1, 2, 3, 5, 11}) {
    auto fake = new FakePing(); fake->autoReply = true;
    PresenceMonitor monitor{std::unique_ptr<PingTransport>(fake)};
    std::vector<PingTarget> targets;
    for (int index = 0; index < count; ++index) targets.push_back({std::to_string(index), "127.0.0.1"});
    int interval = std::max(1000, (3000 + count - 1) / count);
    for (int64_t time = 0; time <= count * interval * 3; time += 100) {
      fake->now = time; monitor.tick(time, targets);
    }
    ASSERT_GE(fake->calls.size(), size_t(count * 3));
    for (size_t index = 0; index < fake->calls.size(); ++index) {
      EXPECT_EQ(fake->calls[index].target.id, std::to_string(index % count));
      if (index) { EXPECT_EQ(fake->calls[index].time - fake->calls[index - 1].time, interval); }
      if (index >= size_t(count)) { EXPECT_GE(fake->calls[index].time - fake->calls[index - count].time, 3000); }
    }
  }
}

TEST(PresenceTest, SuccessTurnsGreenAndTwoConsecutiveFailuresTurnBlue) {
  auto fake = new FakePing();
  PresenceMonitor monitor{std::unique_ptr<PingTransport>(fake)};
  std::vector<PingTarget> targets{{"computer", "127.0.0.1"}};
  auto tick = [&](int64_t now) { fake->now = now; monitor.tick(now, targets); };
  tick(0); fake->reply(0, true); tick(100);
  EXPECT_TRUE(monitor.online("computer"));
  tick(3000); fake->reply(1, false); tick(3100);
  EXPECT_TRUE(monitor.online("computer"));
  tick(6000); fake->reply(2, false); tick(6100);
  EXPECT_FALSE(monitor.online("computer"));
  tick(9000); fake->reply(3, true); tick(9100);
  EXPECT_TRUE(monitor.online("computer"));
  tick(12000); fake->reply(4, false); tick(12100);
  EXPECT_TRUE(monitor.online("computer"));
}

TEST(PresenceTest, UnansweredPacketsExpireAtThreeSeconds) {
  auto fake = new FakePing();
  PresenceMonitor monitor{std::unique_ptr<PingTransport>(fake)};
  std::vector<PingTarget> targets{{"computer", "127.0.0.1"}};
  fake->now = 0; monitor.tick(0, targets);
  fake->reply(0, true); monitor.tick(1, targets);
  fake->now = 3000; monitor.tick(3000, targets);
  monitor.tick(5999, targets);
  EXPECT_TRUE(fake->cancelled.empty());
  EXPECT_TRUE(monitor.online("computer"));
  fake->now = 6000; monitor.tick(6000, targets);
  EXPECT_EQ(fake->cancelled.size(), 1u);
  EXPECT_TRUE(monitor.online("computer"));
  fake->now = 9000; monitor.tick(9000, targets);
  EXPECT_EQ(fake->cancelled.size(), 2u);
  EXPECT_FALSE(monitor.online("computer"));
}

TEST(PresenceTest, ClosedFoldersCancelPendingWorkAndIgnoreLateReplies) {
  auto fake = new FakePing();
  PresenceMonitor monitor{std::unique_ptr<PingTransport>(fake)};
  std::vector<PingTarget> targets{{"computer", "127.0.0.1"}};
  monitor.tick(0, targets);
  monitor.tick(100, {});
  ASSERT_EQ(fake->cancelled.size(), 1u);
  fake->reply(0, true);
  for (int64_t now = 200; now < 10000; now += 100) monitor.tick(now, {});
  EXPECT_EQ(fake->calls.size(), 1u);
  EXPECT_FALSE(monitor.online("computer"));
}

TEST(PresenceTest, AddressChangesInvalidateOldRepliesAndDoNotBurstAfterLongPauses) {
  auto fake = new FakePing();
  PresenceMonitor monitor{std::unique_ptr<PingTransport>(fake)};
  monitor.tick(0, {{"a", "127.0.0.1"}});
  fake->reply(0, true);
  monitor.tick(100, {{"a", "127.0.0.2"}});
  EXPECT_FALSE(monitor.online("a"));
  fake->now = 60000;
  monitor.tick(60000, {{"a", "127.0.0.2"}, {"b", "127.0.0.3"}, {"c", "127.0.0.4"}});
  EXPECT_EQ(fake->calls.size(), 2u);
  monitor.tick(60001, {{"a", "127.0.0.2"}, {"b", "127.0.0.3"}, {"c", "127.0.0.4"}});
  EXPECT_EQ(fake->calls.size(), 2u);
}

TEST(PresenceTest, FailedStartsAndTransportExceptionsDoNotEscape) {
  auto fake = new FakePing(); fake->throwStart = true;
  PresenceMonitor monitor{std::unique_ptr<PingTransport>(fake)};
  EXPECT_NO_THROW(monitor.tick(0, {{"a", "invalid"}}));
  fake->throwStart = false; fake->failStart = true;
  EXPECT_NO_THROW(monitor.tick(3000, {{"a", "invalid"}}));
  EXPECT_FALSE(monitor.online("a"));
}
