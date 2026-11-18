// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "ConnectionTimeout.h"
#include <chrono>
#include <thread>

namespace {
struct Watchdog {
  core::MethodTimer<Watchdog> timer{this, &Watchdog::expired};
  int calls = 0;
  void expired(core::Timer*) { ++calls; }
};
}

TEST(ConnectionTimeoutTest, UserDecisionPausesDeadlineAndResumesRemainingTime) {
  Watchdog watchdog;
  watchdog.timer.start(30);
  {
    PauseConnectionTimeout decision(watchdog.timer);
    std::this_thread::sleep_for(std::chrono::milliseconds(70));
    core::Timer::checkTimeouts();
    EXPECT_EQ(watchdog.calls, 0);
    EXPECT_FALSE(watchdog.timer.isStarted());
  }
  EXPECT_TRUE(watchdog.timer.isStarted());
  std::this_thread::sleep_for(std::chrono::milliseconds(70));
  core::Timer::checkTimeouts();
  EXPECT_EQ(watchdog.calls, 1);
}

TEST(ConnectionTimeoutTest, EstablishedSessionDoesNotRestartStoppedDeadline) {
  Watchdog watchdog;
  { PauseConnectionTimeout inactive(watchdog.timer); }
  EXPECT_FALSE(watchdog.timer.isStarted());
  watchdog.timer.start(20);
  watchdog.timer.stop();
  { PauseConnectionTimeout established(watchdog.timer); }
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  core::Timer::checkTimeouts();
  EXPECT_EQ(watchdog.calls, 0);
}
