// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "SessionLiveness.h"

TEST(SessionLivenessTest, IdleDesktopIsProbedBeforeItCanTimeOut) {
  SessionLiveness session; session.start(0,0); session.frameCompleted(0);
  EXPECT_EQ(session.check(999), SessionLiveness::Wait);
  EXPECT_EQ(session.check(1000), SessionLiveness::Probe);
  EXPECT_EQ(session.check(4999), SessionLiveness::Wait);
  EXPECT_EQ(session.check(5000), SessionLiveness::Reconnect);
}
TEST(SessionLivenessTest, HealthyStaticRepliesKeepSessionAliveIndefinitely) {
  SessionLiveness session; session.start(0,0); session.frameCompleted(0);
  for (int tick = 1000; tick < 60000; tick += 1000) {
    EXPECT_EQ(session.check(tick), SessionLiveness::Probe);
    session.progress(tick, tick); session.frameCompleted(tick);
  }
}
TEST(SessionLivenessTest, SlowFrameMayExceedDeadlineWhileBytesKeepArriving) {
  SessionLiveness session; session.start(0,0); session.frameStarted();
  for (int time = 1000; time < 30000; time += 1000) {
    session.progress(time, time);
    EXPECT_EQ(session.check(time), SessionLiveness::Wait);
  }
  EXPECT_EQ(session.check(32999), SessionLiveness::Wait);
  EXPECT_EQ(session.check(33000), SessionLiveness::Reconnect);
}
TEST(SessionLivenessTest, ConfiguredSessionDeadlineIsIndependentOfConnectTimeout) {
  SessionLiveness session; session.configure(12000); session.start(0,0);
  EXPECT_EQ(session.check(4000), SessionLiveness::Wait);
  EXPECT_EQ(session.check(11999), SessionLiveness::Wait);
  EXPECT_EQ(session.check(12000), SessionLiveness::Reconnect);
}
