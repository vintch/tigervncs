// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "ScaleGeometry.h"

TEST(ScaleGeometry, LetterboxAndPillarbox)
{
  auto a = fitDesktop(1600, 900, 800, 600, true);
  EXPECT_EQ(a.x, 800); EXPECT_EQ(a.y, 450);
  auto b = fitDesktop(1600, 900, 1800, 600, true);
  EXPECT_EQ(b.x, 1066); EXPECT_EQ(b.y, 600);
  auto c = fitDesktop(640, 480, 1280, 960, true);
  EXPECT_EQ(c.x, 1280); EXPECT_EQ(c.y, 960);
  auto d = fitDesktop(1600, 900, 800, 600, false);
  EXPECT_EQ(d.x, 1600); EXPECT_EQ(d.y, 900);
}

TEST(ScaleGeometry, CapturedDragsAndTinyWindows)
{
  auto a = windowToDesktop({400, 225}, 800, 450, 1600, 900);
  EXPECT_EQ(a.x, 800); EXPECT_EQ(a.y, 450);
  auto b = windowToDesktop({-500, 10000}, 800, 450, 1600, 900);
  EXPECT_EQ(b.x, 0); EXPECT_EQ(b.y, 898);
  auto c = fitDesktop(5120, 2880, 1, 1, true);
  EXPECT_EQ(c.x, 1); EXPECT_EQ(c.y, 1);
  auto d = windowToDesktop({1, -1}, 1, 1, 5120, 2880);
  EXPECT_EQ(d.x, 0); EXPECT_EQ(d.y, 0);
}

TEST(ScaleGeometry, FitsArbitrarySizesAndBoundsPointer)
{
  for (int w : {1, 2, 127, 799, 1920, 65535}) {
    for (int h : {1, 101, 600, 1440, 65535}) {
      auto size = fitDesktop(5120, 2880, w, h, true);
      ASSERT_GT(size.x, 0); ASSERT_GT(size.y, 0);
      ASSERT_LE(size.x, w); ASSERT_LE(size.y, h);
      EXPECT_TRUE(size.x == w || size.y == h);
      for (auto pos : {core::Point{-10000, -10000}, core::Point{w/2, h/2},
                       core::Point{655350, 655350}}) {
        auto remote = windowToDesktop(pos, size.x, size.y, 5120, 2880);
        EXPECT_GE(remote.x, 0); EXPECT_LT(remote.x, 5120);
        EXPECT_GE(remote.y, 0); EXPECT_LT(remote.y, 2880);
      }
    }
  }
}
