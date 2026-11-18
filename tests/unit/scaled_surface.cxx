// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "Surface.h"

class TestSurface : public Surface {
public:
  TestSurface(int width, int height) : Surface(width, height) {}
  void paintHalves() {
    for (int y = 0; y < h; ++y)
      for (int x = 0; x < w; ++x)
        data[y*w+x] = x < w/2 ? RGBQUAD{0, 0, 240, 255} : RGBQUAD{240, 0, 0, 255};
  }
  RGBQUAD pixel(int x, int y) { GdiFlush(); return data[y*w+x]; }
};

TEST(ScaledSurface, NonIntegerScalingPreservesPositionAndColors)
{
  TestSurface source(101, 61);
  TestSurface destination(80, 50);
  source.paintHalves();
  destination.clear(17, 18, 19);
  source.drawScaled(&destination, 10, 7, 60, 30);
  auto left = destination.pixel(12, 9);
  auto right = destination.pixel(67, 35);
  auto outside = destination.pixel(2, 2);
  EXPECT_GT(left.rgbRed, 220); EXPECT_LT(left.rgbBlue, 20);
  EXPECT_GT(right.rgbBlue, 220); EXPECT_LT(right.rgbRed, 20);
  EXPECT_EQ(outside.rgbRed, 17); EXPECT_EQ(outside.rgbGreen, 18);
}

TEST(ScaledSurface, RedrawUsesUpdatedSourceAndCanEnlarge)
{
  TestSurface source(20, 10);
  TestSurface destination(200, 100);
  source.clear(200, 0, 0);
  source.drawScaled(&destination, 0, 0, 200, 100);
  EXPECT_EQ(destination.pixel(100, 50).rgbRed, 200);
  source.clear(0, 200, 0);
  source.drawScaled(&destination, 0, 0, 200, 100);
  EXPECT_EQ(destination.pixel(100, 50).rgbGreen, 200);
  EXPECT_EQ(destination.pixel(100, 50).rgbRed, 0);
}
