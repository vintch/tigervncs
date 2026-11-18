// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_SCALE_GEOMETRY_H
#define TIGERVNCS_SCALE_GEOMETRY_H

#include <algorithm>
#include <cstdint>
#include <core/Rect.h>

inline core::Point fitDesktop(int desktopWidth, int desktopHeight,
                              int windowWidth, int windowHeight, bool fit)
{
  desktopWidth = std::max(1, desktopWidth);
  desktopHeight = std::max(1, desktopHeight);
  if (!fit)
    return {desktopWidth, desktopHeight};
  windowWidth = std::max(1, windowWidth);
  windowHeight = std::max(1, windowHeight);
  if (int64_t(windowWidth) * desktopHeight <= int64_t(windowHeight) * desktopWidth)
    return {windowWidth, std::max(1, int(int64_t(desktopHeight) * windowWidth / desktopWidth))};
  return {std::max(1, int(int64_t(desktopWidth) * windowHeight / desktopHeight)), windowHeight};
}

inline core::Point windowToDesktop(const core::Point& pos, int width, int height,
                                   int desktopWidth, int desktopHeight)
{
  // Clamp before multiplication: captured drags can be outside the viewport.
  int x = std::max(0, std::min(pos.x, width - 1));
  int y = std::max(0, std::min(pos.y, height - 1));
  return {int(int64_t(x) * desktopWidth / std::max(1, width)),
          int(int64_t(y) * desktopHeight / std::max(1, height))};
}
#endif
