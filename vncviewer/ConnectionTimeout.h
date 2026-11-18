// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_CONNECTION_TIMEOUT_H
#define TIGERVNCS_CONNECTION_TIMEOUT_H
#include <core/Timer.h>
#include <algorithm>

static const int connectionTimeoutMs = 4000;

// Human decisions do not consume the network establishment deadline.
class PauseConnectionTimeout {
public:
  explicit PauseConnectionTimeout(core::Timer& value) : timer(value), remaining(-1) {
    if (timer.isStarted()) {
      remaining = std::max(1, timer.getRemainingMs());
      timer.stop();
    }
  }
  ~PauseConnectionTimeout() { if (remaining >= 0) timer.start(remaining); }
private:
  core::Timer& timer;
  int remaining;
};
#endif
