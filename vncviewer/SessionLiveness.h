// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_SESSION_LIVENESS_H
#define TIGERVNCS_SESSION_LIVENESS_H
#include <cstdint>

// A quiet incremental RFB stream is valid. Probe it before declaring a stall.
// Incoming bytes extend a slow frame's deadline; wall-clock frame duration does not.
class SessionLiveness {
public:
  enum Action { Wait, Probe, Reconnect };
  void configure(int milliseconds) { timeout = milliseconds; }
  void start(int64_t now, uint64_t bytes) {
    progressAt = now; received = bytes;
    framePending = true; probing = false; firstFrame = false;
  }
  void progress(int64_t now, uint64_t bytes) {
    if (bytes != received) { received = bytes; progressAt = now; probing = false; }
  }
  void frameStarted() { framePending = true; }
  void frameCompleted(int64_t now) {
    progressAt = now; framePending = false; firstFrame = true; probing = false;
  }
  Action check(int64_t now) {
    if ((framePending || probing || !firstFrame) && now - progressAt >= timeout) return Reconnect;
    if (!framePending && !probing && now - progressAt >= 1000) {
      probing = true; progressAt = now; return Probe;
    }
    return Wait;
  }
private:
  int timeout = 4000;
  int64_t progressAt = 0;
  uint64_t received = 0;
  bool framePending = false, probing = false, firstFrame = false;
};
#endif
