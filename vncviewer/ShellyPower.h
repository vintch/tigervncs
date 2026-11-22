// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_SHELLY_POWER_H
#define TIGERVNCS_SHELLY_POWER_H
#include <core/Configuration.h>
#include <json/json.h>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
namespace shellyPower {
extern core::IntParameter delaySeconds;
struct Credentials { std::string address, username, password; bool gen2 = false; ~Credentials(); };
bool configured(const Json::Value& computer);
Credentials credentials(const Json::Value& document, const std::string& id);
struct Address { std::string host; unsigned short port = 80; };
Address parseAddress(const std::string& value);
class Transport {
public:
  virtual ~Transport() {}
  virtual bool check(const Credentials&) { return false; }
  virtual bool setPower(const Credentials&, bool on, int flipBackSeconds) = 0;
};
std::shared_ptr<Transport> transport();
enum class Phase { SwitchingOff, Waiting, Restoring, Done };
struct Cycle {
  std::atomic<Phase> phase{Phase::SwitchingOff};
  std::atomic<bool> cancelled{false};
  std::atomic<int64_t> waitStarted{0};
  bool offSucceeded = false, onSucceeded = false;
  std::mutex mutex; std::condition_variable wake;
  void cancel() {
    { std::lock_guard<std::mutex> lock(mutex); cancelled.store(true); }
    wake.notify_all();
  }
};
int64_t clockMs();
std::shared_ptr<Cycle> start(Credentials, int seconds, const std::shared_ptr<Transport>& client);
}
#endif
