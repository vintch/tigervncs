// SPDX-License-Identifier: GPL-2.0-or-later
// Only modal decisions are stubbed. The actual socket, protocol handshake,
// watchdog, teardown and outer application loop are used by the test viewer.
#include "ConnectionStore.h"
#include <chrono>
#include <cstdlib>
#include <fstream>

namespace {
const auto started = std::chrono::steady_clock::now();
void event(Json::Value result) {
  result["elapsedMs"] = Json::Int64(std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now() - started).count());
  const char* path = std::getenv("VNC_TEST_EVENTS");
  if (!path) std::abort();
  Json::StreamWriterBuilder writer; writer["indentation"] = "";
  std::ofstream output(path, std::ios::app);
  output << Json::writeString(writer, result) << '\n';
}
}

int connectionErrorStub(const std::string& message) {
  static int count = 0;
  const char* retries = std::getenv("VNC_TEST_RETRIES");
  int retry = retries ? std::atoi(retries) : 0;
  Json::Value result;
  result["event"] = "connection-error";
  result["message"] = message;
  result["action"] = count++ < retry ? "Retry" : "Cancel";
  event(result);
  return result["action"] == "Retry" ? 1 : 0;
}

void returnedToMainWindowStub() {
  ConnectionCredentials credentials;
  Json::Value result;
  result["event"] = "main-window";
  result["credentialsCleared"] = !ConnectionStore::activeCredentials("127.0.0.1", 5900, credentials);
  event(result);
}
