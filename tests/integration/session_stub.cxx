// SPDX-License-Identifier: GPL-2.0-or-later
// Only modal decisions are stubbed. The actual socket, protocol handshake,
// watchdog, teardown and outer application loop are used by the test viewer.
#include "ConnectionStore.h"
#include "PresenceMonitor.h"
#include "vncviewer.h"
#include <FL/Fl.H>
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

void sessionWindowStub(const char* kind, const void* window, uint32_t pixel, bool reused) {
  Json::Value result;
  result["event"] = kind; result["window"] = Json::UInt64(reinterpret_cast<uintptr_t>(window));
  result["pixel"] = Json::UInt(pixel); result["reused"] = reused;
  result["presenceSuspended"] = presenceSuspended();
  event(result);
  if (std::string(kind) == "frame" && reused) disconnect();
  if (std::string(kind) == "frame" && !reused && std::getenv("VNC_TEST_CLOSE_IDLE"))
    Fl::add_timeout(6.2, [](void*) { disconnect(); });
}

// UI smoke mode shows Options without a disabled owner window, allowing the
// same dialog to be inspected by Windows accessibility tools.
#include "OptionsDialog.h"
#include <FL/Fl.H>
bool optionsUiStub() {
  if (!std::getenv("VNC_TEST_OPTIONS_UI")) return false;
  OptionsDialog::showDialog();
  while (Fl::first_window()) Fl::wait();
  return true;
}
