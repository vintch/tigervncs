// SPDX-License-Identifier: GPL-2.0-or-later
// Executes only against the caller's isolated fixture; not distributed.
#include "PowerTools.h"
#include "PortableConfig.h"
#include <chrono>
#include <thread>
#include <iostream>
int main(int argc, char** argv) {
  if (argc != 4) return 2;
  try {
    powerTools::Action action;
    if (!powerTools::actionForLabel(argv[3], action)) return 2;
    auto document = PortableConfig(argv[1]).read();
    powerTools::plinkExecutable.setParam(document["viewer"]["PlinkExecutable"].asCString());
    auto job = powerTools::start(std::move(document), argv[2], action);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(17);
    while (!job->done.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    bool success = job->done.load(std::memory_order_acquire) && job->success;
    std::cout << (success ? "Command acknowledged\n" : "Command not acknowledged\n");
    return success ? 0 : 1;
  } catch (...) { return 1; }
}
