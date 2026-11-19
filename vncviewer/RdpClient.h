// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_RDP_CLIENT_H
#define TIGERVNCS_RDP_CLIENT_H
#include "ConnectionStore.h"
#include <atomic>
#include <memory>
namespace rdpClient {
struct Settings {
  std::string address, username, password; bool hasPassword=false;
  ~Settings();
};
Settings savedSettings(const Json::Value&,const std::string& id,const std::string& address);
std::string arguments(const Settings&);
struct Job {
  std::atomic<bool> done{false}; bool launched=false; unsigned long processId=0;
  std::string error; unsigned long exitCode=0;
};
// Production always launches the system mstsc. Test hooks live in test builds.
std::shared_ptr<Job> start(Settings);
#ifdef TIGERVNCS_RDP_TEST
std::shared_ptr<Job> startForTest(Settings,const std::wstring& executable);
#endif
}
#endif
