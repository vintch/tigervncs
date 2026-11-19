// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_POWER_TOOLS_H
#define TIGERVNCS_POWER_TOOLS_H
#include <core/Configuration.h>
#include <json/json.h>
#include <atomic>
#include <memory>
#include <string>
namespace powerTools {
extern core::StringParameter plinkExecutable;
enum class Action { PowerOff, Reboot, ForcePowerOff, ForceReboot };
const char* label(Action action);
bool actionForLabel(const std::string& label, Action& action);
bool available();
bool menuEnabled(const Json::Value& computer, bool plinkPresent, bool busy = false);
bool executableAvailable(const std::string& path);
std::string sshHost(const std::string& address);
std::string fingerprintFromOutput(const std::string& output);
std::string remoteCommand(Action action, const std::string& token);
struct Request {
  std::string host, username, password;
  Action action = Action::PowerOff;
  ~Request();
};
// No GUI, logs, plaintext files, or password-bearing process arguments.
bool execute(const std::string& executable, const Request& request, unsigned timeoutMs = 15000);
struct Job { std::atomic<bool> done{false}; bool success = false; };
std::shared_ptr<Job> start(Json::Value document, const std::string& computerId, Action action);
}
#endif
