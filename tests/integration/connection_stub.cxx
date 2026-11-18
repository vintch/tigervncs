// SPDX-License-Identifier: GPL-2.0-or-later
// Linked only into the explicit vncviewer_manager_test target, never production.
#include "ConnectionStore.h"
#include <network/TcpSocket.h>
#include <cstdlib>
#include <fstream>

int runConnectionStub(const std::string& address) {
  const char* expectedAddress = std::getenv("VNC_TEST_ADDRESS");
  const char* expectedUser = std::getenv("VNC_USERNAME");
  const char* expectedPassword = std::getenv("VNC_PASSWORD");
  std::string host; int port;
  network::getHostAndPort(address.c_str(), &host, &port);
  ConnectionCredentials credentials;
  bool active = ConnectionStore::activeCredentials(host, port, credentials);
  Json::Value result(Json::objectValue);
  result["stubCalled"] = true;
  result["addressMatches"] = expectedAddress && address == expectedAddress;
  result["usernameMatches"] = expectedUser && credentials.username == expectedUser;
  result["passwordMatches"] = expectedPassword && credentials.hasPassword && credentials.password == expectedPassword;
  result["savedProfileUsed"] = active;
  bool passed = active && result["addressMatches"].asBool() &&
    result["usernameMatches"].asBool() && result["passwordMatches"].asBool();
  result["passed"] = passed;
  // Only booleans, no plaintext credentials in the test artifact.
  std::ofstream output(PortableConfig::executablePath() + ".stub-result");
  output << result;
  return passed ? 0 : 2;
}
