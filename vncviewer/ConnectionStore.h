// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_CONNECTION_STORE_H
#define TIGERVNCS_CONNECTION_STORE_H
#include "PortableConfig.h"
#include "CredentialVault.h"
#include <vector>

struct ConnectionCredentials {
  std::string username, password;
  bool hasPassword = false;
  std::string sessionMode = "current-screen";
  ~ConnectionCredentials() { CredentialVault::erase(password); }
};

class ConnectionStore {
public:
  enum PasswordChange { KeepPassword, SetPassword, ForgetPassword };
  explicit ConnectionStore(const std::string& filename = PortableConfig::executablePath()) : file(filename), path(filename) {}
  Json::Value read() const;
  void setExpanded(bool expanded);
  void setFolderExpanded(const std::string& id, bool expanded);
  bool move(const std::string& id, bool folder, int direction);
  static std::vector<std::string> children(const Json::Value& document, const std::string& parent);
  static bool canMove(const Json::Value& document, const std::string& id, bool folder, int direction);
  std::string saveFolder(const std::string& id, const std::string& name, const std::string& parent);
  std::string saveConnection(const std::string& id, const std::string& name,
    const std::string& address, const std::string& username, const std::string& folder,
    PasswordChange change, const std::string& password, const std::string& sessionMode = "",
    const Json::Value& vpn = Json::Value(), const Json::Value& powerOn = Json::Value(),
    PasswordChange shellyChange = KeepPassword, const std::string& shellyPassword = "",
    const std::string& connectionType = "");
  void remove(const std::string& id, bool folder);
  Json::Value connection(const std::string& id) const;
  bool prepareConnection(const std::string& id, const std::string& address, ConnectionCredentials& result,
                         const std::string& overrideMode = "") const;
  static std::string folderPath(const Json::Value& document, const std::string& id);
  static bool sameEndpoint(const std::string& address, const std::string& host, int port);
  static void activate(const std::string& id, const std::string& address);
  static bool activeCredentials(const std::string& host, int port, ConnectionCredentials& result);
  static void clearActive();
  static void rejectActivePassword();
private:
  PortableConfig file;
  std::string path;
  static std::string activeId, activeAddress, activePath, activeMode;
  static bool activePasswordAllowed;
};
#endif
