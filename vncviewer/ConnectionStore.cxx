// SPDX-License-Identifier: GPL-2.0-or-later
#include "ConnectionStore.h"
#include <network/TcpSocket.h>
#include <core/string.h>
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <stdexcept>

std::string ConnectionStore::activeId, ConnectionStore::activeAddress, ConnectionStore::activePath;
std::string ConnectionStore::activeMode = "current-screen";
bool ConnectionStore::activePasswordAllowed = true;

namespace {
std::string trim(const std::string& value) {
  auto a = value.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  return value.substr(a, value.find_last_not_of(" \t\r\n") - a + 1);
}
void text(const std::string& value, const char* field, size_t maximum, bool empty = false) {
  if ((!empty && value.empty()) || value.size() > maximum || !core::isValidUTF8(value.c_str()) ||
      std::any_of(value.begin(), value.end(), [](unsigned char c) { return c < 32; }))
    throw std::runtime_error(std::string("Invalid ") + field);
}
int indexOf(const Json::Value& array, const std::string& id) {
  for (Json::ArrayIndex i = 0; i < array.size(); ++i)
    if (array[i]["id"].asString() == id) return int(i);
  return -1;
}
void validate(Json::Value& document) {
  for (auto collection : {"connections", "folders"}) {
    if (document[collection].isNull()) document[collection] = Json::Value(Json::arrayValue);
    if (!document[collection].isArray() || document[collection].size() > 10000)
      throw std::runtime_error(std::string("Invalid saved ") + collection);
  }
  if (document["manager"].isNull()) document["manager"] = Json::Value(Json::objectValue);
  if (!document["manager"].isObject()) throw std::runtime_error("Invalid manager settings");
  if (!document["manager"]["expanded"].isNull() && !document["manager"]["expanded"].isBool())
    throw std::runtime_error("Invalid manager expansion state");
  if (!document["manager"]["order"].isNull()) {
    const auto& order = document["manager"]["order"];
    if (!order.isObject()) throw std::runtime_error("Invalid sibling order");
    for (const auto& key : order.getMemberNames()) {
      if (!order[key].isArray() || order[key].size() > 20000) throw std::runtime_error("Invalid sibling order");
      for (const auto& id : order[key])
        if (!id.isString()) throw std::runtime_error("Invalid sibling identifier");
    }
  }
  std::set<std::string> ids;
  std::map<std::string, std::string> parents;
  for (const auto& folder : document["folders"]) {
    if (!folder.isObject() || !folder["id"].isString() || !folder["name"].isString() ||
        !folder["parentId"].isString()) throw std::runtime_error("Invalid folder entry");
    auto id = folder["id"].asString();
    text(id, "folder identifier", 64);
    text(folder["name"].asString(), "folder name", 256);
    if (!folder["expanded"].isNull() && !folder["expanded"].isBool())
      throw std::runtime_error("Invalid folder expansion state");
    if (!ids.insert(id).second) throw std::runtime_error("Duplicate saved identifier");
    parents[id] = folder["parentId"].asString();
  }
  for (const auto& folder : parents) {
    std::set<std::string> seen;
    std::string current = folder.first;
    while (!current.empty()) {
      auto parent = parents.find(current);
      if (parent == parents.end()) throw std::runtime_error("Folder parent does not exist");
      if (!seen.insert(current).second) throw std::runtime_error("A folder cannot contain itself");
      if (seen.size() > 128) throw std::runtime_error("Folder nesting exceeds 128 levels");
      current = parent->second;
    }
  }
  for (const auto& connection : document["connections"]) {
    if (!connection.isObject() || !connection["id"].isString() || !connection["name"].isString() ||
        !connection["address"].isString() || !connection["username"].isString() ||
        !connection["folderId"].isString()) throw std::runtime_error("Invalid computer entry");
    auto id = connection["id"].asString();
    text(id, "computer identifier", 64);
    text(connection["name"].asString(), "computer name", 256);
    text(connection["address"].asString(), "server address", 2048);
    text(connection["username"].asString(), "username", 1024, true);
    if (!connection["sessionMode"].isNull() && connection["sessionMode"] != "current-screen" &&
        connection["sessionMode"] != "user-session") throw std::runtime_error("Invalid connection session mode");
    if (!ids.insert(id).second) throw std::runtime_error("Duplicate saved identifier");
    auto parent = connection["folderId"].asString();
    if (!parent.empty() && !parents.count(parent)) throw std::runtime_error("Computer folder does not exist");
    if (!connection["password"].isNull() && !connection["password"].isObject())
      throw std::runtime_error("Invalid saved password record");
  }
}
}

Json::Value ConnectionStore::read() const {
  auto document = file.read();
  validate(document);
  return document;
}
void ConnectionStore::setExpanded(bool expanded) {
  auto document = read();
  document["manager"]["expanded"] = expanded;
  file.write(document);
}
void ConnectionStore::setFolderExpanded(const std::string& id, bool expanded) {
  auto document = read();
  int index = indexOf(document["folders"], id);
  if (index < 0) throw std::runtime_error("Folder no longer exists");
  document["folders"][index]["expanded"] = expanded;
  file.write(document);
}
std::vector<std::string> ConnectionStore::children(const Json::Value& document, const std::string& parent) {
  std::vector<std::string> fallback, result;
  std::set<std::string> remaining;
  for (const auto& folder : document["folders"])
    if (folder["parentId"].asString() == parent) fallback.push_back(folder["id"].asString());
  for (const auto& computer : document["connections"])
    if (computer["folderId"].asString() == parent) fallback.push_back(computer["id"].asString());
  remaining.insert(fallback.begin(), fallback.end());
  for (const auto& id : document["manager"]["order"][parent])
    if (remaining.erase(id.asString())) result.push_back(id.asString());
  for (const auto& id : fallback) if (remaining.erase(id)) result.push_back(id);
  return result;
}
bool ConnectionStore::canMove(const Json::Value& document, const std::string& id, bool folder, int direction) {
  if (direction != -1 && direction != 1) return false;
  auto collection = folder ? "folders" : "connections";
  int index = indexOf(document[collection], id);
  if (index < 0) return false;
  auto siblings = children(document, document[collection][index][folder ? "parentId" : "folderId"].asString());
  auto position = std::find(siblings.begin(), siblings.end(), id);
  if (position == siblings.end()) return false;
  return direction < 0 ? position != siblings.begin() : position + 1 != siblings.end();
}
bool ConnectionStore::move(const std::string& id, bool folder, int direction) {
  auto document = read();
  if (!canMove(document, id, folder, direction)) return false;
  auto collection = folder ? "folders" : "connections";
  auto parent = document[collection][indexOf(document[collection], id)][folder ? "parentId" : "folderId"].asString();
  auto siblings = children(document, parent);
  auto position = std::find(siblings.begin(), siblings.end(), id);
  std::iter_swap(position, position + direction);
  document["manager"]["order"][parent] = Json::Value(Json::arrayValue);
  for (const auto& sibling : siblings) document["manager"]["order"][parent].append(sibling);
  file.write(document);
  return true;
}
std::string ConnectionStore::saveFolder(const std::string& id, const std::string& name,
                                        const std::string& parent) {
  auto document = read();
  int index = id.empty() ? -1 : indexOf(document["folders"], id);
  auto siblings = children(document, parent);
  if (!id.empty() && index < 0) throw std::runtime_error("Folder no longer exists");
  Json::Value folder = index < 0 ? Json::Value(Json::objectValue) : document["folders"][index];
  std::string result = id.empty() ? CredentialVault::newId() : id;
  folder["id"] = result; folder["name"] = trim(name); folder["parentId"] = parent;
  if (index < 0) document["folders"].append(folder); else document["folders"][index] = folder;
  validate(document);
  if (std::find(siblings.begin(), siblings.end(), result) == siblings.end()) {
    siblings.push_back(result);
    document["manager"]["order"][parent] = Json::Value(Json::arrayValue);
    for (const auto& sibling : siblings) document["manager"]["order"][parent].append(sibling);
  }
  file.write(document);
  return result;
}
std::string ConnectionStore::saveConnection(const std::string& id, const std::string& name,
  const std::string& address, const std::string& username, const std::string& folder,
  PasswordChange change, const std::string& password, const std::string& sessionMode) {
  auto document = read();
  int index = id.empty() ? -1 : indexOf(document["connections"], id);
  auto siblings = children(document, folder);
  if (!id.empty() && index < 0) throw std::runtime_error("Computer entry no longer exists");
  Json::Value entry = index < 0 ? Json::Value(Json::objectValue) : document["connections"][index];
  std::string result = id.empty() ? CredentialVault::newId() : id;
  entry["id"] = result; entry["name"] = trim(name); entry["address"] = trim(address);
  entry["username"] = username; entry["folderId"] = folder;
  if (!sessionMode.empty()) entry["sessionMode"] = sessionMode;
  else if (entry["sessionMode"].isNull()) entry["sessionMode"] = "current-screen";
  std::string host; int port;
  network::getHostAndPort(entry["address"].asString().c_str(), &host, &port);
  if (host.empty() || port < 1 || port > 65535) throw std::runtime_error("Invalid server address or port");
  // Validate metadata before generating or changing any credential key.
  if (index < 0) document["connections"].append(entry); else document["connections"][index] = entry;
  validate(document);
  if (std::find(siblings.begin(), siblings.end(), result) == siblings.end()) {
    siblings.push_back(result);
    document["manager"]["order"][folder] = Json::Value(Json::arrayValue);
    for (const auto& sibling : siblings) document["manager"]["order"][folder].append(sibling);
  }
  auto position = index < 0 ? document["connections"].size() - 1 : Json::ArrayIndex(index);
  if (change == SetPassword)
    document["connections"][position]["password"] = CredentialVault::encrypt(document, result, password);
  else if (change == ForgetPassword)
    document["connections"][position].removeMember("password");
  if (document["connections"][position]["sessionMode"] == "user-session" &&
      (username.empty() || document["connections"][position]["password"].isNull()))
    throw std::runtime_error("User session requires a saved username and password.");
  file.write(document);
  return result;
}
void ConnectionStore::remove(const std::string& id, bool folder) {
  auto document = read();
  auto collection = folder ? "folders" : "connections";
  int index = indexOf(document[collection], id);
  if (index < 0) throw std::runtime_error("Entry no longer exists");
  if (folder) {
    for (const auto& child : document["folders"])
      if (child["parentId"].asString() == id) throw std::runtime_error("Move or delete the contents of this folder first");
    for (const auto& child : document["connections"])
      if (child["folderId"].asString() == id) throw std::runtime_error("Move or delete the contents of this folder first");
  }
  document[collection].removeIndex(Json::ArrayIndex(index), nullptr);
  if (folder) document["manager"]["order"].removeMember(id);
  for (const auto& parent : document["manager"]["order"].getMemberNames()) {
    auto siblings = children(document, parent);
    document["manager"]["order"][parent] = Json::Value(Json::arrayValue);
    for (const auto& sibling : siblings) document["manager"]["order"][parent].append(sibling);
  }
  file.write(document);
}
Json::Value ConnectionStore::connection(const std::string& id) const {
  auto document = read();
  int index = indexOf(document["connections"], id);
  if (index < 0) throw std::runtime_error("Computer entry no longer exists");
  return document["connections"][index];
}
std::string ConnectionStore::folderPath(const Json::Value& document, const std::string& id) {
  std::string result, current = id;
  std::set<std::string> seen;
  while (!current.empty()) {
    if (!seen.insert(current).second) throw std::runtime_error("Invalid folder hierarchy");
    int index = indexOf(document["folders"], current);
    if (index < 0) throw std::runtime_error("Folder no longer exists");
    auto folder = document["folders"][index];
    result = folder["name"].asString() + (result.empty() ? "" : " / " + result);
    current = folder["parentId"].asString();
  }
  return result;
}
bool ConnectionStore::sameEndpoint(const std::string& address, const std::string& host, int port) {
  std::string expected; int expectedPort;
  try { network::getHostAndPort(address.c_str(), &expected, &expectedPort); }
  catch (...) { return false; }
  auto lower = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return value;
  };
  return expectedPort == port && lower(expected) == lower(host);
}
void ConnectionStore::activate(const std::string& id, const std::string& address) {
  clearActive(); activeId = id; activeAddress = address; activePath = PortableConfig::executablePath();
}
void ConnectionStore::clearActive() { activeId.clear(); activeAddress.clear(); activePath.clear(); activeMode = "current-screen"; activePasswordAllowed = true; }
void ConnectionStore::rejectActivePassword() { activePasswordAllowed = false; }
bool ConnectionStore::prepareConnection(const std::string& id, const std::string& address,
                                         ConnectionCredentials& result, const std::string& overrideMode) const {
  clearActive();
  CredentialVault::erase(result.password); result.username.clear(); result.hasPassword = false; result.sessionMode = "current-screen";
  if (id.empty()) return false;
  auto entry = connection(id);
  if (!overrideMode.empty() && overrideMode != "current-screen" && overrideMode != "user-session")
    throw std::runtime_error("Invalid connection session mode");
  std::string host; int port;
  network::getHostAndPort(address.c_str(), &host, &port);
  if (!sameEndpoint(entry["address"].asString(), host, port)) return false;
  activeId = id; activeAddress = address; activePath = path;
  activeMode = overrideMode.empty() ? (entry["sessionMode"] == "user-session" ? "user-session" : "current-screen") : overrideMode;
  try {
    bool active = activeCredentials(host, port, result);
    if (activeMode == "user-session" && (!active || !result.hasPassword || result.username.empty()))
      throw std::runtime_error("User session requires a saved username and password. Edit this computer first.");
    return active;
  }
  catch (...) { clearActive(); throw; }
}
bool ConnectionStore::activeCredentials(const std::string& host, int port, ConnectionCredentials& result) {
  CredentialVault::erase(result.password); result.username.clear(); result.hasPassword = false; result.sessionMode = "current-screen";
  if (activeId.empty() || !sameEndpoint(activeAddress, host, port)) return false;
  ConnectionStore store(activePath);
  auto document = store.read();
  int index = indexOf(document["connections"], activeId);
  if (index < 0) return false;
  const auto& entry = document["connections"][index];
  if (!sameEndpoint(entry["address"].asString(), host, port)) return false;
  result.username = entry["username"].asString();
  result.sessionMode = activeMode;
  result.hasPassword = activePasswordAllowed && !entry["password"].isNull();
  if (result.hasPassword)
    result.password = CredentialVault::decrypt(document, activeId, entry["password"]);
  return true;
}
