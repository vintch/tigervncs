// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_PORTABLE_CONFIG_H
#define TIGERVNCS_PORTABLE_CONFIG_H
#include <string>
#include <json/json.h>

// UTF-8 filenames; writes are atomic and never fall back to another directory.
class PortableConfig {
public:
  explicit PortableConfig(const std::string& filename) : path(filename) {}
  Json::Value read() const;
  void write(const Json::Value& value) const;
  static std::string executablePath();
private:
  std::string path;
};
#endif
