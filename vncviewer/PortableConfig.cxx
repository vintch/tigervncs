// SPDX-License-Identifier: GPL-2.0-or-later
#include "PortableConfig.h"
#include <core/string.h>
#include <FL/fl_utf8.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>
#ifdef WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

namespace {
void validate(const Json::Value& value)
{
  if (!value.isObject() || !value["schemaVersion"].isInt() ||
      value["schemaVersion"].asInt() != 1 || !value["viewer"].isObject())
    throw std::runtime_error("Unsupported or invalid tigervncs.json format");
}
}

Json::Value PortableConfig::read() const
{
  std::unique_ptr<FILE, decltype(&fclose)> file(fl_fopen(path.c_str(), "rb"), fclose);
  if (!file) {
    if (errno != ENOENT)
      throw std::runtime_error("Cannot read " + path + ": " + strerror(errno));
    Json::Value value(Json::objectValue);
    value["schemaVersion"] = 1;
    value["viewer"] = Json::Value(Json::objectValue);
    value["connections"] = Json::Value(Json::arrayValue);
    return value;
  }
  std::string text;
  char buffer[4096];
  size_t count;
  while ((count = fread(buffer, 1, sizeof(buffer), file.get())) != 0) {
    text.append(buffer, count);
    if (text.size() > 16 * 1024 * 1024)
      throw std::runtime_error("Configuration exceeds 16 MiB: " + path);
  }
  if (ferror(file.get()))
    throw std::runtime_error("Cannot read configuration: " + path);
  Json::CharReaderBuilder builder;
  builder["rejectDupKeys"] = true;
  builder["failIfExtra"] = true;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  Json::Value value;
  std::string error;
  if (!reader->parse(text.data(), text.data() + text.size(), &value, &error))
    throw std::runtime_error("Invalid JSON in " + path + ": " + error);
  validate(value);
  return value;
}

void PortableConfig::write(const Json::Value& value) const
{
  validate(value);
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "  ";
  std::string text = Json::writeString(builder, value) + "\n";
#ifdef WIN32
  std::string temp = path + ".tmp." + std::to_string(GetCurrentProcessId());
#else
  std::string temp = path + ".tmp." + std::to_string(getpid());
#endif
  FILE* file = fl_fopen(temp.c_str(), "wb");
  if (!file)
    throw std::runtime_error("Cannot write settings beside the executable: " + path);
  bool ok = fwrite(text.data(), 1, text.size(), file) == text.size();
  ok = fflush(file) == 0 && ok;
#ifdef WIN32
  ok = _commit(_fileno(file)) == 0 && ok;
#else
  ok = fsync(fileno(file)) == 0 && ok;
#endif
  ok = fclose(file) == 0 && ok;
#ifdef WIN32
  std::wstring wideTemp = core::utf8ToUTF16(temp.c_str());
  std::wstring widePath = core::utf8ToUTF16(path.c_str());
  if (ok)
    ok = MoveFileExW(wideTemp.c_str(), widePath.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
  if (!ok)
    DeleteFileW(wideTemp.c_str());
#else
  if (ok)
    ok = rename(temp.c_str(), path.c_str()) == 0;
  if (!ok)
    unlink(temp.c_str());
#endif
  if (!ok)
    throw std::runtime_error("Cannot replace settings beside the executable: " + path);
}

std::string PortableConfig::executablePath()
{
  std::string executable;
#ifdef WIN32
  std::vector<wchar_t> buffer(32768);
  DWORD size = GetModuleFileNameW(nullptr, buffer.data(), DWORD(buffer.size()));
  if (size == 0 || size >= buffer.size())
    throw std::runtime_error("Cannot locate the executable for portable settings");
  executable = core::utf16ToUTF8(buffer.data(), size);
#else
  char buffer[32768];
#ifdef __APPLE__
  uint32_t size = sizeof(buffer);
  if (_NSGetExecutablePath(buffer, &size) != 0)
    throw std::runtime_error("Cannot locate the executable");
  executable = buffer;
#else
  ssize_t size = readlink("/proc/self/exe", buffer, sizeof(buffer));
  if (size <= 0 || size == sizeof(buffer))
    throw std::runtime_error("Cannot locate the executable");
  executable.assign(buffer, size);
#endif
#endif
  return executable.substr(0, executable.find_last_of("/\\") + 1) + "tigervncs.json";
}
