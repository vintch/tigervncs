// SPDX-License-Identifier: GPL-2.0-or-later
// Explicit diagnostic: authenticate with an encrypted saved profile and decode
// one framebuffer, without saving pixels or sending keyboard/pointer input.
#include "ConnectionStore.h"
#include <rfb/CConnection.h>
#include <rfb/PixelBuffer.h>
#include <rfb/encodings.h>
#include <network/TcpSocket.h>
#include <rdr/MemOutStream.h>
#include <rdr/InStream.h>
#include <rdr/OutStream.h>
#include <rdr/FdInStream.h>
#include <rdr/FdOutStream.h>
#include <chrono>
#include <thread>
#include <iostream>
#include <core/Logger_stdio.h>
#include <core/LogWriter.h>

class Probe : public rfb::CConnection {
public:
  ConnectionCredentials credentials;
  bool gotFrame = false;
  bool gotPixels = false;
  Probe() { supportsDesktopResize = true; setShared(true); }
  void getUserPasswd(std::string* user, std::string* password) override {
    if (user) *user = credentials.username;
    *password = credentials.password;
  }
  bool verifyCertificate(unsigned int, const uint8_t*, size_t) override { return false; }
  bool verifyHostKey(const uint8_t*, size_t, const char*) override { return false; }
  void initDone() override {
    setFramebuffer(new rfb::ManagedPixelBuffer(server.pf(), server.width(), server.height()));
    setPreferredEncoding(rfb::encodingZRLE);
  }
  bool dataRect(const core::Rect& rectangle, int encoding) override {
    bool ready = rfb::CConnection::dataRect(rectangle, encoding);
    if (ready && encoding >= 0 && rectangle.area()) gotPixels = true;
    return ready;
  }
  void framebufferUpdateEnd() override {
    rfb::CConnection::framebufferUpdateEnd(); gotFrame = gotPixels;
  }
  void bell() override {}
};

int main(int argc, char** argv) {
  if (argc != 4 && argc != 5) return 2;
  try {
    core::initStdIOLoggers(); core::LogWriter::setLogParams("*:stderr:30");
    ConnectionStore store(argv[1]);
    auto record = store.connection(argv[2]);
    Probe probe;
    auto address = record["address"].asString();
    std::string requested = argv[3];
    bool actual = requested == "current-screen" || requested == "user-session";
    store.prepareConnection(argv[2], address, probe.credentials, actual ? requested : "");
    if (actual) probe.setAppleSessionMode(requested == "user-session" ? 2 : 1);
    if (!probe.credentials.hasPassword) throw std::runtime_error("Saved credentials are required");
    std::string host; int port; network::getHostAndPort(address.c_str(), &host, &port);
    network::TcpSocket socket(host.c_str(), port, 4000);
    rdr::MemOutStream output;
    probe.setStreams(&socket.inStream(), &output); probe.initialiseProtocol();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    auto wait = [&] {
      if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("Probe timeout");
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    };
    if (actual) {
      while (!probe.gotFrame) {
        probe.processMsg();
        if (output.length()) {
          socket.outStream().writeBytes(output.data(), output.length()); socket.outStream().flush(); output.clear();
        }
        wait();
      }
      std::cout << "mode=" << requested << " sessionGranted=true framebufferDecoded=true width="
                << probe.server.width() << " height=" << probe.server.height() << '\n';
      return 0;
    }
    while (probe.state() != rfb::CConnection::RFBSTATE_INITIALISATION) {
      probe.processMsg();
      if (output.length()) {
        std::vector<uint8_t> bytes(output.data(), output.data() + output.length());
        if (bytes.size() == 12 && bytes[0] == 'R') std::memcpy(bytes.data(), "RFB 003.889\n", 12);
        if (probe.state() == rfb::CConnection::RFBSTATE_INITIALISATION) bytes.back() = std::strtoul(argv[3], nullptr, 0);
        socket.outStream().writeBytes(bytes.data(), bytes.size()); socket.outStream().flush(); output.clear();
      }
      wait();
    }
    auto& input = socket.inStream();
    while (!input.hasData(24)) wait();
    int width = input.readU16(), height = input.readU16(); input.skip(16);
    auto length = input.readU32();
    if (length > 65536) throw std::runtime_error("Excessive name length");
    while (!input.hasData(length)) wait();
    std::vector<uint8_t> name(length); input.readBytes(name.data(), name.size());
    std::cout << "dimensions=" << width << 'x' << height << " nameBytes=" << length << " prefix=";
    for (size_t index = 0; index < std::min<size_t>(22, name.size()); ++index) std::cout << std::hex << int(name[index]) << ' ';
    std::cout << std::dec << '\n';
    if (width == 0 || height == 0 || (name.size() >= 22 && name[0] == 0 && (name[5] & 4))) {
      while (!input.hasData(2)) wait();
      auto size = input.readU16();
      if (size < 10 || size > 4096) throw std::runtime_error("Invalid session info size");
      while (!input.hasData(size)) wait();
      auto version = input.readU16(); auto allowed = input.readU32(); input.skip(4);
      std::vector<uint8_t> user(size - 10); input.readBytes(user.data(), user.size());
      std::cout << "sessionInfoVersion=" << version << " allowedCommands=" << allowed << '\n';
      if (argc == 5) {
        auto& wire = socket.outStream();
        wire.writeU16(72); wire.writeU16(1); wire.writeU32(0);
        wire.writeU8(std::atoi(argv[4])); wire.writeU8(0);
        uint8_t username[64]{};
        std::memcpy(username, user.data(), std::min<size_t>(63, user.size()));
        wire.writeBytes(username, 64); wire.flush();
        while (true) {
          while (!input.hasData(2)) wait();
          auto resultLength = input.readU16();
          if (resultLength < 6 || resultLength > 4096) throw std::runtime_error("Invalid session result");
          while (!input.hasData(resultLength)) wait();
          auto resultVersion = input.readU16(); auto status = input.readU32(); input.skip(resultLength - 6);
          std::cout << "sessionResultVersion=" << resultVersion << " status=" << status << '\n';
          if (status == 0 || status == 4) break;
          if (status != 2 && status != 3) throw std::runtime_error("Session denied");
        }
        // Request only standard lossless RFB encodings, without input events.
        wire.writeU8(0); wire.pad(3);
        rfb::PixelFormat pf(32, 24, false, true, 255,255,255,16,8,0); pf.write(&wire);
        wire.writeU8(2); wire.writeU8(0); wire.writeU16(3);
        wire.writeU32(16); wire.writeU32(uint32_t(-223)); wire.writeU32(uint32_t(-224));
        wire.writeU8(3); wire.writeU8(0); wire.writeU16(0); wire.writeU16(0);
        wire.writeU16(width); wire.writeU16(height); wire.flush();
        while (!input.hasData(4)) wait();
        auto type = input.readU8(); input.skip(1); auto count = input.readU16();
        std::cout << "firstMessage=" << int(type) << " countOrSize=" << count << '\n';
        if (type == 0 && count) {
          while (!input.hasData(12)) wait();
          input.skip(4); auto rectWidth = input.readU16(); auto rectHeight = input.readU16(); auto encoding = input.readS32();
          std::cout << "firstRect=" << rectWidth << 'x' << rectHeight << " encoding=" << encoding << '\n';
        }
      }
    }
    return 0;
  } catch (std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
