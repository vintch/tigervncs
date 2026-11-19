// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include <rfb/CConnection.h>
#include <rfb/CSecurity.h>
#include <rfb/Security.h>
#include <rfb/PixelBuffer.h>
#include <rfb/encodings.h>
#include <rdr/MemInStream.h>
#include <rdr/MemOutStream.h>
#include <cstring>

namespace {
class AuthenticatedDH : public rfb::CSecurity {
public:
  explicit AuthenticatedDH(rfb::CConnection* c) : CSecurity(c) {}
  int getType() const override { return rfb::secTypeDH; }
  bool processMsg() override { return true; }
};
class SessionReplay : public rfb::CConnection {
public:
  bool initialized = false;
  void authenticated() { csecurity = new AuthenticatedDH(this); setState(RFBSTATE_SECURITY_RESULT); }
  void getUserPasswd(std::string*, std::string*) override {}
  bool verifyCertificate(unsigned int, const uint8_t*, size_t) override { return false; }
  bool verifyHostKey(const uint8_t*, size_t, const char*) override { return false; }
  void bell() override {}
  void initDone() override {
    initialized = true;
    setFramebuffer(new rfb::ManagedPixelBuffer(server.pf(), server.width(), server.height()));
    setPreferredEncoding(rfb::encodingZRLE);
  }
};
std::vector<uint8_t> transcript(uint32_t flags, uint32_t allowed, const std::string& user,
                                std::vector<uint32_t> statuses = {0}, int width = 64) {
  rdr::MemOutStream output;
  output.writeBytes(reinterpret_cast<const uint8_t*>("RFB 003.889\n"), 12);
  output.writeU32(0); // Authentication already exercised by live DH checks.
  output.writeU16(width); output.writeU16(width);
  rfb::PixelFormat(32,24,false,true,255,255,255,16,8,0).write(&output);
  std::string name(22, '\0'); name += "Fixture";
  for (int i = 0; i < 4; ++i) name[2 + i] = char(flags >> (24 - i * 8));
  output.writeU32(name.size()); output.writeBytes(reinterpret_cast<const uint8_t*>(name.data()), name.size());
  if (flags & 4) {
    output.writeU16(11 + user.size()); output.writeU16(1); output.writeU32(allowed); output.writeU32(0);
    output.writeBytes(reinterpret_cast<const uint8_t*>(user.c_str()), user.size() + 1);
    for (auto status : statuses) { output.writeU16(6); output.writeU16(1); output.writeU32(status); }
  }
  return {output.data(), output.data() + output.length()};
}
void begin(SessionReplay& connection, rdr::MemInStream& input, rdr::MemOutStream& output, int mode) {
  connection.setAppleSessionMode(mode); connection.setShared(true);
  connection.setStreams(&input, &output); connection.initialiseProtocol();
  ASSERT_TRUE(connection.processMsg());
  ASSERT_EQ(std::memcmp(output.data(), "RFB 003.889\n", 12), 0);
  connection.authenticated(); ASSERT_TRUE(connection.processMsg());
  ASSERT_EQ(output.data()[12], 0xc1);
}
}

TEST(AppleSession, EmitsDistinctCommandsAndWaitsForGrantBeforeFramebufferSetup) {
  for (int mode : {1,2}) {
    auto bytes = transcript(4, 7, "console-user", {2,3,4});
    rdr::MemInStream input(bytes.data(), bytes.size()); rdr::MemOutStream output;
    SessionReplay connection; begin(connection, input, output, mode);
    ASSERT_TRUE(connection.processMsg()); EXPECT_FALSE(connection.initialized);
    ASSERT_TRUE(connection.processMsg()); EXPECT_FALSE(connection.initialized);
    ASSERT_EQ(output.length(), 87u);
    EXPECT_EQ(output.data()[13], 0); EXPECT_EQ(output.data()[14], 72);
    EXPECT_EQ(output.data()[21], mode);
    EXPECT_EQ(std::memcmp(output.data() + 23, "console-user", 12), 0);
    ASSERT_TRUE(connection.processMsg()); EXPECT_FALSE(connection.initialized);
    ASSERT_TRUE(connection.processMsg()); EXPECT_FALSE(connection.initialized);
    ASSERT_TRUE(connection.processMsg()); EXPECT_TRUE(connection.initialized);
    EXPECT_EQ(connection.state(), rfb::CConnection::RFBSTATE_NORMAL);
  }
}

TEST(AppleSession, ConsoleRequestWithoutLoggedInUserUsesAllowedRequestCommand) {
  auto bytes = transcript(4, 1, "");
  rdr::MemInStream input(bytes.data(), bytes.size()); rdr::MemOutStream output;
  SessionReplay connection; begin(connection, input, output, 1);
  connection.processMsg(); connection.processMsg();
  ASSERT_GE(output.length(), 87u); EXPECT_EQ(output.data()[21], 0);
}

TEST(AppleSession, UnsupportedOrDeniedUserSessionNeverFallsBackToConsole) {
  for (uint32_t flags : {0u, 12u}) {
    auto bytes = transcript(flags, 7, "console");
    rdr::MemInStream input(bytes.data(), bytes.size()); rdr::MemOutStream output;
    SessionReplay connection; begin(connection, input, output, 2);
    EXPECT_THROW(connection.processMsg(), std::exception); EXPECT_FALSE(connection.initialized);
  }
  for (uint32_t allowed : {1u, 2u}) {
    auto bytes = transcript(4, allowed, "console");
    rdr::MemInStream input(bytes.data(), bytes.size()); rdr::MemOutStream output;
    SessionReplay connection; begin(connection, input, output, 2);
    connection.processMsg(); EXPECT_THROW(connection.processMsg(), std::exception);
    EXPECT_FALSE(connection.initialized);
  }
  auto bytes = transcript(4, 7, "console", {1});
  rdr::MemInStream input(bytes.data(), bytes.size()); rdr::MemOutStream output;
  SessionReplay connection; begin(connection, input, output, 2);
  connection.processMsg(); connection.processMsg();
  EXPECT_THROW(connection.processMsg(), std::exception); EXPECT_FALSE(connection.initialized);
}

TEST(AppleSession, UserSessionRejectsNonAppleBeforeSendingCredentials) {
  const uint8_t banner[] = "RFB 003.008\n";
  rdr::MemInStream input(banner, 12); rdr::MemOutStream output;
  SessionReplay connection; connection.setAppleSessionMode(2);
  connection.setStreams(&input, &output); connection.initialiseProtocol();
  EXPECT_THROW(connection.processMsg(), std::exception); EXPECT_EQ(output.length(), 0u);
}

TEST(AppleSession, CurrentScreenLeavesOrdinaryRfbHandshakeUnchanged) {
  const uint8_t bytes[] = {'R','F','B',' ','0','0','3','.','0','0','8','\n',0,0,0,0};
  rdr::MemInStream input(bytes, sizeof(bytes)); rdr::MemOutStream output;
  SessionReplay connection; connection.setAppleSessionMode(1); connection.setShared(true);
  connection.setStreams(&input, &output); connection.initialiseProtocol();
  ASSERT_TRUE(connection.processMsg());
  EXPECT_EQ(std::memcmp(output.data(), "RFB 003.008\n", 12), 0);
  connection.authenticated(); ASSERT_TRUE(connection.processMsg());
  ASSERT_EQ(output.length(), 13u); EXPECT_EQ(output.data()[12], 1);
}

TEST(AppleSession, ZeroGeometryNeverProducesZeroSizedFramebufferRequest) {
  auto bytes = transcript(4, 7, "console", {0}, 0);
  rdr::MemInStream input(bytes.data(), bytes.size()); rdr::MemOutStream output;
  SessionReplay connection; begin(connection, input, output, 2);
  while (connection.state() != rfb::CConnection::RFBSTATE_NORMAL) ASSERT_TRUE(connection.processMsg());
  EXPECT_TRUE(connection.initialized); EXPECT_EQ(connection.server.width(), 1); EXPECT_EQ(connection.server.height(), 1);
}
