// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include <rfb/CConnection.h>
#include <rfb/ClientCompatibility.h>
#include <rfb/PixelBuffer.h>
#include <rdr/MemInStream.h>
#include <rdr/MemOutStream.h>
#include <cstring>

class CompatibilityConnection : public rfb::CConnection {
public:
  void initializeDesktop() {
    serverInit(16, 16, rfb::PixelFormat(32, 24, false, true,
                                      255, 255, 255, 16, 8, 0), "fixture");
  }
  void getUserPasswd(std::string*, std::string*) override {}
  bool verifyCertificate(unsigned int, const uint8_t*, size_t) override { return false; }
  bool verifyHostKey(const uint8_t*, size_t, const char*) override { return false; }
protected:
  void bell() override {}
  void initDone() override {
    setFramebuffer(new rfb::ManagedPixelBuffer(server.pf(), 16, 16));
    setPF(rfb::PixelFormat(8, 8, false, true, 7, 7, 3, 5, 2, 0));
  }
};

TEST(ClientCompatibility, AppleBannerAndPixelFormatOnWire)
{
  const char banner[] = "RFB 003.889\n";
  rdr::MemInStream input(reinterpret_cast<const uint8_t*>(banner), 12);
  rdr::MemOutStream output;
  CompatibilityConnection connection;
  connection.setStreams(&input, &output);
  connection.initialiseProtocol();
  ASSERT_TRUE(connection.processMsg());
  ASSERT_TRUE(connection.isAppleServer());
  EXPECT_TRUE(connection.server.isVersion(3, 8));
  ASSERT_EQ(output.length(), 12u);
  EXPECT_EQ(std::memcmp(output.data(), "RFB 003.008\n", 12), 0);
  output.clear();
  connection.initializeDesktop();
  ASSERT_GE(output.length(), 20u);
  EXPECT_EQ(output.data()[0], 0); // SetPixelFormat
  EXPECT_EQ(output.data()[4], 16); // actual bpp transmitted
  EXPECT_EQ(output.data()[5], 16);
  EXPECT_EQ(connection.server.pf(),
            rfb::PixelFormat(16, 16, false, true, 31, 63, 31, 11, 5, 0));
}

TEST(ClientCompatibility, OrdinaryServersKeepEightBitSupport)
{
  const char banner[] = "RFB 003.008\n";
  rdr::MemInStream input(reinterpret_cast<const uint8_t*>(banner), 12);
  rdr::MemOutStream output;
  CompatibilityConnection connection;
  connection.setStreams(&input, &output);
  connection.initialiseProtocol();
  ASSERT_TRUE(connection.processMsg());
  ASSERT_FALSE(connection.isAppleServer());
  output.clear();
  connection.initializeDesktop();
  ASSERT_GE(output.length(), 20u);
  EXPECT_EQ(output.data()[4], 8);
  EXPECT_EQ(connection.server.pf().bpp, 8);
}

TEST(ClientCompatibility, FullColorAndSupportedEncodings)
{
  rfb::PixelFormat full(32, 24, false, true, 255, 255, 255, 16, 8, 0);
  EXPECT_EQ(rfb::compatiblePixelFormat(true, full), full);
  for (int encoding : {rfb::encodingRaw, rfb::encodingHextile, rfb::encodingZRLE})
    EXPECT_EQ(rfb::compatibleEncoding(true, encoding), encoding);
  EXPECT_EQ(rfb::compatibleEncoding(true, rfb::encodingTight), rfb::encodingZRLE);
  EXPECT_EQ(rfb::compatibleEncoding(true, rfb::encodingJPEG), rfb::encodingZRLE);
  EXPECT_EQ(rfb::compatibleEncoding(false, rfb::encodingTight), rfb::encodingTight);
}
