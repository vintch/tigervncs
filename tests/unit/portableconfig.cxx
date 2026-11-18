// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include "PortableConfig.h"

class PortableConfigTest : public testing::Test {
protected:
  std::string path = "portable-config-unit-test.json";
  void SetUp() override {
    path = std::string("portable-config-") +
           testing::UnitTest::GetInstance()->current_test_info()->name() + ".json";
    std::remove(path.c_str());
  }
  void TearDown() override { std::remove(path.c_str()); }
};

TEST_F(PortableConfigTest, RoundtripRetainsNestedConnectionFields)
{
  PortableConfig file(path);
  auto value = file.read();
  value["viewer"]["ScaleToWindow"] = true;
  value["viewer"]["QualityLevel"] = 3;
  value["connections"][0]["folder"] = "Office/Macs";
  value["connections"][0]["custom"]["label"] = "test";
  file.write(value);
  value = file.read();
  value["viewer"]["ScaleToWindow"] = false;
  file.write(value);
  auto saved = file.read();
  EXPECT_FALSE(saved["viewer"]["ScaleToWindow"].asBool());
  EXPECT_EQ(saved["viewer"]["QualityLevel"].asInt(), 3);
  EXPECT_EQ(saved["connections"][0]["custom"]["label"].asString(), "test");
  EXPECT_EQ(saved["connections"][0]["folder"].asString(), "Office/Macs");
}

TEST_F(PortableConfigTest, RejectsMalformedOrFutureConfiguration)
{
  { std::ofstream stream(path); stream << "{broken"; }
  EXPECT_THROW(PortableConfig(path).read(), std::runtime_error);
  { std::ofstream stream(path); stream << R"({"schemaVersion":2,"viewer":{}})"; }
  EXPECT_THROW(PortableConfig(path).read(), std::runtime_error);
  { std::ofstream stream(path); stream << R"({"schemaVersion":1,"viewer":{},"viewer":{}})"; }
  EXPECT_THROW(PortableConfig(path).read(), std::runtime_error);
}

TEST_F(PortableConfigTest, FailedReplacementKeepsOriginal)
{
  PortableConfig file(path);
  auto value = file.read();
  file.write(value);
  value["schemaVersion"] = 99;
  EXPECT_THROW(file.write(value), std::runtime_error);
  EXPECT_EQ(file.read()["schemaVersion"].asInt(), 1);
  EXPECT_THROW(PortableConfig("missing-directory/settings.json").write(file.read()),
               std::runtime_error);
}
