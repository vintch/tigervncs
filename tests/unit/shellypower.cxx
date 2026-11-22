// SPDX-License-Identifier: GPL-2.0-or-later
#include <gtest/gtest.h>
#include "ShellyPower.h"
#include "ConnectionStore.h"
#include <thread>
#include <cstdio>
namespace {
struct FakePlug : shellyPower::Transport {
  std::vector<bool> calls;
  int timer = 0, failuresOn = 0; bool failOff = false, throws = false;
  bool setPower(const shellyPower::Credentials&, bool on, int seconds) override {
    calls.push_back(on); if (!on) timer = seconds;
    if (throws) throw std::runtime_error("Network error");
    if (on && failuresOn > 0) { --failuresOn; return false; }
    return on || !failOff;
  }
};
bool wait(const std::shared_ptr<shellyPower::Cycle>& cycle, shellyPower::Phase phase, int timeout = 3000) {
  auto end = shellyPower::clockMs() + timeout;
  while (cycle->phase.load() != phase && shellyPower::clockMs() < end) std::this_thread::sleep_for(std::chrono::milliseconds(5));
  return cycle->phase.load() == phase;
}
}
TEST(ShellyPower, AddressValidation) {
  EXPECT_EQ(shellyPower::parseAddress("shellyplug-sprechzimmer4.ha.local").host,"shellyplug-sprechzimmer4.ha.local");
  EXPECT_EQ(shellyPower::parseAddress("localhost:1234").port,1234);
  EXPECT_EQ(shellyPower::parseAddress("10.3.192.12").port,80);
  EXPECT_EQ(shellyPower::parseAddress("127.0.0.1:12345").port,12345);
  EXPECT_EQ(shellyPower::parseAddress("[::1]:8080").host,"::1");
  EXPECT_EQ(shellyPower::parseAddress("2001:db8::").host,"2001:db8::");
  for (auto value : {"", "http://10.0.0.1", "10.0.0.1/path", "admin@10.0.0.1", "10.0.0.1:0", "10.0.0.1:65536", "10.0.0.1:", "10.0.0.1\r\nHeader:x"})
    EXPECT_THROW(shellyPower::parseAddress(value), std::runtime_error) << value;
}
TEST(ShellyPower, FullCycleUsesBackupTimerAndRestores) {
  auto plug = std::make_shared<FakePlug>(); auto started = shellyPower::clockMs();
  auto cycle = shellyPower::start({},1,plug);
  ASSERT_TRUE(wait(cycle,shellyPower::Phase::Done));
  EXPECT_TRUE(cycle->offSucceeded); EXPECT_TRUE(cycle->onSucceeded);
  EXPECT_EQ(plug->calls,(std::vector<bool>{false,true})); EXPECT_EQ(plug->timer,1);
  EXPECT_GE(shellyPower::clockMs()-started,1000);
}
TEST(ShellyPower, CancellationRestoresImmediately) {
  auto plug = std::make_shared<FakePlug>(); auto cycle = shellyPower::start({},15,plug);
  ASSERT_TRUE(wait(cycle,shellyPower::Phase::Waiting));
  auto started = shellyPower::clockMs(); cycle->cancel();
  ASSERT_TRUE(wait(cycle,shellyPower::Phase::Done));
  EXPECT_LT(shellyPower::clockMs()-started,500);
  EXPECT_TRUE(cycle->onSucceeded); EXPECT_EQ(plug->calls,(std::vector<bool>{false,true}));
}
TEST(ShellyPower, FailedOffStillRestoresAndFailedOnRetries) {
  auto plug = std::make_shared<FakePlug>(); plug->failOff=true; plug->failuresOn=1;
  auto cycle = shellyPower::start({},15,plug); ASSERT_TRUE(wait(cycle,shellyPower::Phase::Done));
  EXPECT_FALSE(cycle->offSucceeded); EXPECT_TRUE(cycle->onSucceeded);
  EXPECT_EQ(plug->calls,(std::vector<bool>{false,true,true}));
}
TEST(ShellyPower, CancellationCannotBeOvertakenByAnInflightOffRequest) {
  struct SlowPlug : FakePlug {
    std::atomic<bool> entered{false}, release{false};
    bool setPower(const shellyPower::Credentials& credentials, bool on, int seconds) override {
      if (!on) {
        entered.store(true); auto deadline=shellyPower::clockMs()+2000;
        while (!release.load() && shellyPower::clockMs()<deadline) std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
      return FakePlug::setPower(credentials,on,seconds);
    }
  };
  auto plug=std::make_shared<SlowPlug>(); auto cycle=shellyPower::start({},15,plug);
  auto deadline=shellyPower::clockMs()+1000;
  while (!plug->entered.load() && shellyPower::clockMs()<deadline) std::this_thread::sleep_for(std::chrono::milliseconds(5));
  EXPECT_TRUE(plug->entered.load()); cycle->cancel();
  EXPECT_EQ(cycle->phase.load(),shellyPower::Phase::SwitchingOff);
  plug->release.store(true); ASSERT_TRUE(wait(cycle,shellyPower::Phase::Done));
  EXPECT_TRUE(cycle->onSucceeded); EXPECT_EQ(plug->calls,(std::vector<bool>{false,true}));
}
TEST(ShellyPower, NetworkExceptionsCompleteWithoutHanging) {
  auto plug = std::make_shared<FakePlug>(); plug->throws=true;
  auto cycle = shellyPower::start({},15,plug); ASSERT_TRUE(wait(cycle,shellyPower::Phase::Done));
  EXPECT_FALSE(cycle->offSucceeded); EXPECT_FALSE(cycle->onSucceeded);
}
TEST(ShellyPower, SeparateEncryptedPasswordSurvivesEditsAndDisabling) {
  const char* path="shelly-test.json"; std::remove(path);
  ConnectionStore store(path); Json::Value power;
  power["mode"]="shelly-plug"; power["address"]="10.3.192.12"; power["username"]="admin";
  auto id=store.saveConnection("","Mac","10.3.1.13","Administrator","",ConnectionStore::SetPassword,"vnc-secret","current-screen",{},power,ConnectionStore::SetPassword,"plug-secret");
  auto doc=store.read(); auto plug=shellyPower::credentials(doc,id);
  EXPECT_EQ(plug.password,"plug-secret"); EXPECT_EQ(CredentialVault::decrypt(doc,id,store.connection(id)["password"]),"vnc-secret");
  EXPECT_EQ(doc.toStyledString().find("plug-secret"),std::string::npos);
  EXPECT_THROW(CredentialVault::decrypt(doc,id,store.connection(id)["powerOn"]["password"]),std::runtime_error);
  auto cipher=store.connection(id)["powerOn"]["password"];
  power["mode"]="none";
  store.saveConnection(id,"Renamed","10.3.1.13","Administrator","",ConnectionStore::KeepPassword,"","",{},power);
  EXPECT_FALSE(shellyPower::configured(store.connection(id))); EXPECT_EQ(cipher,store.connection(id)["powerOn"]["password"]);
  power["mode"]="shelly-plug";
  store.saveConnection(id,"Renamed","10.3.1.13","Administrator","",ConnectionStore::ForgetPassword,"","",{},power);
  doc=store.read(); doc.removeMember("credentialKey");
  EXPECT_THROW(CredentialVault::encrypt(doc,id,"replacement"),std::runtime_error);
  power["mode"]="invalid";
  EXPECT_THROW(store.saveConnection(id,"Broken","10.3.1.13","Administrator","",ConnectionStore::KeepPassword,"","",{},power),std::runtime_error);
  EXPECT_EQ(store.connection(id)["name"],"Renamed"); std::remove(path);
}

TEST(ShellyPower, Gen2UsesFixedApiUsernameAndKeepsEncryptedPassword) {
  const char* path="shelly-gen2-settings-test.json"; std::remove(path);
  {
    ConnectionStore store(path);
    Json::Value power; power["mode"]="shelly-plug-gen2"; power["address"]="plug.example.local"; power["username"]="ignored";
    auto id=store.saveConnection("","Computer","host","","",ConnectionStore::KeepPassword,"","current-screen",{},power,ConnectionStore::SetPassword,"synthetic-secret");
    auto document=store.read();
    auto credentials=shellyPower::credentials(document,id);
    EXPECT_TRUE(credentials.gen2); EXPECT_EQ(credentials.username,"admin");
    EXPECT_EQ(credentials.password,"synthetic-secret");
    EXPECT_TRUE(shellyPower::configured(store.connection(id)));
  }
  std::remove(path);
}
