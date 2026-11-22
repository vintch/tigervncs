// SPDX-License-Identifier: GPL-2.0-or-later
// Isolated integration utility. Password is read only from standard input.
#include "ShellyPower.h"
#include "ConnectionStore.h"
#include <iostream>
#include <thread>
int main(int argc,char** argv) {
  try {
    if (argc<3) return 2;
    ConnectionStore store(argv[2]);
    if (std::string(argv[1])=="seed" && argc==5) {
      std::string password; std::getline(std::cin,password);
      Json::Value power; power["mode"]="shelly-plug"; power["address"]=argv[3]; power["username"]=argv[4];
      auto doc=store.read();
      std::string id=doc["connections"].empty()?"":doc["connections"][0]["id"].asString();
      id=store.saveConnection(id,"Shelly integration test","10.3.1.13","","",ConnectionStore::KeepPassword,"","current-screen",{},power,ConnectionStore::SetPassword,password);
      CredentialVault::erase(password); store.setExpanded(true);
      std::cout<<id<<'\n'; return 0;
    }
    auto doc=store.read(); auto id=doc["connections"][0]["id"].asString();
    auto credentials=shellyPower::credentials(doc,id);
    if (std::string(argv[1])=="check") return shellyPower::transport()->check(credentials)?0:1;
    if (std::string(argv[1])=="on") return shellyPower::transport()->setPower(credentials,true,0)?0:1;
    if (std::string(argv[1])!="cycle" || argc!=5) return 2;
    auto started=shellyPower::clockMs(); auto cycle=shellyPower::start(credentials,std::stoi(argv[3]),shellyPower::transport());
    bool cancel=false; int cancelMs=std::stoi(argv[4]);
    while (cycle->phase.load()!=shellyPower::Phase::Done && shellyPower::clockMs()-started<60000) {
      if (!cancel && cancelMs>=0 && cycle->phase.load()==shellyPower::Phase::Waiting && shellyPower::clockMs()-cycle->waitStarted.load()>=cancelMs) { cycle->cancel(); cancel=true; }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if(cycle->phase.load()!=shellyPower::Phase::Done) return 3;
    std::cout<<"off="<<cycle->offSucceeded<<" restored="<<cycle->onSucceeded<<" cancelled="<<cancel<<" elapsedMs="<<shellyPower::clockMs()-started<<'\n';
    return cycle->offSucceeded && cycle->onSucceeded ? 0:1;
  } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
