// SPDX-License-Identifier: GPL-2.0-or-later
// Password input is stdin only. Does not send remote desktop input.
#include "RdpClient.h"
#include <thread>
#include <iostream>
int main(int argc,char** argv) {
  try {
    if(argc<3) return 2;
    ConnectionStore store(argv[2]);
    if(std::string(argv[1])=="seed" && argc==5) {
      std::string password; std::getline(std::cin,password);
      auto id=store.saveConnection("","RDP integration test",argv[3],argv[4],"",ConnectionStore::SetPassword,password,
        "current-screen",{}, {},ConnectionStore::KeepPassword,"","rdp");
      CredentialVault::erase(password); store.setExpanded(true); std::cout<<id<<'\n'; return 0;
    }
    auto doc=store.read(); auto entry=doc["connections"][0];
    auto job=rdpClient::start(rdpClient::savedSettings(doc,entry["id"].asString(),entry["address"].asString()));
    while(!job->done.load()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout<<"launched="<<job->launched<<" processId="<<job->processId<<" error="<<job->error<<'\n';
    return job->launched && job->error.empty()?0:1;
  } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
