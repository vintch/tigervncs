// SPDX-License-Identifier: GPL-2.0-or-later
#include "RdpClient.h"
#include "ConnectionProtocol.h"
#include "RdpDefaults.h"
#include <core/string.h>
#include <core/Configuration.h>
#include <thread>
#include <cstring>
#ifdef WIN32
#include <windows.h>
#include <wincred.h>
#endif
namespace rdpClient {
core::BoolParameter forceWindowSize("RdpForceWindowSize", "Set explicit initial RDP desktop dimensions", false);
core::IntParameter windowWidth("RdpWindowWidth", "Initial RDP desktop width in pixels", 1024, 200, 8192);
core::IntParameter windowHeight("RdpWindowHeight", "Initial RDP desktop height in pixels", 600, 200, 8192);
Settings::~Settings() { CredentialVault::erase(password); }
Settings savedSettings(const Json::Value& document,const std::string& id,const std::string& address) {
  Settings settings; settings.address=connectionProtocol::rdpEndpoint(address).address();
  for(const auto& entry:document["connections"]) if(entry["id"]==id) {
    if(connectionProtocol::type(entry)!="rdp" || !connectionProtocol::sameRdpEndpoint(entry["address"].asString(),address)) break;
    settings.username=entry["username"].asString(); settings.hasPassword=!entry["password"].isNull();
    if(settings.hasPassword) settings.password=CredentialVault::decrypt(document,id,entry["password"]);
    break;
  }
  return settings;
}
std::string arguments(const Settings& settings) {
  std::string result="/v:"+connectionProtocol::rdpEndpoint(settings.address).address();
  if(forceWindowSize) result+=" /w:"+std::to_string(int(windowWidth))+" /h:"+std::to_string(int(windowHeight));
  return result;
}
namespace {
#ifdef WIN32
// Supply credentials without an RDP file, then restore the prior entry when
// this client exits. The secret never appears in the command line.
class CredentialLease {
  std::wstring target, username, password;
  PCREDENTIALW previous=nullptr;
  bool installed=false;
public:
  explicit CredentialLease(const Settings& settings) {
    if(!settings.hasPassword || settings.username.empty()) return;
    auto endpoint=connectionProtocol::rdpEndpoint(settings.address);
    target=core::utf8ToUTF16(("TERMSRV/"+endpoint.host).c_str());
    username=core::utf8ToUTF16(settings.username.c_str());
    password=core::utf8ToUTF16(settings.password.c_str());
    if(!CredReadW(target.c_str(),CRED_TYPE_GENERIC,0,&previous) && GetLastError()!=ERROR_NOT_FOUND)
      throw std::runtime_error("Unable to prepare RDP credentials");
    if(previous && previous->UserName && username==previous->UserName &&
       previous->CredentialBlobSize==password.size()*sizeof(wchar_t) &&
       (!previous->CredentialBlobSize || !memcmp(previous->CredentialBlob,password.data(),previous->CredentialBlobSize)))
      return;
    CREDENTIALW credential{}; credential.Type=CRED_TYPE_GENERIC;
    credential.TargetName=&target[0]; credential.UserName=&username[0];
    credential.CredentialBlobSize=DWORD(password.size()*sizeof(wchar_t));
    credential.CredentialBlob=reinterpret_cast<BYTE*>(&password[0]); credential.Persist=CRED_PERSIST_SESSION;
    credential.Comment=const_cast<wchar_t*>(L"TigerVNCs temporary RDP credential");
    if(!CredWriteW(&credential,0)) {
      if(previous) { CredFree(previous); previous=nullptr; }
      SecureZeroMemory(&password[0],password.size()*sizeof(wchar_t));
      throw std::runtime_error("Unable to pass saved credentials to Windows Remote Desktop");
    }
    installed=true;
  }
  ~CredentialLease() {
    if(installed) {
      PCREDENTIALW current=nullptr;
      if(CredReadW(target.c_str(),CRED_TYPE_GENERIC,0,&current)) {
        bool ours=current->UserName && username==current->UserName &&
          current->CredentialBlobSize==password.size()*sizeof(wchar_t) &&
          (!current->CredentialBlobSize || !memcmp(current->CredentialBlob,password.data(),current->CredentialBlobSize));
        if(ours) {
          if(previous) CredWriteW(previous,0);
          else CredDeleteW(target.c_str(),CRED_TYPE_GENERIC,0);
        }
        if(current->CredentialBlob) SecureZeroMemory(current->CredentialBlob,current->CredentialBlobSize);
        CredFree(current);
      }
    }
    if(previous) {
      if(previous->CredentialBlob) SecureZeroMemory(previous->CredentialBlob,previous->CredentialBlobSize);
      CredFree(previous);
    }
    if(!password.empty()) SecureZeroMemory(&password[0],password.size()*sizeof(wchar_t));
  }
};
#endif
std::shared_ptr<Job> startClient(Settings settings, const std::wstring& testExecutable) {
  // Validate synchronously so malformed entries never hide the manager.
  connectionProtocol::rdpEndpoint(settings.address);
  auto job=std::make_shared<Job>();
  std::thread([settings,job,testExecutable]() mutable {
#ifdef WIN32
    HANDLE process=nullptr;
    try {
      CredentialLease credential(settings);
      std::unique_ptr<DefaultSettingsLease> defaults;
#ifdef TIGERVNCS_RDP_TEST
      if(testExecutable.empty())
#endif
      defaults.reset(new DefaultSettingsLease);
      CredentialVault::erase(settings.password);
      wchar_t directory[MAX_PATH]; UINT length=GetSystemDirectoryW(directory,MAX_PATH);
      if(!length || length>=MAX_PATH) throw std::runtime_error("Unable to locate Windows Remote Desktop");
      std::wstring executable=std::wstring(directory)+L"\\mstsc.exe";
#ifdef TIGERVNCS_RDP_TEST
      if(!testExecutable.empty()) executable=testExecutable;
#endif
      std::wstring command=L"\""+executable+L"\" "+core::utf8ToUTF16(arguments(settings).c_str());
      STARTUPINFOW startup{}; startup.cb=sizeof(startup);
      startup.dwFlags=STARTF_USESHOWWINDOW; startup.wShowWindow=SW_SHOWNORMAL;
      startup.lpDesktop=const_cast<wchar_t*>(L"winsta0\\default");
      PROCESS_INFORMATION info{};
      if(!CreateProcessW(executable.c_str(),&command[0],nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&info))
        throw std::runtime_error("Unable to start Windows Remote Desktop");
      process=info.hProcess; CloseHandle(info.hThread); job->launched=true; job->processId=info.dwProcessId;
      if(WaitForSingleObject(process,INFINITE)!=WAIT_OBJECT_0 || !GetExitCodeProcess(process,&job->exitCode))
        throw std::runtime_error("Unable to monitor Windows Remote Desktop");
    } catch(const std::exception& error) { job->error=error.what(); }
    catch(...) { job->error="Unable to start Windows Remote Desktop"; }
    if(process) CloseHandle(process);
#else
    job->error="RDP connections require Windows";
#endif
    job->done.store(true,std::memory_order_release);
  }).detach();
  return job;
}
}
std::shared_ptr<Job> start(Settings settings) { return startClient(settings,L""); }
#ifdef TIGERVNCS_RDP_TEST
std::shared_ptr<Job> startForTest(Settings settings,const std::wstring& executable) { return startClient(settings,executable); }
#endif
}
