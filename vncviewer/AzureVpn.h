// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_AZURE_VPN_H
#define TIGERVNCS_AZURE_VPN_H
#include <string>
#include <vector>
#include <stdexcept>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <ras.h>
#include <raserror.h>
#include <core/string.h>
#endif
namespace azureVpn {
#ifdef WIN32
inline std::wstring phonebook() {
  wchar_t directory[32768]; DWORD size=GetEnvironmentVariableW(L"LOCALAPPDATA",directory,32768);
  if (!size || size>=32768) throw std::runtime_error("Cannot locate Azure VPN Client profiles.");
  return std::wstring(directory)+L"\\Packages\\Microsoft.AzureVpn_8wekyb3d8bbwe\\LocalState\\rasphone.pbk";
}
struct Api {
  HMODULE library=nullptr;
  decltype(&RasEnumEntriesW) entries=nullptr;
  decltype(&RasEnumConnectionsW) connections=nullptr;
  decltype(&RasGetConnectStatusW) status=nullptr;
  decltype(&RasHangUpW) hangup=nullptr;
  Api() {
    wchar_t directory[MAX_PATH];
    if (GetSystemDirectoryW(directory,MAX_PATH)) library=LoadLibraryW((std::wstring(directory)+L"\\rasapi32.dll").c_str());
    if (library) {
      entries=reinterpret_cast<decltype(entries)>(GetProcAddress(library,"RasEnumEntriesW"));
      connections=reinterpret_cast<decltype(connections)>(GetProcAddress(library,"RasEnumConnectionsW"));
      status=reinterpret_cast<decltype(status)>(GetProcAddress(library,"RasGetConnectStatusW"));
      hangup=reinterpret_cast<decltype(hangup)>(GetProcAddress(library,"RasHangUpW"));
    }
    if (!entries || !connections || !status || !hangup) { if (library) FreeLibrary(library); library=nullptr; throw std::runtime_error("Windows RAS is unavailable."); }
  }
  ~Api() { if (library) FreeLibrary(library); }
};
inline std::vector<std::string> profiles() {
  auto book=phonebook();
  if (GetFileAttributesW(book.c_str())==INVALID_FILE_ATTRIBUTES) throw std::runtime_error("Azure VPN Client phonebook was not found.");
  Api api; DWORD bytes=sizeof(RASENTRYNAMEW), count=0;
  std::vector<RASENTRYNAMEW> data(1); data[0].dwSize=sizeof(RASENTRYNAMEW);
  DWORD error=api.entries(nullptr,book.c_str(),data.data(),&bytes,&count);
  if (error==ERROR_BUFFER_TOO_SMALL && bytes<=4*1024*1024) {
    data.resize((bytes+sizeof(RASENTRYNAMEW)-1)/sizeof(RASENTRYNAMEW)); data[0].dwSize=sizeof(RASENTRYNAMEW);
    error=api.entries(nullptr,book.c_str(),data.data(),&bytes,&count);
  }
  if (error || count>data.size()) throw std::runtime_error("Cannot enumerate Azure VPN profiles.");
  std::vector<std::string> result;
  for (DWORD i=0;i<count;++i) result.push_back(core::utf16ToUTF8(data[i].szEntryName));
  return result;
}
inline std::vector<RASCONNW> activeConnections(Api& api) {
  DWORD bytes=sizeof(RASCONNW), count=0; std::vector<RASCONNW> data(1); data[0].dwSize=sizeof(RASCONNW);
  DWORD error=api.connections(data.data(),&bytes,&count);
  if (error==ERROR_BUFFER_TOO_SMALL && bytes<=4*1024*1024) {
    data.resize((bytes+sizeof(RASCONNW)-1)/sizeof(RASCONNW)); data[0].dwSize=sizeof(RASCONNW);
    error=api.connections(data.data(),&bytes,&count);
  }
  if (error || count>data.size()) throw std::runtime_error("Cannot query Azure VPN connections.");
  data.resize(count); return data;
}
inline bool disconnect(const std::string& profile) {
  Api api; auto book=phonebook(); auto name=core::utf8ToUTF16(profile.c_str());
  for (const auto& item:activeConnections(api)) {
    if (_wcsicmp(item.szPhonebook,book.c_str())!=0 || name!=item.szEntryName) continue;
    if (api.hangup(item.hrasconn)) return false;
    auto deadline=GetTickCount64()+10000;
    for (;;) {
      RASCONNSTATUSW state{}; state.dwSize=sizeof(state);
      DWORD error=api.status(item.hrasconn,&state);
      if (error==ERROR_INVALID_HANDLE) break;
      if (error || GetTickCount64()>=deadline) return false;
      Sleep(50);
    }
  }
  return true;
}
struct Status { bool connected=false, transitioning=false; std::vector<std::string> profiles; };
inline Status query() {
  auto book=phonebook(); profiles(); Api api;
  auto data=activeConnections(api); DWORD count=DWORD(data.size());
  Status result;
  for (DWORD i=0;i<count;++i) {
    if (_wcsicmp(data[i].szPhonebook,book.c_str())!=0) continue;
    RASCONNSTATUSW state{}; state.dwSize=sizeof(state);
    if (api.status(data[i].hrasconn,&state)) throw std::runtime_error("Cannot query Azure VPN connection status.");
    if (state.rasconnstate==RASCS_Connected && !state.dwError) {
      result.connected=true; result.profiles.push_back(core::utf16ToUTF8(data[i].szEntryName));
    } else if (state.rasconnstate!=RASCS_Disconnected) result.transitioning=true;
  }
  return result;
}
#endif
}
#endif
