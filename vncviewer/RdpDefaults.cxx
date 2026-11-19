// SPDX-License-Identifier: GPL-2.0-or-later
#include "RdpDefaults.h"
#include "PortableConfig.h"
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <atomic>
#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#endif
namespace rdpClient {
namespace {
std::atomic<unsigned> activeSettings{0};
const std::string tokens[]={"prompt for credentials:i:","authentication level:i:"};
struct Flag { size_t position,begin,end; unsigned kind; unsigned char value; };
size_t width(const std::vector<unsigned char>& b) { return b.size()>=2 && b[0]==255 && b[1]==254 ? 2:1; }
std::vector<Flag> flags(const std::vector<unsigned char>& bytes) {
  std::vector<Flag> result; size_t unit=width(bytes),start=unit==2?2:0;
  if(unit==1 && bytes.size()>=3 && bytes[0]==239 && bytes[1]==187 && bytes[2]==191) start=3;
  for(size_t at=start;at<bytes.size();at+=unit) {
    if(at>start && bytes[at-unit]!='\n') continue;
    for(unsigned kind=0;kind<2;++kind) {
      const auto& token=tokens[kind]; if(at+token.size()*unit>=bytes.size()) continue;
      bool match=true;
      for(size_t i=0;i<token.size();++i) {
        unsigned char c=bytes[at+i*unit]; if(c>='A' && c<='Z') c+=32;
        if(c!=token[i] || (unit==2 && bytes[at+i*unit+1])) { match=false; break; }
      }
      size_t value=at+token.size()*unit;
      if(match && bytes[value]>='0' && bytes[value]<='3' &&
         (value+unit>=bytes.size() || bytes[value+unit]=='\r' || bytes[value+unit]=='\n')) {
        size_t end=value+unit;
        while(end<bytes.size() && bytes[end]!='\n') end+=unit;
        result.push_back({value,at,std::min(bytes.size(),end+unit),kind,bytes[value]});
      }
    }
  }
  return result;
}
void append(std::vector<unsigned char>& bytes,const std::string& text,size_t unit) {
  for(unsigned char c:text) { bytes.push_back(c); if(unit==2) bytes.push_back(0); }
}
#ifdef WIN32
struct File { HANDLE value=INVALID_HANDLE_VALUE; ~File(){if(value!=INVALID_HANDLE_VALUE) CloseHandle(value);} };
std::vector<unsigned char> read(HANDLE file) {
  LARGE_INTEGER size{}; if(!GetFileSizeEx(file,&size) || size.QuadPart>1024*1024 || size.QuadPart<0) throw std::runtime_error("Cannot read native RDP preferences");
  std::vector<unsigned char> data(size_t(size.QuadPart)); DWORD count=0;
  if(!data.empty() && (!ReadFile(file,data.data(),DWORD(data.size()),&count,nullptr) || count!=data.size())) throw std::runtime_error("Cannot read native RDP preferences");
  return data;
}
void write(HANDLE file,const std::vector<unsigned char>& bytes) {
  LARGE_INTEGER zero{}; DWORD count=0;
  if(!SetFilePointerEx(file,zero,nullptr,FILE_BEGIN) ||
     (!bytes.empty() && (!WriteFile(file,bytes.data(),DWORD(bytes.size()),&count,nullptr) || count!=bytes.size())) || !SetEndOfFile(file))
    throw std::runtime_error("Cannot prepare native RDP preferences");
}
std::wstring nativePath() {
  wchar_t directory[MAX_PATH];
  if(FAILED(SHGetFolderPathW(nullptr,CSIDL_PERSONAL,nullptr,SHGFP_TYPE_CURRENT,directory))) throw std::runtime_error("Cannot locate native RDP preferences");
  return std::wstring(directory)+L"\\Default.rdp";
}
void clearRecovery(const std::string& config,const std::string& id) {
  if(config.empty() || id.empty()) return;
  PortableConfig file(config); auto document=file.read();
  if(document["rdpRecovery"]["id"]==id) { document.removeMember("rdpRecovery"); file.write(document); }
}
bool restore(const std::wstring& path,const std::string& config,bool onlyPending) {
  if(activeSettings.load()) throw std::runtime_error("Close the RDP session before restoring its settings.");
  PortableConfig settings(config); auto document=settings.read(); auto recovery=document["rdpRecovery"];
  bool saved=!recovery.isNull();
  if(!saved && onlyPending) return false;
  std::vector<Flag> prior;
  if(saved) {
    if(!recovery.isObject() || recovery["version"]!=1 || !recovery["id"].isString() ||
       !recovery["hadDefaultFile"].isBool() || !recovery["flags"].isArray() || recovery["flags"].size()>256)
      throw std::runtime_error("Invalid saved RDP recovery settings");
    DWORD owner=recovery["ownerPid"].asUInt();
    if(owner && owner!=GetCurrentProcessId()) {
      HANDLE process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,owner);
      if(process) {
        FILETIME created{},exited{},kernel{},user{};
        bool identity=GetProcessTimes(process,&created,&exited,&kernel,&user) && recovery["ownerStarted"].isUInt64() &&
          recovery["ownerStarted"].asUInt64()==((ULONGLONG(created.dwHighDateTime)<<32)|created.dwLowDateTime);
        bool running=identity && WaitForSingleObject(process,0)==WAIT_TIMEOUT; CloseHandle(process);
        if(running) throw std::runtime_error("Another TigerVNCs instance is using the RDP settings."); }
    }
    for(const auto& value:recovery["flags"]) {
      if(!value["kind"].isUInt() || value["kind"].asUInt()>1 || !value["value"].isUInt() || value["value"].asUInt()>3)
        throw std::runtime_error("Invalid saved RDP prompt value");
      prior.push_back({0,0,0,value["kind"].asUInt(),static_cast<unsigned char>('0'+value["value"].asUInt())});
    }
  }
  File file; file.value=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
  if(file.value==INVALID_HANDLE_VALUE) {
    if(saved && GetLastError()==ERROR_FILE_NOT_FOUND) { clearRecovery(config,recovery["id"].asString()); return true; }
    if(GetLastError()!=ERROR_FILE_NOT_FOUND) throw std::runtime_error("Cannot restore native RDP preferences");
    file.value=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_HIDDEN,nullptr);
    if(file.value==INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot restore native RDP preferences");
  }
  auto bytes=read(file.value), result=bytes; auto found=flags(bytes);
  if(saved) {
    for(auto i=found.rbegin();i!=found.rend();++i) if(i->value=='0') {
      auto old=std::find_if(prior.rbegin(),prior.rend(),[&](const Flag& flag){return flag.kind==i->kind;});
      if(old!=prior.rend()) result[i->position]=old->value;
      else result.erase(result.begin()+i->begin,result.begin()+i->end);
    }
  } else {
    bool present[2]={false,false};
    for(const auto& flag:found) { present[flag.kind]=true; result[flag.position]=flag.kind==0?'1':'2'; }
    if(result.empty()) result={255,254};
    size_t unit=width(result);
    for(unsigned kind=0;kind<2;++kind) if(!present[kind]) {
      if(result.size()>(unit==2?2u:0u) && result[result.size()-unit]!='\n') append(result,"\r\n",unit);
      append(result,tokens[kind]+(kind==0?"1\r\n":"2\r\n"),unit);
    }
  }
  size_t start=width(result)==2?2:0;
  bool empty=result.size()<=start || std::all_of(result.begin()+start,result.end(),[](unsigned char c){return c==0 || c=='\r' || c=='\n' || c==' ';});
  if(saved && !recovery["hadDefaultFile"].asBool() && empty) {
    CloseHandle(file.value); file.value=INVALID_HANDLE_VALUE;
    if(!DeleteFileW(path.c_str())) throw std::runtime_error("Cannot remove temporary RDP preferences");
  } else if(result!=bytes) write(file.value,result);
  if(saved) clearRecovery(config,recovery["id"].asString());
  return saved;
}
#endif
}
struct DefaultSettingsLease::State {
  std::wstring path; std::vector<unsigned char> original,installed; bool existed=true,changed=false,committed=false;
  std::string recoveryConfig,recoveryId; bool active=false;
  ~State();
};
bool settingsInUse() { return activeSettings.load()!=0; }
bool restoreDefaultSettings() {
#ifdef WIN32
  return restore(nativePath(),PortableConfig::executablePath(),false);
#else
  throw std::runtime_error("RDP settings require Windows");
#endif
}
void DefaultSettingsLease::initialize(const std::wstring& path,const std::string& recoveryConfig) {
#ifdef WIN32
  state->path=path;
  File file; file.value=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
  if(file.value==INVALID_HANDLE_VALUE) {
    if(GetLastError()!=ERROR_FILE_NOT_FOUND) throw std::runtime_error("Cannot prepare native RDP preferences");
    file.value=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_HIDDEN,nullptr);
    if(file.value==INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot prepare native RDP preferences");
    state->existed=false;
  }
  state->original=read(file.value); state->installed=state->original;
  if(!state->existed) state->installed={255,254};
  auto found=flags(state->installed); bool present[2]={false,false};
  for(const auto& flag:found) { present[flag.kind]=true; state->installed[flag.position]='0'; }
  size_t unit=width(state->installed);
  for(unsigned kind=0;kind<2;++kind) if(!present[kind]) {
    if(state->installed.size()>(unit==2?2u:0u) && state->installed[state->installed.size()-unit]!='\n') append(state->installed,"\r\n",unit);
    append(state->installed,tokens[kind]+"0\r\n",unit);
  }
  state->changed=!state->existed || state->installed!=state->original;
  if(state->changed && !recoveryConfig.empty()) {
    PortableConfig config(recoveryConfig); auto document=config.read();
    if(!document["rdpRecovery"].isNull()) throw std::runtime_error("Restore the pending RDP settings before connecting.");
    auto originalFlags=flags(state->original);
    if(originalFlags.size()>256) throw std::runtime_error("Too many native RDP prompt settings");
    Json::Value saved; saved["version"]=1; saved["hadDefaultFile"]=state->existed;
    saved["ownerPid"]=Json::UInt(GetCurrentProcessId());
    FILETIME created{},exited{},kernel{},user{};
    if(!GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)) throw std::runtime_error("Cannot identify the RDP recovery owner");
    saved["ownerStarted"]=Json::UInt64((ULONGLONG(created.dwHighDateTime)<<32)|created.dwLowDateTime);
    saved["id"]=std::to_string(GetCurrentProcessId())+":"+std::to_string(GetTickCount64());
    saved["flags"]=Json::Value(Json::arrayValue);
    for(const auto& flag:originalFlags) { Json::Value value; value["kind"]=flag.kind; value["value"]=Json::UInt(flag.value-'0'); saved["flags"].append(value); }
    document["rdpRecovery"]=saved; config.write(document);
    state->recoveryConfig=recoveryConfig; state->recoveryId=saved["id"].asString();
  }
  if(state->changed) write(file.value,state->installed);
  state->committed=true;
  state->active=true; ++activeSettings;
#else
  (void)path;
#endif
}
DefaultSettingsLease::DefaultSettingsLease():state(new State) {
#ifdef WIN32
  auto path=nativePath(); auto config=PortableConfig::executablePath();
  restore(path,config,true);
  initialize(path,config);
#endif
}
#ifdef TIGERVNCS_RDP_TEST
DefaultSettingsLease::DefaultSettingsLease(const std::wstring& path):state(new State) { initialize(path); }
DefaultSettingsLease::DefaultSettingsLease(const std::wstring& path,const std::string& config):state(new State) { restore(path,config,true); initialize(path,config); }
void DefaultSettingsLease::abandonForTest() { state->changed=false; }
bool restoreDefaultSettingsForTest(const std::wstring& path,const std::string& config) { return restore(path,config,false); }
#endif
DefaultSettingsLease::~DefaultSettingsLease()=default;
DefaultSettingsLease::State::~State() {
  if(active) --activeSettings;
#ifdef WIN32
  if(!changed) return;
  try {
    File file; file.value=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file.value==INVALID_HANDLE_VALUE) return;
    auto current=read(file.value), restored=current;
    if(!committed || current==installed) restored=original;
    else {
      auto prior=flags(original), currentFlags=flags(current);
      // Work backwards so deleting appended lines never invalidates offsets.
      for(auto i=currentFlags.rbegin();i!=currentFlags.rend();++i) if(i->value=='0') {
        auto old=std::find_if(prior.rbegin(),prior.rend(),[&](const Flag& f){return f.kind==i->kind;});
        if(old!=prior.rend()) restored[i->position]=old->value;
        else restored.erase(restored.begin()+i->begin,restored.begin()+i->end);
      }
    }
    if(!existed && restored.empty()) {
      CloseHandle(file.value); file.value=INVALID_HANDLE_VALUE; DeleteFileW(path.c_str());
    } else if(restored!=current) write(file.value,restored);
    clearRecovery(recoveryConfig,recoveryId);
  } catch(...) {}
#endif
}
}
