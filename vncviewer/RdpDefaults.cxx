// SPDX-License-Identifier: GPL-2.0-or-later
#include "RdpDefaults.h"
#include <vector>
#include <stdexcept>
#include <algorithm>
#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#endif
namespace rdpClient {
namespace {
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
#endif
}
struct DefaultSettingsLease::State {
  std::wstring path; std::vector<unsigned char> original,installed; bool existed=true,changed=false,committed=false;
  ~State();
};
void DefaultSettingsLease::initialize(const std::wstring& path) {
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
  if(state->changed) write(file.value,state->installed);
  state->committed=true;
#else
  (void)path;
#endif
}
DefaultSettingsLease::DefaultSettingsLease():state(new State) {
#ifdef WIN32
  wchar_t directory[MAX_PATH];
  if(FAILED(SHGetFolderPathW(nullptr,CSIDL_PERSONAL,nullptr,SHGFP_TYPE_CURRENT,directory))) throw std::runtime_error("Cannot locate native RDP preferences");
  initialize(std::wstring(directory)+L"\\Default.rdp");
#endif
}
#ifdef TIGERVNCS_RDP_TEST
DefaultSettingsLease::DefaultSettingsLease(const std::wstring& path):state(new State) { initialize(path); }
#endif
DefaultSettingsLease::~DefaultSettingsLease()=default;
DefaultSettingsLease::State::~State() {
#ifdef WIN32
  if(!changed) return;
  try {
    File file; file.value=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file.value==INVALID_HANDLE_VALUE) return;
    auto current=read(file.value), restored=current;
    if(!committed || current==installed) restored=original;
    else {
      auto prior=flags(original), active=flags(current);
      // Work backwards so deleting appended lines never invalidates offsets.
      for(auto i=active.rbegin();i!=active.rend();++i) if(i->value=='0') {
        auto old=std::find_if(prior.rbegin(),prior.rend(),[&](const Flag& f){return f.kind==i->kind;});
        if(old!=prior.rend()) restored[i->position]=old->value;
        else restored.erase(restored.begin()+i->begin,restored.begin()+i->end);
      }
    }
    if(!existed && restored.empty()) {
      CloseHandle(file.value); file.value=INVALID_HANDLE_VALUE; DeleteFileW(path.c_str());
    } else if(restored!=current) write(file.value,restored);
  } catch(...) {}
#endif
}
}
