// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_CONNECTION_PROTOCOL_H
#define TIGERVNCS_CONNECTION_PROTOCOL_H
#include <json/json.h>
#include <algorithm>
#include <string>
#include <stdexcept>
namespace connectionProtocol {
inline std::string type(const Json::Value& entry) {
  const auto& value=entry["connectionType"];
  if (value.isNull()) return "vnc";
  if (value != "vnc" && value != "rdp") throw std::runtime_error("Invalid connection type");
  return value.asString();
}
struct RdpEndpoint {
  std::string host; unsigned port=3389;
  std::string address() const { return (host.find(':')==std::string::npos ? host : "["+host+"]")+(port==3389 ? "" : ":"+std::to_string(port)); }
};
inline RdpEndpoint rdpEndpoint(const std::string& address) {
  if (address.empty() || address.size()>1024 || address.find_first_of("/\\@?#\"= \t\r\n")!=std::string::npos ||
      std::any_of(address.begin(),address.end(),[](unsigned char c){return c<32 || c==127;}))
    throw std::runtime_error("Enter an RDP hostname or IP address, optionally followed by :port");
  RdpEndpoint result; std::string port; bool explicitPort=false;
  if (address[0]=='[') {
    auto end=address.find(']'); if(end==std::string::npos) throw std::runtime_error("Invalid RDP IPv6 address");
    result.host=address.substr(1,end-1);
    if(end+1<address.size()) { if(address[end+1]!=':') throw std::runtime_error("Invalid RDP address"); port=address.substr(end+2); explicitPort=true; }
  } else {
    auto colon=address.find(':');
    if(colon!=std::string::npos && address.find(':',colon+1)==std::string::npos) {
      result.host=address.substr(0,colon); port=address.substr(colon+1); explicitPort=true;
    } else result.host=address;
  }
  if(result.host.empty() || result.host[0]=='-' || result.host.find_first_of("[]")!=std::string::npos)
    throw std::runtime_error("Invalid RDP host");
  if(explicitPort) {
    if(port.empty() || port.size()>5 || !std::all_of(port.begin(),port.end(),[](unsigned char c){return c>='0' && c<='9';})) throw std::runtime_error("Invalid RDP port");
    unsigned number=unsigned(std::stoul(port)); if(number<1 || number>65535) throw std::runtime_error("Invalid RDP port"); result.port=number;
  }
  return result;
}
inline bool sameRdpEndpoint(const std::string& a,const std::string& b) {
  auto left=rdpEndpoint(a), right=rdpEndpoint(b);
  auto lower=[](std::string text) { for(auto& c:text) if(c>='A' && c<='Z') c=char(c-'A'+'a'); return text; };
  return left.port==right.port && lower(left.host)==lower(right.host);
}
}
#endif
