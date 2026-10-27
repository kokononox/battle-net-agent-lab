#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0602
#include "network_sample_win.h"
#include <fstream>
#include <string>
// Only reads adapter counters. It cannot launch Setup/Agent or send HTTP requests.
bool valid(const std::string& s,bool hash){if(s.empty()||s.size()>(hash?40:30)||(hash&&s.size()!=40))return false;for(char c:s)if(hash?!(c>='0'&&c<='9'||c>='a'&&c<='f'):!(c>='0'&&c<='9'))return false;return true;}
int main(int argc,char** argv){
 if(argc!=3||!valid(argv[1],true)||!valid(argv[2],false))return 2;
 counter_diag::Diagnostics d;std::string status="observed";unsigned long long previous=0;
 for(unsigned int i=0;i<=32;++i){
  counter_diag::Sample s;unsigned long long total=0;
  if(!sample_network(total,&s)){status="metrics_failed";break;}
  d.observe(s,i==8);
  if(i&&total<previous){status="counter_decreased";break;}
  previous=total;if(i!=32)Sleep(250);
 }
 CreateDirectoryW(L"output",nullptr);std::ofstream out("output/counter-native.json");
 out<<"{\"schema\":\"bnet-counter-native-1\",\"source_commit\":\""<<argv[1]<<"\",\"run_id\":\""<<argv[2]
    <<"\",\"status\":\""<<status<<"\",\"network_scope\":\"hostwide_adapter_counters\",\"boundary_kind\":\"synthetic_observation_marker\",\"target_launched\":false,\"transfer_requested\":false,\"diagnostics\":";
 d.json(out);out<<"}\n";
 return status=="observed"?0:2;
}
