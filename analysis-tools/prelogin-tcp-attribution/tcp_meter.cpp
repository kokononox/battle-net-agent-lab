#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include "estats_common.h"
#include <fstream>
#include <vector>
#include <string>
#include <set>
#include <array>
#include <cstdlib>
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
using Key=std::array<DWORD,4>;
struct Conn {MIB_TCPROW row{};Stats baseline{},last{};};
struct Report {
 std::string status="not_started",source,run;DWORD error=0;unsigned long long start=0,ms=0,polls=0;
 unsigned int tracked=0,failed=0,changes=0,resets=0;
 bool handle=false,listener=false,ready=false;Stats delta{};
};
bool number(const char*s,unsigned long&out){if(!s||!*s)return false;unsigned long long n=0;for(const char*p=s;*p;p++){if(*p<'0'||*p>'9')return false;n=n*10+(*p-'0');if(n>0xffffffffULL)return false;}out=(unsigned long)n;return n>0;}
bool identity(const std::string&s,bool hash){if(s.empty()||s.size()>(hash?40:30)||(hash&&s.size()!=40))return false;for(char c:s)if(hash?!(c>='0'&&c<='9'||c>='a'&&c<='f'):!(c>='0'&&c<='9'))return false;return true;}
Key key(const MIB_TCPROW&r){return {r.dwLocalAddr,r.dwLocalPort,r.dwRemoteAddr,r.dwRemotePort};}
bool rows(DWORD pid,DWORD port,std::vector<MIB_TCPROW>&out){
 ULONG z=0;GetExtendedTcpTable(nullptr,&z,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);if(z<4||z>16*1024*1024)return false;
 std::vector<unsigned char>b(z);if(GetExtendedTcpTable(b.data(),&z,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0))return false;
 auto t=(PMIB_TCPTABLE_OWNER_PID)b.data();if(t->dwNumEntries>65536||FIELD_OFFSET(MIB_TCPTABLE_OWNER_PID,table)+(size_t)t->dwNumEntries*sizeof(MIB_TCPROW_OWNER_PID)>z)return false;
 unsigned int listening=0;out.clear();
 for(DWORD i=0;i<t->dwNumEntries;i++){auto&r=t->table[i];if(r.dwOwningPid!=pid)continue;
  if(r.dwState==MIB_TCP_STATE_LISTEN&&ntohs((u_short)r.dwLocalPort)==port&&(r.dwLocalAddr==0||r.dwLocalAddr==htonl(INADDR_LOOPBACK)))++listening;
  if(r.dwState!=MIB_TCP_STATE_ESTAB||r.dwRemoteAddr==0||(ntohl(r.dwRemoteAddr)>>24)==127)continue;
  if(out.size()>=128)return false;
  out.push_back({r.dwState,r.dwLocalAddr,r.dwLocalPort,r.dwRemoteAddr,r.dwRemotePort});
 }
 return listening==1;
}
void write(const Report&r){
 auto b=[](bool v){return v?"true":"false";};
 std::ofstream f("output/tcp-meter.tmp",std::ios::trunc);
 f<<"{\"schema\":\"bnet-owned-tcp-meter-1\",\"source_commit\":\""<<r.source<<"\",\"run_id\":\""<<r.run<<"\",\"status\":\""<<r.status<<"\",\"win32_error\":"<<r.error
 <<",\"process_handle_held\":"<<b(r.handle)<<",\"listener_owner_verified\":"<<b(r.listener)<<",\"baseline_ready\":"<<b(r.ready)
 <<",\"tracked_connections\":"<<r.tracked<<",\"polls\":"<<r.polls<<",\"elapsed_ms\":"<<r.ms<<",\"failed_reads\":"<<r.failed<<",\"connection_set_changes\":"<<r.changes<<",\"counter_resets\":"<<r.resets
 <<",\"data_bytes_in_delta\":"<<r.delta.in<<",\"data_bytes_out_delta\":"<<r.delta.out<<",\"thru_bytes_received_delta\":"<<r.delta.received<<",\"thru_bytes_acked_delta\":"<<r.delta.acked
 <<",\"scope\":\"baseline_owned_external_ipv4_tcp_connections\",\"window\":\"pre_arm_baseline_to_last_checkpoint\",\"all_process_traffic_covered\":false,\"hardware_payload_proven\":false,\"raw_endpoints_exported\":false,\"payload_exported\":false,\"production_limits_changed\":false}\n";
 f.close();MoveFileExW(L"output/tcp-meter.tmp",L"output/tcp-meter.json",MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);
}
void run(Report&r,DWORD pid,DWORD port){
 HANDLE h=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!h){r.status="owner_refused";return;}r.handle=true;
 struct Close {HANDLE h;~Close(){CloseHandle(h);}}close{h};
 std::vector<MIB_TCPROW> current;if(WaitForSingleObject(h,0)!=WAIT_TIMEOUT||!rows(pid,port,current)){r.status="owner_refused";return;}r.listener=true;
 std::vector<Conn> c;std::set<Key> initial;
 for(auto row:current){Conn v;v.row=row;if(!initial.insert(key(row)).second){r.status="owner_refused";return;}
  r.error=enable(v.row);if(r.error){r.status="enable_failed";return;}
  r.error=read_stats(v.row,v.baseline);if(r.error){r.status="read_failed";return;}v.last=v.baseline;c.push_back(v);
 }
 if(c.empty()){r.status="no_connections";return;}
 r.tracked=(unsigned int)c.size();r.start=GetTickCount64();r.ready=true;r.status="observing";write(r);
 {std::ofstream f("output/tcp-meter-ready.tmp");f<<"ready\n";f.close();if(!MoveFileExW(L"output/tcp-meter-ready.tmp",L"output/tcp-meter-ready.signal",MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){r.status="write_failed";return;}}
 for(unsigned int k=0;k<200;k++){
  if(WaitForSingleObject(h,0)!=WAIT_TIMEOUT||!rows(pid,port,current)){r.status="owner_refused";return;}
  std::set<Key> now;for(const auto& row:current)now.insert(key(row));if(now!=initial){++r.changes;r.status="connection_set_changed";return;}
  Stats sum{};
  for(auto&v:c){Stats s{};r.error=read_stats(v.row,s);if(r.error){++r.failed;r.status="read_failed";return;}
   if(s.in<v.last.in||s.out<v.last.out||s.received<v.last.received||s.acked<v.last.acked){++r.resets;r.status="counter_reset";return;}
   v.last=s;sum.in+=s.in-v.baseline.in;sum.out+=s.out-v.baseline.out;sum.received+=s.received-v.baseline.received;sum.acked+=s.acked-v.baseline.acked;
  }
  r.delta=sum;r.ms=GetTickCount64()-r.start;++r.polls;write(r);
  if(GetFileAttributesW(L"output/tcp-meter-stop.signal")!=INVALID_FILE_ATTRIBUTES){r.status="completed";return;}
  Sleep(25);
 }
 r.status="time_limit";
}
int main(int argc,char**argv){
 if(argc!=3||!identity(argv[1],true)||!identity(argv[2],false))return 2;
 const char*a=getenv("RETAIL_SUPERVISED"),*b=getenv("RETAIL_PREPARE");if(!a||std::string(a)!="job-c10"||!b||std::string(b)!="approved-retail-prepare-c10")return 2;
 DWORD pid=0,port=0;if(!number(getenv("TCP_METER_PID"),pid)||!number(getenv("TCP_METER_PORT"),port)||port>65535)return 2;
 Report r;r.source=argv[1];r.run=argv[2];try{run(r,pid,port);}catch(...){r.status="other";}write(r);
 return r.status=="completed"?0:2;
}
