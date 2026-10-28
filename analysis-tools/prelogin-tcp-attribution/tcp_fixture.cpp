#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <fstream>
#include <vector>
#include <thread>
#include <string>
#include <atomic>
#include "../prelogin-retail-prepare/network_sample_win.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")
struct Stats { unsigned long long in=0,out=0,received=0,acked=0; };
struct Result {
 std::string status="not_started"; unsigned long error=0;
 bool owner=false,enabled=false,control_enabled=false,content=false,control_clean=false;
 unsigned long long sent=0,received=0,adapter_delta=0;
 Stats before,after,control_before,control_after;
};
struct Socket { SOCKET s=INVALID_SOCKET; ~Socket(){if(s!=INVALID_SOCKET)closesocket(s);} };
bool valid(const std::string& s,bool hash){if(s.empty()||s.size()>(hash?40:30)||(hash&&s.size()!=40))return false;for(char c:s)if(hash?!(c>='0'&&c<='9'||c>='a'&&c<='f'):!(c>='0'&&c<='9'))return false;return true;}
void timeout(SOCKET s){DWORD ms=2000;setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&ms,sizeof(ms));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(char*)&ms,sizeof(ms));}
bool tuple(SOCKET s,MIB_TCPROW& row){
 sockaddr_in local{},remote{};int z=sizeof(local);
 if(getsockname(s,(sockaddr*)&local,&z)||getpeername(s,(sockaddr*)&remote,&z))return false;
 ULONG size=0;GetExtendedTcpTable(nullptr,&size,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
 if(size<4||size>16*1024*1024)return false;std::vector<unsigned char>b(size);
 if(GetExtendedTcpTable(b.data(),&size,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0))return false;
 auto t=(PMIB_TCPTABLE_OWNER_PID)b.data();unsigned int found=0;
 for(DWORD i=0;i<t->dwNumEntries;i++){auto&r=t->table[i];
  if(r.dwOwningPid==GetCurrentProcessId()&&r.dwState==MIB_TCP_STATE_ESTAB&&r.dwLocalAddr==local.sin_addr.s_addr&&r.dwRemoteAddr==remote.sin_addr.s_addr&&r.dwLocalPort==local.sin_port&&r.dwRemotePort==remote.sin_port){
   row={r.dwState,r.dwLocalAddr,r.dwLocalPort,r.dwRemoteAddr,r.dwRemotePort};++found;
  }
 }
 return found==1;
}
ULONG enable(MIB_TCPROW& row){TCP_ESTATS_DATA_RW_v0 rw{};rw.EnableCollection=TRUE;return SetPerTcpConnectionEStats(&row,TcpConnectionEstatsData,(PUCHAR)&rw,0,sizeof(rw),0);}
ULONG read_stats(MIB_TCPROW& row,Stats& s){
 TCP_ESTATS_DATA_RW_v0 rw{};TCP_ESTATS_DATA_ROD_v0 rod{};
 ULONG e=GetPerTcpConnectionEStats(&row,TcpConnectionEstatsData,(PUCHAR)&rw,0,sizeof(rw),nullptr,0,0,(PUCHAR)&rod,0,sizeof(rod));
 if(e)return e;if(rw.EnableCollection!=TRUE)return ERROR_INVALID_STATE;
 s={rod.DataBytesIn,rod.DataBytesOut,rod.ThruBytesReceived,rod.ThruBytesAcked};return 0;
}
bool connect_pair(Socket& listener,Socket& client,Socket& server){
 listener.s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);client.s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
 if(listener.s==INVALID_SOCKET||client.s==INVALID_SOCKET)return false;
 sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=0;
 if(bind(listener.s,(sockaddr*)&a,sizeof(a))||listen(listener.s,1))return false;
 int z=sizeof(a);if(getsockname(listener.s,(sockaddr*)&a,&z)||connect(client.s,(sockaddr*)&a,sizeof(a)))return false;
 server.s=accept(listener.s,nullptr,nullptr);if(server.s==INVALID_SOCKET)return false;
 timeout(client.s);timeout(server.s);return true;
}
bool send_pattern(SOCKET s,size_t n,char c,unsigned long long& total){
 std::vector<char>b(16384,c);while(n){int k=send(s,b.data(),(int)(n<b.size()?n:b.size()),0);if(k<=0)return false;n-=k;total+=k;}return true;
}
bool recv_pattern(SOCKET s,size_t n,char c,unsigned long long& total){
 std::vector<char>b(16384);while(n){int k=recv(s,b.data(),(int)(n<b.size()?n:b.size()),0);if(k<=0)return false;for(int i=0;i<k;i++)if(b[i]!=c)return false;n-=k;total+=k;}return true;
}
void run(Result&r){
 WSADATA w{};if(WSAStartup(MAKEWORD(2,2),&w)){r.status="socket_failed";return;}
 // All four connected endpoints are owned by this process; only client rows are counted.
 Socket l,c,s,cl,cc,cs;if(!connect_pair(l,c,s)||!connect_pair(cl,cc,cs)){r.status="socket_failed";return;}
 MIB_TCPROW row{},control{};
 if(!tuple(c.s,row)||!tuple(cc.s,control)){r.status="owner_refused";return;}r.owner=true;
 r.error=enable(row);if(r.error){r.status="enable_failed";return;}
 r.error=enable(control);if(r.error){r.status="enable_failed";return;}
 r.error=read_stats(row,r.before);if(r.error){r.status="read_failed";return;}r.enabled=true;
 r.error=read_stats(control,r.control_before);if(r.error){r.status="read_failed";return;}r.control_enabled=true;
 unsigned long long n0=0,n1=0;if(!sample_network(n0)){r.status="adapter_failed";return;}
 std::atomic<bool> server_ok{false};unsigned long long server_sent=0,server_received=0;
 std::thread server([&]{server_ok=send_pattern(s.s,1048576,0x5a,server_sent)&&recv_pattern(s.s,65536,0x25,server_received);});
 bool client_ok=recv_pattern(c.s,1048576,0x5a,r.received)&&send_pattern(c.s,65536,0x25,r.sent);
 server.join();r.content=server_ok&&client_ok&&server_sent==1048576&&server_received==65536;
 if(!r.content){r.status="transfer_failed";return;}
 Sleep(100); // permit cumulative ACK counters to settle; endpoints remain open
 if(!tuple(c.s,row)||!tuple(cc.s,control)){r.status="owner_refused";return;}
 r.error=read_stats(row,r.after);if(r.error){r.status="read_failed";return;}
 r.error=read_stats(control,r.control_after);if(r.error){r.status="read_failed";return;}
 if(!sample_network(n1)||n1<n0){r.status="adapter_failed";return;}r.adapter_delta=n1-n0;
 r.control_clean=r.control_after.in==r.control_before.in&&r.control_after.out==r.control_before.out&&r.control_after.received==r.control_before.received&&r.control_after.acked==r.control_before.acked;
 if(r.after.in<r.before.in||r.after.out<r.before.out||r.after.received<r.before.received||r.after.acked<r.before.acked){r.status="counter_decreased";return;}
 r.status=(r.control_clean&&r.after.in-r.before.in==1048576&&r.after.out-r.before.out==65536&&r.after.received-r.before.received==1048576&&r.after.acked-r.before.acked==65536)?"calibrated":"counter_mismatch";
}
int main(int argc,char**argv){
 if(argc!=3||!valid(argv[1],true)||!valid(argv[2],false))return 2;
 Result r;try{run(r);}catch(...){r.status="other";}WSACleanup();
 auto b=[](bool x){return x?"true":"false";};
 std::ofstream f("output/tcp-fixture.json");
 f<<"{\"schema\":\"bnet-tcp-fixture-1\",\"source_commit\":\""<<argv[1]<<"\",\"run_id\":\""<<argv[2]<<"\",\"status\":\""<<r.status<<"\",\"win32_error\":"<<r.error
 <<",\"owner_verified\":"<<b(r.owner)<<",\"collection_enabled\":"<<b(r.enabled)<<",\"control_collection_enabled\":"<<b(r.control_enabled)<<",\"content_verified\":"<<b(r.content)<<",\"control_unchanged\":"<<b(r.control_clean)
 <<",\"application_received_bytes\":"<<r.received<<",\"application_sent_bytes\":"<<r.sent
 <<",\"data_bytes_in_delta\":"<<(r.after.in>=r.before.in?r.after.in-r.before.in:0)<<",\"data_bytes_out_delta\":"<<(r.after.out>=r.before.out?r.after.out-r.before.out:0)
 <<",\"thru_bytes_received_delta\":"<<(r.after.received>=r.before.received?r.after.received-r.before.received:0)<<",\"thru_bytes_acked_delta\":"<<(r.after.acked>=r.before.acked?r.after.acked-r.before.acked:0)
 <<",\"hostwide_adapter_delta_bytes\":"<<r.adapter_delta<<",\"loopback_only\":true,\"external_transfer_requested\":false,\"battle_net_launched\":false,\"raw_endpoints_exported\":false,\"payload_exported\":false,\"production_limits_changed\":false}\n";
 return r.status=="calibrated"?0:2;
}
