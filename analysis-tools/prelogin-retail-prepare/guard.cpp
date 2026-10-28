#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0602
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <netioapi.h>
#include <climits>
#include <iphlpapi.h>
#include <string>
#include <fstream>
#include <sstream>
#include <limits>
#include "network_sample_win.h"
#include "phase_arm.h"
#include "budget_profile.h"
#pragma comment(lib,"iphlpapi.lib")
using std::wstring;
struct Receipt {
 counter_diag::Diagnostics diagnostics;
 std::string status="not_started",mode,source,run,profile="legacy-c10"; bool configured=false,assigned=false,resumed=false,terminate=false,drained=false,metrics=false;
 bool phase=false,ack=false; unsigned long long phase_elapsed=0,phase_delta=0,phase_limit=67108864ULL; DWORD error=0,max_active=0,final_active=0; unsigned long long elapsed=0,delta=0,min_free=0,time_limit=240000,byte_limit=1073741824ULL,reserve=10737418240ULL; long long exit_code=-1;
};
wstring env(const wchar_t* n){DWORD k=GetEnvironmentVariableW(n,nullptr,0);if(!k)return L"";wstring s(k,L'\0');GetEnvironmentVariableW(n,s.data(),k);s.resize(k-1);return s;}
std::string ascii(const wstring&s){std::string r;for(auto c:s){if(c>127)return "";r+=(char)c;}return r;}
bool identity(const std::string&s,bool hash){if(s.empty()||s.size()>(hash?40:30)||(hash&&s.size()!=40))return false;for(char c:s)if(hash?!(c>='0'&&c<='9'||c>='a'&&c<='f'):!(c>='0'&&c<='9'))return false;return true;}
bool fresh(){return env(L"GITHUB_ACTIONS")==L"true"&&env(L"RUNNER_OS")==L"Windows"&&env(L"RUNNER_ENVIRONMENT")==L"github-hosted"&&env(L"GITHUB_EVENT_NAME")==L"push"&&env(L"GITHUB_RUN_ATTEMPT")==L"1"&&env(L"GITHUB_REF")==L"refs/heads/research/prelogin-telemetry-wow-data-provenance"&&env(L"RETAIL_PREPARE")==L"approved-retail-prepare-c10";}
bool network(unsigned long long&n,counter_diag::Sample* s=nullptr){return sample_network(n,s);}
bool disk(unsigned long long&n){auto temp=env(L"RUNNER_TEMP"),sys=env(L"SystemDrive")+L"\\";ULARGE_INTEGER a{},b{};if(temp.empty()||!GetDiskFreeSpaceExW(temp.c_str(),&a,nullptr,nullptr)||!GetDiskFreeSpaceExW(sys.c_str(),&b,nullptr,nullptr))return false;n=a.QuadPart<b.QuadPart?a.QuadPart:b.QuadPart;return true;}
bool active(HANDLE job,DWORD&n){JOBOBJECT_BASIC_ACCOUNTING_INFORMATION i{};if(!QueryInformationJobObject(job,JobObjectBasicAccountingInformation,&i,sizeof(i),nullptr))return false;n=i.ActiveProcesses;return true;}
wstring quote(const wstring&s){if(s.empty()||s.find_first_of(L"\"\r\n")!=wstring::npos)return L"";return L"\""+s+L"\"";}
void output(const Receipt&r){CreateDirectoryW(L"output",nullptr);std::ofstream f("output/retail-supervisor-"+r.mode+".json",std::ios::trunc);auto b=[](bool x){return x?"true":"false";};f<<"{\"schema\":\"bnet-retail-supervisor-5\",\"budget_profile\":\""<<r.profile<<"\",\"source_commit\":\""<<r.source<<"\",\"run_id\":\""<<r.run<<"\",\"mode\":\""<<r.mode<<"\",\"status\":\""<<r.status<<"\",\"job_kill_on_close_configured\":"<<b(r.configured)<<",\"child_assigned_before_resume\":"<<b(r.assigned)<<",\"child_resumed\":"<<b(r.resumed)<<",\"termination_requested\":"<<b(r.terminate)<<",\"job_drained\":"<<b(r.drained)<<",\"metrics_available\":"<<b(r.metrics)<<",\"max_active_processes\":"<<r.max_active<<",\"final_active_processes\":"<<r.final_active<<",\"root_exit_code\":"<<(r.exit_code<0?"null":std::to_string(r.exit_code))<<",\"win32_error\":"<<r.error<<",\"elapsed_ms\":"<<r.elapsed<<",\"time_limit_ms\":"<<r.time_limit<<",\"network_threshold_bytes\":"<<r.byte_limit<<",\"network_delta_bytes\":"<<r.delta<<",\"minimum_free_bytes\":"<<r.min_free<<",\"disk_reserve_bytes\":"<<r.reserve<<",\"poll_interval_ms\":250,\"network_scope\":\""<<(r.mode=="observe"?"hostwide_adapter_counters":"synthetic_fixture")<<"\",\"hard_network_byte_cap\":false,\"game_transfer_request_proven_by_supervisor\":false,\"transfer_phase_signal_seen\":"<<b(r.phase)<<",\"phase_elapsed_ms\":"<<r.phase_elapsed<<",\"phase_network_delta_bytes\":"<<r.phase_delta<<",\"phase_time_limit_ms\":30000,\"phase_network_threshold_bytes\":"<<r.phase_limit<<",\"phase_arming_acknowledged\":"<<b(r.ack)<<",\"phase_baseline_policy\":\"acknowledged_pre_request_snapshot\",\"network_diagnostics\":";r.diagnostics.json(f);f<<"}\n";}
bool acknowledge(){
 HANDLE f=CreateFileW(L"output/retail-transfer-ready.tmp",GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(f==INVALID_HANDLE_VALUE)return false;DWORD written=0;const char text[]="ready\n";
 bool ok=WriteFile(f,text,6,&written,nullptr)&&written==6&&FlushFileBuffers(f);CloseHandle(f);if(!ok)return false;return MoveFileExW(L"output/retail-transfer-ready.tmp",L"output/retail-transfer-ready.signal",MOVEFILE_WRITE_THROUGH)!=0;
}
int wmain(int argc,wchar_t**argv){
 if(argc<2)return 2;wstring mode=argv[1];
 if(mode==L"fixture-grandchild"){Sleep(300000);return 0;}
 if(mode==L"fixture-child"){
  wchar_t self[32768];DWORD n=GetModuleFileNameW(nullptr,self,32768);if(!n||n>=32768)return 2;wstring cmd=quote(self)+L" fixture-grandchild";STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
  if(!CreateProcessW(self,cmd.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&si,&pi))return 3;CloseHandle(pi.hThread);CloseHandle(pi.hProcess);Sleep(300000);return 0;
 }
 if(mode!=L"observe"&&mode!=L"fixture_timeout"&&mode!=L"fixture_network"&&mode!=L"fixture_disk"&&mode!=L"fixture_phase_timeout"&&mode!=L"fixture_phase_network")return 2;
 Receipt r;r.mode=ascii(mode);r.source=ascii(env(L"GITHUB_SHA"));r.run=ascii(env(L"GITHUB_RUN_ID"));if(!identity(r.source,true)||!identity(r.run,false))return 2;
 if(!fresh()){r.status="environment_refused";output(r);return 2;}
 bool fixture=mode!=L"observe";r.time_limit=fixture?3000:240000;
 retail_budget::Limits limits;auto requested=env(L"RETAIL_BUDGET_PROFILE");
 if(!retail_budget::select(ascii(requested),fixture,limits)||!fixture&&!requested.empty()&&ascii(requested).empty()){r.status="environment_refused";output(r);return 2;}
 r.byte_limit=limits.total;r.phase_limit=limits.phase;
 if(!fixture&&!requested.empty())r.profile=ascii(requested);
 if(mode==L"fixture_network")r.byte_limit=2;
 HANDLE job=nullptr;PROCESS_INFORMATION pi{};unsigned long long start=GetTickCount64(),net0=0,last_net=0,phase_start=0,phase_net0=0;PhaseArm arm;
 auto finish=[&](){
  if(job){r.terminate=true;if(!TerminateJobObject(job,125)){r.error=GetLastError();r.status="cleanup_failed";}auto deadline=GetTickCount64()+5000;DWORD n=0;while(GetTickCount64()<deadline){if(!active(job,n)){r.status="cleanup_failed";break;}r.final_active=n;if(!n){r.drained=true;break;}Sleep(50);}if(!r.drained)r.status="cleanup_failed";}
  if(pi.hProcess){WaitForSingleObject(pi.hProcess,1000);DWORD code=STILL_ACTIVE;if(GetExitCodeProcess(pi.hProcess,&code)&&code!=STILL_ACTIVE)r.exit_code=code;CloseHandle(pi.hProcess);}if(pi.hThread)CloseHandle(pi.hThread);if(job)CloseHandle(job);r.elapsed=GetTickCount64()-start;output(r);
 };
 unsigned long long free0=0;counter_diag::Sample initial_sample;
 if(!fixture&&(!network(net0,&initial_sample)||!disk(free0))){r.status="metrics_failed";finish();return 2;}if(!fixture&&free0<r.reserve){r.status="disk_limit";r.min_free=free0;finish();return 2;}r.metrics=true;r.min_free=fixture?r.reserve+1:free0;last_net=net0;if(!fixture)r.diagnostics.observe(initial_sample);
 job=CreateJobObjectW(nullptr,nullptr);JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
 if(!job||!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&info,sizeof(info))){r.error=GetLastError();r.status="assignment_failed";finish();return 2;}r.configured=true;
 wchar_t self[32768];DWORD selflen=GetModuleFileNameW(nullptr,self,32768);wstring app,cmd;
 if(fixture){if(!selflen||selflen>=32768){r.status="launch_failed";finish();return 2;}app=self;cmd=quote(app)+L" fixture-child";}
 else {if(argc!=3){r.status="launch_failed";finish();return 2;}app=argv[2];auto script=env(L"GITHUB_WORKSPACE")+L"\\analysis-tools\\prelogin-retail-prepare\\run_prepare.py";if(quote(app).empty()||quote(script).empty()){r.status="launch_failed";finish();return 2;}cmd=quote(app)+L" "+quote(script);}
 if(!fixture&&!SetEnvironmentVariableW(L"RETAIL_SUPERVISED",L"job-c10")){r.status="launch_failed";finish();return 2;}
 STARTUPINFOW si{};si.cb=sizeof(si);
 if(!CreateProcessW(app.c_str(),cmd.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED,nullptr,nullptr,&si,&pi)){r.error=GetLastError();r.status="launch_failed";finish();return 2;}
 if(!AssignProcessToJobObject(job,pi.hProcess)){r.error=GetLastError();r.status="assignment_failed";TerminateProcess(pi.hProcess,125);finish();return 2;}r.assigned=true;
 if(ResumeThread(pi.hThread)==(DWORD)-1){r.error=GetLastError();r.status="resume_failed";finish();return 2;}r.resumed=true;
 while(true){
  DWORD n=0;if(!active(job,n)){r.error=GetLastError();r.status="monitor_failed";break;}if(n>r.max_active)r.max_active=n;
  unsigned long long elapsed=GetTickCount64()-start;
  if(!fixture&&!r.phase&&GetFileAttributesW(L"output/retail-transfer-active.signal")!=INVALID_FILE_ATTRIBUTES){r.phase=true;}
  if(!fixture){unsigned long long now=0,free=0;counter_diag::Sample current_sample;if(!network(now,&current_sample)){r.status="metrics_failed";break;}r.diagnostics.observe(current_sample,r.phase&&!r.ack);if(now<last_net||!disk(free)){r.status="metrics_failed";break;}last_net=now;r.delta=now-net0;if(r.phase&&!arm.armed){arm.arm(now,current_sample.tick);phase_net0=arm.baseline;phase_start=arm.start;}if(r.phase){r.phase_delta=now-phase_net0;r.phase_elapsed=GetTickCount64()-phase_start;}if(free<r.min_free)r.min_free=free;}
  else if(n>=2&&elapsed>=500){if(mode==L"fixture_network")r.delta=3;if(mode==L"fixture_disk")r.min_free=0;if(mode==L"fixture_phase_timeout"){r.phase=true;r.phase_elapsed=30001;}if(mode==L"fixture_phase_network"){r.phase=true;r.phase_delta=67108865;}}
  if(r.phase&&r.phase_delta>=r.phase_limit){r.status="phase_network_limit";break;}
  if(r.phase&&r.phase_elapsed>=30000){r.status="phase_time_limit";break;}
  if(r.min_free<r.reserve){r.status="disk_limit";break;}
  if(r.delta>=r.byte_limit){r.status="network_limit";break;}
  if(elapsed>=r.time_limit){r.status="time_limit";break;}
  if(!fixture&&r.phase&&!r.ack){if(!arm.armed||!acknowledge()){r.status="monitor_failed";break;}r.ack=true;}
  DWORD code=STILL_ACTIVE;if(!GetExitCodeProcess(pi.hProcess,&code)){r.status="monitor_failed";break;}if(code!=STILL_ACTIVE){r.exit_code=code;r.status=code==0?"worker_completed":"worker_failed";break;}
  Sleep(250);
 }
 finish();bool ok=fixture?(r.drained&&r.max_active>=2&&r.status==(mode==L"fixture_timeout"?"time_limit":mode==L"fixture_network"?"network_limit":mode==L"fixture_disk"?"disk_limit":mode==L"fixture_phase_timeout"?"phase_time_limit":"phase_network_limit")):(r.status=="worker_completed"&&r.drained);return ok?0:2;
}
