#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0a00
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "marker.h"
#include "decision.h"
#define VERSION "0.2.0"
#define MSG_STAGE (WM_APP+1)
#define MSG_DONE (WM_APP+2)
#define MSG_SCAN (WM_APP+3)
#define CAP (1024*1024)
static HWND win,startbtn,openbtn,statusctl,targetsctl,refreshbtn;
static HFONT bodyfont,titlefont;
static HBRUSH white;
static volatile LONG busy=0;
static HANDLE workerhandle;
static WCHAR outdir[1024];
static int scale=100;
static int px(int x){return MulDiv(x,scale,100);}
typedef struct {DWORD pid;FILETIME creation;} Candidate;
static Candidate candidates[32],selected;
static size_t candidate_count;
static const WCHAR *states[]={
 L"بازی را انتخاب کنید؛ اتصال فقط پس از تأیید شما انجام می‌شود.",
 L"در حال پیدا کردن دیباگر…",
 L"در حال تطبیق هویت و هش فایل بازی با بیلد آزمایش‌شده…",
 L"در حال اتصال کوتاه و جداشدن دیباگر…",
 L"در حال بررسی زنده‌بودن بازی و ذخیرهٔ نتیجه…"
};
typedef struct {
 const char *stage;
 DWORD error,debugger_exit,target_pid;
 int debugger_found,marker_seen,debugger_exited;
 int target_alive_after_detach,forced_cleanup,output_truncated;
 int passed,saved,job_assigned,consent,identity_verified,debugger_launched;
 int target_query_ok,hash_computed,access_denied_hint,already_debugged_hint;
 int target_liveness_checked;
 char target_sha[65];
 DWORD ver[4];
} Result;
static void stage(int n){PostMessageW(win,MSG_STAGE,n,0);}
static int make_nonce(WCHAR *wide,char *narrow) {
 unsigned char bytes[16];
 if(BCryptGenRandom(NULL,bytes,sizeof(bytes),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0) return 0;
 for(int i=0;i<16;i++) sprintf(narrow+i*2,"%02x",bytes[i]);
 MultiByteToWideChar(CP_UTF8,0,narrow,-1,wide,33); return 1;
}
static int isfile(const WCHAR *p) {DWORD a=GetFileAttributesW(p);return a!=INVALID_FILE_ATTRIBUTES && !(a&FILE_ATTRIBUTE_DIRECTORY);}
static int find_cdb(WCHAR *path) {
 WCHAR root[768];DWORD n=sizeof(root),type=0;
 HKEY key;
 if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots",0,KEY_READ|KEY_WOW64_32KEY,&key)==ERROR_SUCCESS){
  LONG e=RegQueryValueExW(key,L"KitsRoot10",NULL,&type,(LPBYTE)root,&n);RegCloseKey(key);
  if(e==ERROR_SUCCESS && type==REG_SZ && n>sizeof(WCHAR) && n<sizeof(root)) {
   root[n/sizeof(WCHAR)-1]=0;
   _snwprintf(path,1024,L"%ls%lsDebuggers\\x64\\cdb.exe",root,root[wcslen(root)-1]=='\\'?L"":L"\\");
   if(isfile(path)) return 1;
  }
 }
 DWORD l=GetEnvironmentVariableW(L"ProgramFiles(x86)",root,768);
 if(l>0 && l<768) {
  _snwprintf(path,1024,L"%ls\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe",root);
  if(isfile(path))return 1;
 }
 return 0;
}
static void get_version(const WCHAR *p,Result *r) {
 DWORD unused=0,n=GetFileVersionInfoSizeW(p,&unused);if(!n || n>1024*1024)return;
 void *v=malloc(n);if(!v)return;
 VS_FIXEDFILEINFO *f=NULL;UINT size=0;
 if(GetFileVersionInfoW(p,0,n,v)&&VerQueryValueW(v,L"\\",(void**)&f,&size)&&size>=sizeof(*f)&&f->dwSignature==0xfeef04bd){
 r->ver[0]=HIWORD(f->dwFileVersionMS);r->ver[1]=LOWORD(f->dwFileVersionMS);
 r->ver[2]=HIWORD(f->dwFileVersionLS);r->ver[3]=LOWORD(f->dwFileVersionLS);
 }free(v);
}
static int create_output(void) {
 WCHAR root[MAX_PATH],nonceW[33];char nonce[33]; SYSTEMTIME t;
 if(FAILED(SHGetFolderPathW(NULL,CSIDL_LOCAL_APPDATA,NULL,SHGFP_TYPE_CURRENT,root)))return 0;
 if(!make_nonce(nonceW,nonce))return 0;
 WCHAR base[1024];_snwprintf(base,1024,L"%ls\\WLab-OneClick",root);
 if(!CreateDirectoryW(base,NULL)&&GetLastError()!=ERROR_ALREADY_EXISTS)return 0;
 GetLocalTime(&t);
 _snwprintf(outdir,1024,L"%ls\\%04u%02u%02u-%02u%02u%02u-%.8ls",base,t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,nonceW);
 return CreateDirectoryW(outdir,NULL)!=0;
}
static int write_bytes(const WCHAR *name,const char *data,DWORD n) {
 WCHAR path[1200];_snwprintf(path,1200,L"%ls\\%ls",outdir,name);
 HANDLE f=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(f==INVALID_HANDLE_VALUE)return 0;
 DWORD done=0;BOOL ok=WriteFile(f,data,n,&done,NULL);if(ok)ok=FlushFileBuffers(f);CloseHandle(f);
 if(!ok||done!=n){DeleteFileW(path);return 0;}return 1;
}
static void drain(HANDLE pipe,char *log,size_t *used,Result *r) {
 char chunk[8192];DWORD avail=0,n=0;
 /* Bound each pass, so a noisy child cannot prevent the timeout check. */
 for(int i=0;i<64;i++){
  if(!PeekNamedPipe(pipe,NULL,0,NULL,&avail,NULL)||!avail)break;
  if(!ReadFile(pipe,chunk,avail<sizeof(chunk)?avail:sizeof(chunk),&n,NULL)||!n)break;
  size_t keep=n;if(keep>CAP-*used){keep=CAP-*used;r->output_truncated=1;}
  if(keep){memcpy(log+*used,chunk,keep);*used+=keep;}
 }
}
static const char *b(int x){return x?"true":"false";}
static int save_result(Result *r){
 char buf[8192];SYSTEMTIME t;GetSystemTime(&t);
 int n=snprintf(buf,sizeof(buf),
 "{\n  \"tool\": \"WLab-OneClick\",\n  \"version\": \"" VERSION "\",\n"
 "  \"utc\": \"%04u-%02u-%02uT%02u:%02u:%02uZ\",\n"
 "  \"test_scope\": \"explicitly_confirmed_game_attach_detach\",\n"
 "  \"status\": \"%s\",\n  \"stage\": \"%s\",\n  \"win32_error\": %lu,\n"
 "  \"user_confirmed\": %s,\n  \"target_pid\": %lu,\n  \"target_query_ok\": %s,\n"
 "  \"target_hash_computed\": %s,\n  \"target_sha256\": \"%s\",\n  \"target_identity_verified\": %s,\n"
 "  \"approved_build\": \"12.1.5.70448\",\n  \"debugger_found\": %s,\n"
 "  \"debugger_file_version\": \"%lu.%lu.%lu.%lu\",\n  \"debugger_launched\": %s,\n"
 "  \"game_attach_attempted\": %s,\n  \"detach_on_debugger_exit_option\": true,\n"
 "  \"standalone_marker_seen\": %s,\n  \"debugger_exited\": %s,\n  \"debugger_exit_code\": %lu,\n"
 "  \"marker_requires_matching_debugger_target_pid\": true,\n"
 "  \"target_liveness_checked\": %s,\n  \"target_alive_after_detach\": %s,\n  \"debugger_forced_cleanup\": %s,\n"
 "  \"debugger_only_kill_on_close_job\": %s,\n  \"target_termination_requested\": false,\n"
 "  \"debugger_output_truncated\": %s,\n  \"output_hints\": {\"access_denied\": %s, \"already_debugged\": %s},\n"
 "  \"raw_debugger_output_exported\": false,\n  \"hardware_or_network_payload_captured\": false,\n"
 "  \"limitations\": [\"An alive process is not proof of normal gameplay\",\"No hardware-to-message-to-socket trace captured\",\"Does not establish hardware transmission on TCP 3724\"]\n}\n",
 t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,r->passed?"game_attach_detach_passed":r->debugger_launched?"game_attach_detach_not_passed":"not_attempted",r->stage,
 (unsigned long)r->error,b(r->consent),(unsigned long)r->target_pid,b(r->target_query_ok),b(r->hash_computed),r->target_sha,b(r->identity_verified),b(r->debugger_found),
 (unsigned long)r->ver[0],(unsigned long)r->ver[1],(unsigned long)r->ver[2],(unsigned long)r->ver[3],b(r->debugger_launched),b(r->debugger_launched),b(r->marker_seen),
 b(r->debugger_exited),(unsigned long)r->debugger_exit,b(r->target_liveness_checked),b(r->target_alive_after_detach),b(r->forced_cleanup),b(r->job_assigned),b(r->output_truncated),b(r->access_denied_hint),b(r->already_debugged_hint));
 return n>0 && n<(int)sizeof(buf) && write_bytes(L"result.json",buf,(DWORD)n);
}
static int file_sha256(HANDLE f,char *hex){
 BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE h=NULL;unsigned char *obj=NULL,*chunk=NULL,digest[32];DWORD n=0,size=0;int ok=0;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto done;
 if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&size,sizeof(size),&n,0)<0||!size||size>1024*1024)goto done;
 obj=malloc(size);chunk=malloc(65536);if(!obj||!chunk)goto done;
 if(BCryptCreateHash(alg,&h,obj,size,NULL,0,0)<0)goto done;
 ULONGLONG deadline=GetTickCount64()+15000;
 for(;;){
  if(!ReadFile(f,chunk,65536,&n,NULL))goto done;
  if(!n)break;
  if(BCryptHashData(h,chunk,n,0)<0)goto done;
  if(GetTickCount64()>=deadline){SetLastError(ERROR_TIMEOUT);goto done;}
 }
 if(BCryptFinishHash(h,digest,sizeof(digest),0)<0)goto done;
 for(int i=0;i<32;i++)sprintf(hex+i*2,"%02x",digest[i]);ok=1;
done:
 if(h)BCryptDestroyHash(h);if(alg)BCryptCloseAlgorithmProvider(alg,0);
 if(obj)free(obj);if(chunk){SecureZeroMemory(chunk,65536);free(chunk);}return ok;
}
static void scan_targets(void){
 candidate_count=0;SendMessageW(targetsctl,CB_RESETCONTENT,0,0);
 HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
 if(snap==INVALID_HANDLE_VALUE){SetWindowTextW(statusctl,L"خواندن فهرست فرایندها ناموفق بود.");return;}
 PROCESSENTRY32W e={0};e.dwSize=sizeof(e);
 if(Process32FirstW(snap,&e))do{
  if(_wcsicmp(e.szExeFile,L"Wow.exe")!=0)continue;
  if(candidate_count>=32)break;
  HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,e.th32ProcessID);
  if(!h)continue;
  FILETIME ct,et,kt,ut;
  if(GetProcessTimes(h,&ct,&et,&kt,&ut)&&WaitForSingleObject(h,0)==WAIT_TIMEOUT){
   WCHAR line[128];_snwprintf(line,128,L"Wow.exe  —  PID %lu",e.th32ProcessID);
   LRESULT index=SendMessageW(targetsctl,CB_ADDSTRING,0,(LPARAM)line);
   if(index!=CB_ERR&&index!=CB_ERRSPACE){
    candidates[candidate_count].pid=e.th32ProcessID;candidates[candidate_count].creation=ct;
    SendMessageW(targetsctl,CB_SETITEMDATA,index,candidate_count);candidate_count++;
   }
  }CloseHandle(h);
 }while(Process32NextW(snap,&e));
 CloseHandle(snap);
 if(candidate_count){SendMessageW(targetsctl,CB_SETCURSEL,0,0);SetWindowTextW(statusctl,states[0]);}
 else SetWindowTextW(statusctl,L"بازی پیدا نشد یا دسترسی خواندن هویت آن ممکن نبود.\r\nبازی را عادی اجرا کنید، سپس «تازه‌سازی» را بزنید.");
 EnableWindow(startbtn,candidate_count>0);
}
static DWORD WINAPI run(LPVOID unused){
 (void)unused;
 Result r={0};r.stage="initializing";r.debugger_exit=STILL_ACTIVE;r.consent=1;r.target_pid=selected.pid;
 WCHAR cdb[1024],image[32768],nonceW[33],cmd[4096];char nonce[33],marker[80];
 HANDLE target=NULL,file=INVALID_HANDLE_VALUE,job=NULL,readpipe=NULL,writepipe=NULL,nullin=INVALID_HANDLE_VALUE;
 PROCESS_INFORMATION dp={0};STARTUPINFOW si={0};char *log=NULL;size_t used=0;
 stage(1);
 if(!create_output()){r.stage="output_directory_failed";r.error=GetLastError();goto cleanup;}
 if(!find_cdb(cdb)){r.stage="debugger_not_found";r.error=ERROR_FILE_NOT_FOUND;goto cleanup;}
 r.debugger_found=1;get_version(cdb,&r);stage(2);
 target=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,selected.pid);
 if(!target){r.stage="target_query_denied";r.error=GetLastError();goto cleanup;}
 FILETIME ct,et,kt,ut;DWORD size=32768;
 if(!GetProcessTimes(target,&ct,&et,&kt,&ut)||!QueryFullProcessImageNameW(target,0,image,&size)){
  r.stage="target_identity_query_failed";r.error=GetLastError();goto cleanup;}
 r.target_query_ok=1;
 if(CompareFileTime(&ct,&selected.creation)!=0){r.stage="target_replaced";goto cleanup;}
 const WCHAR *base=wcsrchr(image,'\\');base=base?base+1:image;
 if(_wcsicmp(base,L"Wow.exe")!=0){r.stage="target_name_mismatch";goto cleanup;}
 /* Hold a non-writable/non-deletable file handle until the attach test ends. */
 file=CreateFileW(image,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){r.stage="target_file_read_failed";r.error=GetLastError();goto cleanup;}
 if(!file_sha256(file,r.target_sha)){r.stage="target_hash_failed";r.error=GetLastError();goto cleanup;}
 r.hash_computed=1;
 if(!approved_hash(r.target_sha)){r.stage="unapproved_build_hash";goto cleanup;}
 r.identity_verified=1;
 if(WaitForSingleObject(target,0)!=WAIT_TIMEOUT){r.stage="target_exited_before_attach";goto cleanup;}
 if(!make_nonce(nonceW,nonce)){r.stage="random_generator_failed";goto cleanup;}
 log=malloc(CAP+1);if(!log){r.stage="allocation_failed";goto cleanup;}
 job=CreateJobObjectW(NULL,NULL);JOBOBJECT_EXTENDED_LIMIT_INFORMATION ji={0};ji.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
 if(!job||!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&ji,sizeof(ji))){r.stage="debugger_job_failed";r.error=GetLastError();goto cleanup;}
 SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
 if(!CreatePipe(&readpipe,&writepipe,&sa,0)||!SetHandleInformation(readpipe,HANDLE_FLAG_INHERIT,0)){
  r.stage="debugger_pipe_failed";r.error=GetLastError();goto cleanup;}
 nullin=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(nullin==INVALID_HANDLE_VALUE){r.stage="debugger_input_failed";r.error=GetLastError();goto cleanup;}
 snprintf(marker,sizeof(marker),"WLAB_DETACH_%s",nonce);
 /* -pd is mandatory: debugger termination must not request target termination. */
 _snwprintf(cmd,4096,L"\"%ls\" -pd -ee masm -p %lu -c \".if (@$tpid == 0n%lu) { .echo WLAB_DETACH_%ls }; qd\"",cdb,selected.pid,selected.pid,nonceW);
 si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdOutput=writepipe;si.hStdError=writepipe;si.hStdInput=nullin;
 if(!CreateProcessW(cdb,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED,NULL,NULL,&si,&dp)){
  r.stage="debugger_launch_failed";r.error=GetLastError();goto cleanup;}
 /* The game is NEVER assigned to this job. Only our new CDB child is. */
 if(!AssignProcessToJobObject(job,dp.hProcess)){r.stage="debugger_job_assignment_failed";r.error=GetLastError();goto cleanup;}
 r.job_assigned=1;CloseHandle(writepipe);writepipe=NULL;CloseHandle(nullin);nullin=INVALID_HANDLE_VALUE;
 if(WaitForSingleObject(target,0)!=WAIT_TIMEOUT){r.stage="target_exited_before_attach";goto cleanup;}
 stage(3);
 if(ResumeThread(dp.hThread)==(DWORD)-1){r.stage="debugger_resume_failed";r.error=GetLastError();goto cleanup;}
 r.debugger_launched=1;
 ULONGLONG deadline=GetTickCount64()+25000;
 for(;;){
  drain(readpipe,log,&used,&r);DWORD wr=WaitForSingleObject(dp.hProcess,25);
  if(wr==WAIT_OBJECT_0){r.debugger_exited=1;GetExitCodeProcess(dp.hProcess,&r.debugger_exit);drain(readpipe,log,&used,&r);break;}
  if(wr==WAIT_FAILED){r.stage="debugger_wait_failed";r.error=GetLastError();goto cleanup;}
  if(GetTickCount64()>=deadline){r.stage="debugger_timeout";r.error=ERROR_TIMEOUT;goto cleanup;}
 }
 r.marker_seen=marker_line(log,used,marker);
 if(!r.marker_seen)r.stage="marker_missing";
 else if(r.debugger_exit!=0)r.stage="debugger_nonzero_exit";
 else r.stage="post_detach_check";
cleanup:
 stage(4);
 if(dp.hProcess && WaitForSingleObject(dp.hProcess,0)==WAIT_TIMEOUT){
  r.forced_cleanup=1;TerminateProcess(dp.hProcess,20);WaitForSingleObject(dp.hProcess,3000);
 }
 if(job)CloseHandle(job);
 if(target && r.debugger_launched){r.target_liveness_checked=1;r.target_alive_after_detach=WaitForSingleObject(target,1500)==WAIT_TIMEOUT;}
 if(log){
  if(readpipe)drain(readpipe,log,&used,&r);log[used]=0;
  r.access_denied_hint=strstr(log,"Access is denied")!=NULL || strstr(log,"Access denied")!=NULL;
  r.already_debugged_hint=strstr(log,"already being debugged")!=NULL;
  SecureZeroMemory(log,used);free(log);
 }
 if(r.marker_seen && r.debugger_exit==0 && !r.target_alive_after_detach)r.stage="target_not_alive_after_detach";
 if(dp.hThread)CloseHandle(dp.hThread);if(dp.hProcess)CloseHandle(dp.hProcess);
 if(target)CloseHandle(target);if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
 if(readpipe)CloseHandle(readpipe);if(writepipe)CloseHandle(writepipe);if(nullin!=INVALID_HANDLE_VALUE)CloseHandle(nullin);
 r.passed=attach_passed(r.consent,r.identity_verified,r.debugger_launched,r.debugger_exited,r.debugger_exit==0,r.marker_seen,r.target_alive_after_detach,r.forced_cleanup);
 if(r.passed)r.stage="game_attach_detach_completed";
 if(outdir[0])r.saved=save_result(&r);
 PostMessageW(win,MSG_DONE,!r.saved?3:r.passed?1:!r.debugger_found?4:2,0);return 0;
}
static HWND control(const WCHAR *cls,const WCHAR *txt,DWORD style,int x,int y,int w,int h,int id){
 HWND c=CreateWindowExW(WS_EX_RTLREADING,cls,txt,WS_CHILD|WS_VISIBLE|style,px(x),px(y),px(w),px(h),win,(HMENU)(INT_PTR)id,GetModuleHandleW(NULL),NULL);
 SendMessageW(c,WM_SETFONT,(WPARAM)bodyfont,TRUE);return c;
}
static LRESULT CALLBACK proc(HWND h,UINT m,WPARAM w,LPARAM l){
 switch(m){
 case WM_CREATE:{
  win=h;HDC dc=GetDC(h);scale=MulDiv(GetDeviceCaps(dc,LOGPIXELSX),100,96);ReleaseDC(h,dc);
  bodyfont=CreateFontW(-px(17),0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
  titlefont=CreateFontW(-px(25),0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
  HWND title=control(L"STATIC",L"بررسی اتصال به بازی",SS_RIGHT,28,24,584,44,0);SendMessageW(title,WM_SETFONT,(WPARAM)titlefont,TRUE);
  control(L"STATIC",L"فقط بیلد شناخته‌شدهٔ 12.1.5.70448 — با تأیید شما",SS_RIGHT,28,76,584,32,0);
  control(L"STATIC",L"ممکن است بازی لحظه‌ای متوقف شود یا اتصالش قطع شود.\r\nدر محیط آزمایشی و خارج از فعالیت مهم بازی اجرا کنید.\r\nاین نسخه هنوز اطلاعات سخت‌افزاری یا محتوای شبکه را ضبط نمی‌کند.",SS_RIGHT,28,120,584,92,0);
  refreshbtn=control(L"BUTTON",L"تازه‌سازی",WS_TABSTOP|BS_PUSHBUTTON,28,232,128,44,103);
  targetsctl=control(L"COMBOBOX",L"",WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,172,232,440,220,104);
  statusctl=control(L"STATIC",states[0],SS_RIGHT,28,304,584,84,0);
  startbtn=control(L"BUTTON",L"بررسی اتصال به بازی",WS_TABSTOP|BS_DEFPUSHBUTTON,340,408,272,48,101);EnableWindow(startbtn,FALSE);
  openbtn=control(L"BUTTON",L"باز کردن خروجی",WS_TABSTOP|BS_PUSHBUTTON,28,408,272,48,102);EnableWindow(openbtn,FALSE);
  control(L"STATIC",L"بدون تغییر hosts، فایروال یا تنظیمات امنیتی  •  خروجی: result.json",SS_RIGHT,28,480,584,40,0);
  PostMessageW(h,MSG_SCAN,0,0);return 0;}
 case MSG_SCAN:if(!busy)scan_targets();return 0;
 case WM_COMMAND:
  if(LOWORD(w)==103 && !busy){scan_targets();return 0;}
  if(LOWORD(w)==101 && !busy){
   LRESULT index=SendMessageW(targetsctl,CB_GETCURSEL,0,0);
   if(index==CB_ERR)return 0;
   LRESULT id=SendMessageW(targetsctl,CB_GETITEMDATA,index,0);
   if(id<0 || (size_t)id>=candidate_count)return 0;
   selected=candidates[id];WCHAR text[1024];
   _snwprintf(text,1024,L"به Wow.exe با PID %lu متصل شویم؟\r\n\r\nاتصال دیباگر ممکن است بازی را لحظه‌ای متوقف کند، باعث قطع اتصال شود یا برنامه واکنش نشان دهد.\r\n\r\nفقط دستور نشانگر و جداشدن اجرا می‌شود. هیچ حافظه، CPU/BIOS یا محتوای شبکه‌ای ضبط نمی‌شود.\r\n\r\nبازی در محیط آزمایشی و خارج از فعالیت مهم است؟",selected.pid);
   if(MessageBoxW(h,text,L"تأیید اتصال به بازی",MB_YESNO|MB_DEFBUTTON2|MB_ICONWARNING|MB_RTLREADING)!=IDYES)return 0;
   if(InterlockedCompareExchange(&busy,1,0)!=0)return 0;
   outdir[0]=0;EnableWindow(startbtn,FALSE);EnableWindow(openbtn,FALSE);EnableWindow(refreshbtn,FALSE);EnableWindow(targetsctl,FALSE);
   workerhandle=CreateThread(NULL,0,run,NULL,0,NULL);
   if(!workerhandle){InterlockedExchange(&busy,0);EnableWindow(startbtn,TRUE);EnableWindow(refreshbtn,TRUE);EnableWindow(targetsctl,TRUE);SetWindowTextW(statusctl,L"راه‌اندازی بررسی ناموفق بود.");}
  }else if(LOWORD(w)==102 && outdir[0])ShellExecuteW(h,L"open",outdir,NULL,NULL,SW_SHOWNORMAL);
  return 0;
 case MSG_STAGE:if(w<sizeof(states)/sizeof(states[0]))SetWindowTextW(statusctl,states[w]);return 0;
 case MSG_DONE:
  InterlockedExchange(&busy,0);if(workerhandle){CloseHandle(workerhandle);workerhandle=NULL;}
  EnableWindow(startbtn,TRUE);EnableWindow(openbtn,outdir[0]!=0);EnableWindow(refreshbtn,TRUE);EnableWindow(targetsctl,TRUE);
  SetWindowTextW(statusctl,w==1?L"اتصال و جداشدن تأیید شد؛ فرایند بازی هنوز زنده بود.\r\nاگر بازی هنگ یا قطع شد، همراه فایل نتیجه اطلاع دهید.":
   w==4?L"دیباگر CDB پیدا نشد. نتیجه ذخیره شد.":
   w==3?L"ذخیرهٔ نتیجه ناموفق بود؛ این اجرا قابل تأیید نیست.":
   L"بررسی کامل تأیید نشد؛ تکرار خودکار انجام نمی‌شود.\r\nفایل result.json و وضعیت ظاهری بازی را ارسال کنید.");
  if(w!=3)ShellExecuteW(h,L"open",outdir,NULL,NULL,SW_SHOWNORMAL);return 0;
 case WM_CTLCOLORSTATIC:SetBkColor((HDC)w,RGB(255,255,255));SetTextColor((HDC)w,RGB(44,44,43));return (LRESULT)white;
 case WM_CLOSE:if(busy){MessageBoxW(h,L"بررسی خودکار تمام می‌شود؛ لطفاً چند ثانیه صبر کنید.",L"در حال بررسی",MB_OK|MB_RTLREADING);return 0;}DestroyWindow(h);return 0;
 case WM_DESTROY:DeleteObject(bodyfont);DeleteObject(titlefont);PostQuitMessage(0);return 0;
 }return DefWindowProcW(h,m,w,l);
}
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE prev,PWSTR cmd,int show){
 (void)prev;(void)cmd;
 SetProcessDPIAware();HDC dc=GetDC(NULL);scale=MulDiv(GetDeviceCaps(dc,LOGPIXELSX),100,96);ReleaseDC(NULL,dc);
 white=CreateSolidBrush(RGB(255,255,255));WNDCLASSW wc={0};wc.lpfnWndProc=proc;wc.hInstance=inst;wc.lpszClassName=L"WLabGameAttachWindow";
 wc.hCursor=LoadCursorW(NULL,IDC_ARROW);wc.hbrBackground=white;wc.hIcon=LoadIconW(NULL,IDI_APPLICATION);
 if(!RegisterClassW(&wc))return 1;
 RECT rect={0,0,px(640),px(540)};DWORD style=WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX;AdjustWindowRect(&rect,style,FALSE);
 HWND h=CreateWindowExW(0,wc.lpszClassName,L"WLab OneClick 0.2.0",style,CW_USEDEFAULT,CW_USEDEFAULT,rect.right-rect.left,rect.bottom-rect.top,NULL,NULL,inst,NULL);
 if(!h)return 2;ShowWindow(h,show);UpdateWindow(h);MSG msg;
 while(GetMessageW(&msg,NULL,0,0)>0){if(!IsDialogMessageW(h,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}}
 DeleteObject(white);return 0;
}
