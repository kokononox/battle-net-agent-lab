#define UNICODE
#define _UNICODE
#include <windows.h>
/* No CRT dependency: the portable launcher only calls Windows system DLLs. */
static wchar_t root[32768],python[32768],script[32768],cmd[65536];
static STARTUPINFOW si;static PROCESS_INFORMATION pi;
static unsigned length(const wchar_t*s){unsigned n=0;while(s[n])n++;return n;}
static void append(wchar_t*d,const wchar_t*s){unsigned n=length(d),i=0;while(s[i]){d[n++]=s[i++];}d[n]=0;}
void WINAPI entry(void){
 DWORD n=GetModuleFileNameW(NULL,root,32768);if(!n||n>=32768)ExitProcess(1);
 unsigned i=n;while(i&&root[i]!=L'\\')i--;if(!i)ExitProcess(1);root[i]=0;
 if(length(root)>32000)ExitProcess(1);
 append(python,root);append(python,L"\\runtime\\pythonw.exe");append(script,root);append(script,L"\\app.py");
 if(GetFileAttributesW(python)==INVALID_FILE_ATTRIBUTES||GetFileAttributesW(script)==INVALID_FILE_ATTRIBUTES){MessageBoxW(NULL,L"Extract the entire ZIP to a normal folder before opening this tool.",L"WLab BIOS Path",MB_OK|MB_ICONERROR);ExitProcess(2);}
 append(cmd,L"\"");append(cmd,python);append(cmd,L"\" \"");append(cmd,script);append(cmd,L"\"");si.cb=sizeof(si);
 if(!CreateProcessW(python,cmd,NULL,NULL,FALSE,0,NULL,root,&si,&pi)){MessageBoxW(NULL,L"Could not start the bundled runtime. Extract the entire ZIP and check Windows permissions.",L"WLab BIOS Path",MB_OK|MB_ICONERROR);ExitProcess(3);}
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);ExitProcess(0);
}
