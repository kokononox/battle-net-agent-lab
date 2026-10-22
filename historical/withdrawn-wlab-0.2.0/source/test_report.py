"""Portable report-format fixtures, NOT a Windows/CDB integration test."""
import json,re,subprocess,tempfile
from pathlib import Path
src=Path(__file__).with_name('main.c').read_text()
result=re.search(r'typedef struct \{\n const char \*stage;[\s\S]*?\} Result;',src).group()
report=src[src.index('static int save_result'):src.index('static int file_sha256')]
header='''#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "decision.h"
#define VERSION "0.2.0"
typedef uint32_t DWORD;
typedef struct {unsigned short wYear,wMonth,wDay,wHour,wMinute,wSecond;} SYSTEMTIME;
static void GetSystemTime(SYSTEMTIME *t){*t=(SYSTEMTIME){2026,1,2,3,4,5};}
static const char *b(int x){return x?"true":"false";}
static int write_bytes(const void *ignored,const char *data,DWORD n){(void)ignored;return fwrite(data,1,n,stdout)==n;}
'''
main='''int main(int argc,char **argv){(void)argc;Result r={0};int mode=atoi(argv[1]);
r.stage="fixture";r.debugger_exit=259;r.consent=1;
if(mode>0){r.debugger_launched=1;r.identity_verified=approved_hash(APPROVED_SHA);r.target_query_ok=1;r.hash_computed=1;strcpy(r.target_sha,APPROVED_SHA);}
if(mode==2 || mode==3){r.debugger_exited=1;r.debugger_exit=0;r.marker_seen=1;r.target_liveness_checked=1;r.target_alive_after_detach=1;}
if(mode==3)r.forced_cleanup=1;
r.passed=attach_passed(r.consent,r.identity_verified,r.debugger_launched,r.debugger_exited,r.debugger_exit==0,r.marker_seen,r.target_alive_after_detach,r.forced_cleanup);
return save_result(&r)?0:1;}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'report.c').write_text(header+result+'\n'+report+main)
 subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-I',str(Path(__file__).parent),str(p/'report.c'),'-o',str(p/'report')],check=True)
 for mode in range(4):
  r=json.loads(subprocess.check_output([str(p/'report'),str(mode)],text=True))
  assert r['status']==['not_attempted','game_attach_detach_not_passed','game_attach_detach_passed','game_attach_detach_not_passed'][mode]
  assert r['hardware_or_network_payload_captured'] is False
  assert r['target_termination_requested'] is False
  assert r['marker_requires_matching_debugger_target_pid'] is True
  assert r['target_liveness_checked']==(mode>=2)
  assert r['target_alive_after_detach']==(mode>=2)
  assert r['debugger_forced_cleanup']==(mode==3)
  assert r['target_sha256']==('' if mode==0 else re.search(r'#define APPROVED_SHA "(.*?)"',Path(__file__).with_name('decision.h').read_text()).group(1))
print('4 report JSON fixtures passed; report format arguments verified')
