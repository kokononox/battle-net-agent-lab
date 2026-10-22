"""Static build audit. Does NOT assert Windows runtime compatibility."""
import hashlib,json,pathlib,sys
sys.path.insert(0,'/data/re-tools')
import pefile
root=pathlib.Path(__file__).resolve().parents[1]
pe=pefile.PE(str(root/'WLab-Evidence.exe'))
imports={d.dll.decode():sorted(i.name.decode() for i in d.imports if i.name) for d in pe.DIRECTORY_ENTRY_IMPORT}
flat={x for v in imports.values() for x in v}
forbidden={'DebugActiveProcess','DebugBreakProcess','ReadProcessMemory','WriteProcessMemory','VirtualAllocEx','VirtualProtectEx','CreateRemoteThread','SuspendThread','SetThreadContext','SetWindowsHookExW','CreateServiceW','StartServiceW'}
assert not flat&forbidden,flat&forbidden
assert pe.FILE_HEADER.Machine==0x8664
assert pe.OPTIONAL_HEADER.Subsystem==2
assert pe.OPTIONAL_HEADER.DllCharacteristics&0x40 # ASLR
assert pe.OPTIONAL_HEADER.DllCharacteristics&0x100 # DEP
source=(root/'source/main.c').read_text()
assert 'OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,q->pid)' in source
assert 'OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid)' in source
assert source.count('OpenProcess(')==2
assert 'NT Kernel Logger' not in source
assert 'CREATE_NO_WINDOW' in source
assert source.count('CreateProcessW(')==1
assert 'same_guid(&p.p.Wnode.Guid,guid)' in source
assert 'unknown_no_wfp_evidence' in source
assert 'header_pid_not_attribution' in source
assert 'control_payload_pid_events' in source
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
qa={'tool':'WLab Evidence','version':'0.1.0','target':'Windows x64 GUI','compiler':'Zig 0.14.1 / clang, -O2 -Wall -Wextra -Werror','build_passed':True,'exe_sha256':sha(root/'WLab-Evidence.exe'),'exe_bytes':(root/'WLab-Evidence.exe').stat().st_size,'source_sha256':{str(p.relative_to(root)):sha(p) for p in sorted((root/'source').glob('*'))},'portable_tests':'C assertions and independent Python ZIP CRC/content/JSON parsing passed','static_import_audit':'Passed; no listed debugger, game-memory, injection or service-install APIs imported; OpenProcess source rights limited to query/synchronize','aslr':True,'dep':True,'imports':imports,'limitations':{'windows_native_execution':'NOT TESTED','gui_visual_and_dpi':'NOT TESTED on Windows; no Wine present','game_compatibility':'NOT TESTED','native_etw_dns_and_watchdog':'NOT TESTED','selftest_on_user_windows':'REQUIRED before any game trial','code_signing':'UNSIGNED','sanitizers':'NOT RUN: sanitizer runtime unavailable in Linux environment; portable tests rerun without sanitizer','absence_of_hardware_transmission':'NOT PROVEN','hardware_payload_detection':'NOT IMPLEMENTED'}}
(root/'docs/QA.json').write_text(json.dumps(qa,indent=2,ensure_ascii=False)+'\n')
print(json.dumps({k:v for k,v in qa.items() if k not in ['imports','source_sha256']},ensure_ascii=False,indent=2))
