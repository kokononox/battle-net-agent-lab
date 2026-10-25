"""Explicit Windows-only global isolation. Mutations have no subprocess timeout/kill."""
import json,os,subprocess
from pathlib import Path
from policy import PolicyError,digest
from state import atomic_json,locked
from isolation_policy import make_policy
BASE=Path(__file__).resolve().parents[1]

def native(mode,payload,job):
 if os.name!='nt':raise PolicyError('isolation_requires_Windows_explicit_Run_as_administrator')
 import ctypes
 if not ctypes.windll.shell32.IsUserAnAdmin():raise PolicyError('isolation_requires_Windows_explicit_Run_as_administrator')
 # The release manifest is checked before any administrator controller is invoked.
 import sys
 sys.path.insert(0,str(BASE/'lab'))
 from console import verify_package
 verify_package()
 request=job/'isolation-request.json';output=job/'isolation-output.json';atomic_json(request,payload)
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 proc=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/isolation-worker.ps1'),'-Mode',mode,'-Request',str(request),'-Output',str(output)],capture_output=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
 (job/'isolation-stderr.txt').write_bytes(proc.stderr[:32768])
 if not output.is_file():raise PolicyError('isolation_response_missing_changes_unknown_use_recovery_no_retry')
 if output.stat().st_size>33554432:raise PolicyError('isolation_response_size_changes_unknown')
 result=json.loads(output.read_text('utf-8-sig'))
 if proc.returncode or result.get('ok') is not True:raise PolicyError(str(result.get('error','isolation_failed'))+'; '+str(result.get('firewall_change_status','unknown_inspect_recovery')))
 return {k:v for k,v in result.items() if k!='ok'}

def handle(store,action,payload,job):
 if action=='isolation_status':
  result=native('Status',{},job);status=result['isolation_status'];current=store.read();status['saved_generation']=current['config']['generation'];status['settings_match_active']=(status.get('owner')==current['owner'] and status.get('configured_config_digest')==digest(current['config']));return result
 if action=='isolation_restore':
  if payload.get('confirmation')!='RESTORE ISOLATION':raise PolicyError('isolation_restore_consent_required')
  return native('Restore',{'confirmation':'RESTORE ISOLATION'},job)
 if action not in ('isolation_prepare','isolation_apply'):raise PolicyError('unknown_isolation_action')
 with locked(store.lock):
  state=store._read()
  if type(payload.get('generation')) is not int or payload['generation']!=state['config']['generation']:raise PolicyError('config_changed_reload_required')
  policy=make_policy(state)
  q=dict(policy=policy)
  if action=='isolation_apply':
   if payload.get('confirmation')!='APPLY ISOLATION' or not isinstance(payload.get('review_digest'),str) or len(payload['review_digest'])!=64:raise PolicyError('isolation_review_and_consent_required')
   q.update(confirmation=payload['confirmation'],review_digest=payload['review_digest'])
   from policy_backups import create_backup
   backup=create_backup(store,state,reason='before_native_isolation_apply')
  result=native('Prepare' if action=='isolation_prepare' else 'Apply',q,job)
  if action=='isolation_apply':result['prechange_config_backup_id']=backup
  return result
