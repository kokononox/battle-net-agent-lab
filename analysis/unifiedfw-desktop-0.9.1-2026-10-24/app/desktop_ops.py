"""Desktop adapter to unchanged LAB entry points. No new rule engine or policy scope."""
from pathlib import Path
import contextlib,io,json,os,sys
BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE/'app'),str(BASE/'lab')]
from policy import PolicyError,digest
from state import Store,locked,assert_local_tree
from risk_confirmations import risks,require
from console import request_for,native,verify_package

def snapshot(store,generation,legacy_text):
 state=store._read()
 if type(generation) is not int or state['config']['generation']!=generation:raise PolicyError('config_changed_reload_required')
 if state['config']['mode']!='blacklist_only':raise PolicyError('global_whitelist_not_qualified; preview_only; choose_blacklist_only_for_native_apply')
 class Snapshot:
  def read(self):return state
  def verified_programs(self):
   for p in state['config']['programs']:
    if p['enabled']:
     now=store.inspector(p['path'])
     if now['path'].casefold()!=p['path'].casefold() or now['sha256']!=p['sha256']:raise PolicyError('program_binary_changed_reselect_required')
   return state,[p for p in state['config']['programs'] if p['enabled']]
 q=request_for(Snapshot(),legacy_ack=legacy_text=='OLD TOOLS RESTORED')
 return state,q

def native_result(action,q=None):
 # Reuse original administrator check, manifest validation and native admission.
 verify_package();capture=io.StringIO()
 with contextlib.redirect_stdout(capture):code=native(action,q)
 lines=[line.removeprefix('Result file: ').strip() for line in capture.getvalue().splitlines() if line.startswith('Result file: ')]
 if len(lines)!=1:raise PolicyError('native_result_path_missing; changes_unknown_inspect_journal')
 path=assert_local_tree(lines[0]);base=assert_local_tree(BASE/'private-state/lab-jobs').resolve()
 if base not in path.resolve().parents or path.name!='result.json' or path.stat().st_size>33554432:raise PolicyError('native_result_scope_or_size; changes_unknown')
 raw=json.loads(path.read_text('utf-8-sig'));session=raw.get('session') or {}
 summary={k:v for k,v in raw.items() if k not in ('session','environment','active_store_enabled_rule_names')}
 summary['session_summary']={k:session.get(k) for k in ('id','owner','phase')};summary['session_summary']['entry_count']=len(session.get('entries',[]))
 if action=='status':summary['environment_summary']={k:raw.get('environment',{}).get(k) for k in ('vpn_query_errors','legacy_enabled_rule_names')}
 return dict(native_ok=code==0 and raw.get('ok') is True,native=summary,native_result_file=str(path),firewall_change_status=raw.get('firewall_change_status','see_native_result'),protection_verified=False)

def handle(store,action,payload):
 if action=='native_prepare':
  with locked(store.lock):
   state,q=snapshot(store,payload.get('generation'),payload.get('legacy_ack',''))
   return dict(preparation=dict(additional_risks=risks(state['config']),generation=state['config']['generation'],plan_digest=digest(q['plan']),programs=[dict(id=p['id'],path=p['path'],sha256=p['sha256']) for p in q['programs']],rule_count=len(q['plan']['rules']),rules=q['plan']['rules'],overlaps=q['plan']['overlaps'],mode=q['mode'],requires_exact_confirmation='I ACCEPT LAB NETWORK CHANGES',LAB_only=True))
 if action=='native_apply_blacklist':
  if payload.get('confirmation')!='I ACCEPT LAB NETWORK CHANGES':raise PolicyError('explicit_lab_confirmation_required_no_changes')
  with locked(store.lock):
   state,q=snapshot(store,payload.get('generation'),payload.get('legacy_ack',''))
   if payload.get('plan_digest')!=digest(q['plan']):raise PolicyError('plan_changed_repreview_required')
   require(state['config'],payload)
   return native_result('apply',q)
 if action=='native_restore':
  if payload.get('confirmation')!='RESTORE':raise PolicyError('explicit_restore_confirmation_required')
  return native_result('restore')
 if action=='native_status':return native_result('status')
 raise PolicyError('unknown_desktop_native_action')
