"""Bounded local desktop API. Mutations are never reported as 'no changes' on error."""
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from state import Store,assert_local_tree,atomic_json
from policy import PolicyError
BASE=Path(__file__).resolve().parents[1]
NATIVE=('native_prepare','native_apply_blacklist','native_status','native_restore')
def execute(request,response):
 jobs=assert_local_tree(BASE/'private-state/jobs');request=assert_local_tree(request);response=assert_local_tree(response)
 if jobs.resolve() not in request.resolve().parents or response.parent!=request.parent or response.name!='response.json':raise PolicyError('desktop_job_scope')
 action='unknown'
 try:
  if request.stat().st_size>1048576:raise PolicyError('request_too_large')
  q=json.loads(request.read_text('utf-8-sig'))
  if not isinstance(q,dict) or set(q)!={'action','payload'} or not isinstance(q['payload'],dict):raise PolicyError('request_schema')
  action=q['action'];store=Store(BASE/'private-state')
  if action=='policy_review':
   from policy_review import handle
   result=handle(store,q['payload'],request.parent)
  elif isinstance(action,str) and action.startswith('isolation_'):
   from isolation_ops import handle
   result=handle(store,action,q['payload'],request.parent)
  elif action in NATIVE:
   from desktop_ops import handle
   result=handle(store,action,q['payload'])
  elif isinstance(action,str) and action.startswith('audit_'):
   from audit_ops import handle
   result=handle(store,action,q['payload'],request.parent)
  elif isinstance(action,str) and action.startswith('workspace_'):
   from workspace_ops import handle
   result=handle(store,action,q['payload'],request.parent)
  elif action=='hosts_reset_dns_flush':
   from dns_cache_ops import handle
   result=handle(store,action,q['payload'],request.parent)
  elif isinstance(action,str) and action.startswith('hosts_reset_'):
   from hosts_reset import handle
   result=handle(store,action,q['payload'],request.parent)
  elif isinstance(action,str) and action.startswith('hosts_'):
   from hosts_ops import handle
   result=handle(store,action,q['payload'],request.parent)
  elif isinstance(action,str) and action.startswith('baseline_'):
   from baseline_ops import handle
   result=handle(store,action,q['payload'],request.parent)
  elif isinstance(action,str) and action.startswith('monitor_'):
   from live_ops import handle
   result=handle(store,action,q['payload'],request.parent)
  else:
   from cli import handle
   result=handle(store,action,q['payload'],request.parent)
  atomic_json(response,dict(ok=True,**result));return 0
 except Exception as e:
  mut=action in ('native_apply_blacklist','native_restore','isolation_apply','isolation_restore')
  atomic_json(response,dict(ok=False,error=str(e)[:500],firewall_change_status='unknown_if_native_started; inspect_status_and_journal; do_not_retry' if mut else 'no_rule_mutation_requested',protection_verified=False,audit_change_status='unknown_if_write_started; use audit_status; do_not_blindly_retry' if action in ('audit_enable','audit_restore') else 'no_audit_mutation_requested',hosts_change_status='unknown_if_write_started; read_hosts_and_keep_backup; do_not_blindly_retry' if action in ('hosts_apply','workspace_hosts_apply','hosts_reset_apply','hosts_reset_restore_apply') else 'no_hosts_mutation_requested'));return 1
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--response',required=True);a=p.parse_args();raise SystemExit(execute(a.request,a.response))
