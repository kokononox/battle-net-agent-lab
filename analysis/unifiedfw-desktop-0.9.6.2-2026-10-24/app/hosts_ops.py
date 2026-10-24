"""Separate system-wide hosts consent. Never resolves names or writes firewall policy."""
import hashlib,json,os,re,socket
from pathlib import Path
from state import assert_local_tree,locked
import hosts_view as view
import hosts_edit as edit
CONFIRM='I ACCEPT SYSTEM WIDE HOSTS CHANGES'
def sha(data):return hashlib.sha256(data).hexdigest()
def changes_from(payload):
 text=payload.get('domains');action=payload.get('operation')
 if not isinstance(text,str) or len(text)>65536:raise ValueError('hosts_domains_text_required')
 if action not in ('sink','remove'):raise ValueError('hosts_operation_invalid')
 names=[];protected=view.SYSTEM_NAMES|{'wpad',socket.gethostname().lower(),socket.getfqdn().lower()}
 for raw in text.splitlines():
  raw=raw.strip()
  if not raw:continue
  name=view.domain_name(raw)
  # No URLs, wildcards, paths, whitespace lists, addresses, or single-label system names.
  if not name or '.' not in name or name in protected or any(c.isspace() for c in raw):raise ValueError('hosts_domain_only_one_per_line_no_URL_wildcard_or_system_name')
  if name not in names:names.append(name)
 if not 1<=len(names)<=500:raise ValueError('hosts_select_1_to_500_domains')
 return [dict(domain=n,action='upsert',addresses=['0.0.0.0','::']) if action=='sink' else dict(domain=n,action='remove') for n in names]
def read_data():
 path=edit.standard_path()
 with path.open('rb') as f:data=f.read(view.MAX_BYTES+1)
 parsed=view.parse_hosts(data)
 return data,parsed
def plan(data,payload):
 parsed=view.parse_hosts(data)
 if parsed['truncated']:raise ValueError('hosts_truncated_view_edit_refused')
 changes=changes_from(payload);after,_=edit.prepare(data,changes)
 wanted={x['domain'] for x in changes}
 body=dict(schema='unified-hosts-plan-1',expected_sha256=sha(data),after_sha256=sha(after),operation=payload['operation'],changes=changes,before=[x for x in parsed['entries'] if x['domain'] in wanted],after=[x for x in view.parse_hosts(after)['entries'] if x['domain'] in wanted],system_wide=True,per_EXE=False,whitelist_cannot_override_hosts=True,wildcard_subdomains=False,changes_required=after!=data,blocking_verified=False)
 body['plan_digest']=sha(json.dumps(body,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
 return body
def handle(store,action,payload,job):
 if action=='hosts_read':
  _,p=read_data();return dict(hosts=p,system_wide=True,blocking_verified=False,firewall_changed=False)
 if action=='hosts_prepare':
  data,_=read_data();return dict(hosts_plan=plan(data,payload),firewall_changed=False)
 if action!='hosts_apply':raise ValueError('unknown_hosts_action')
 if payload.get('confirmation')!=CONFIRM:raise ValueError('explicit_system_wide_hosts_confirmation_required')
 # Only this adapter can select the fixed OS path; caller cannot supply paths or mappings.
 root=assert_local_tree(store.root);backups=assert_local_tree(root/'hosts-backups');backups.mkdir(exist_ok=True)
 with locked(root/'hosts-operation.lock'):
  data,_=read_data();prepared=plan(data,payload)
  if payload.get('expected_sha256')!=prepared['expected_sha256'] or payload.get('plan_digest')!=prepared['plan_digest']:raise ValueError('hosts_preview_stale_read_and_preview_again')
  if os.name!='nt':raise ValueError('hosts_edit_requires_Windows')
  import ctypes
  if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('hosts_explicit_Run_as_administrator_required')
  result=edit.apply_hosts(root,dict(hosts_edit_consent=True,expected_sha256=prepared['expected_sha256'],changes=prepared['changes']))
 # Do not fail an already-completed edit merely because a later read is denied.
 return dict(hosts_result=result,firewall_changed=False,blocking_verified=False,system_wide=True)
