"""Explicit drafts and adapters. No native firewall calls; hosts writes keep existing fixed-path gates."""
import hashlib,json,os,re
from state import assert_local_tree,atomic_json,locked
from policy import PolicyError,blacklist_entry,interval,validate,path_key
import hosts_ops as ho,hosts_edit as he,hosts_view as hv
from range_builder import build_range
from policy import whitelist_spec,whitelist_text

def clean_hosts(rows):
 if not isinstance(rows,list) or len(rows)>500:raise PolicyError('hosts_draft_limit_500')
 cleaned=[];seen=set();ids=set();groups={'sink':[],'remove':[]}
 for row in rows:
  if not isinstance(row,dict) or set(row)!={'id','domain','operation'} or not isinstance(row['id'],str) or not re.fullmatch('[a-f0-9]{32}',row['id']) or row['id'] in ids:raise PolicyError('hosts_draft_row_schema')
  if row['operation'] not in groups or not isinstance(row['domain'],str) or any(c.isspace() for c in row['domain']):raise PolicyError('hosts_one_domain_per_row')
  name=hv.domain_name(row['domain'])
  if not name:raise PolicyError('hosts_domain_invalid')
  if name in seen:raise PolicyError('hosts_duplicate_domain_resolve_draft')
  seen.add(name);ids.add(row['id']);groups[row['operation']].append(name);cleaned.append(dict(id=row['id'],domain=name,operation=row['operation']))
 # Protect system/host names using the existing adapter, at most twice per batch.
 for operation,names in groups.items():
  if names:ho.changes_from(dict(domains='\n'.join(names),operation=operation))
 return cleaned

def host_file(store):return assert_local_tree(store.root/'hosts-workspace.json')
def read_hosts(store):
 p=host_file(store)
 if not p.exists():return dict(schema='unified-hosts-draft-1',revision=0,rows=[])
 if p.stat().st_size>2097152:raise PolicyError('hosts_draft_file_limit')
 value=json.loads(p.read_text('utf-8-sig'))
 if not isinstance(value,dict) or set(value)!={'schema','revision','rows'} or value['schema']!='unified-hosts-draft-1' or type(value['revision']) is not int or value['revision']<0:raise PolicyError('hosts_draft_schema')
 value['rows']=clean_hosts(value['rows']);return value

def hosts_batch_plan(data,rows):
 rows=clean_hosts(rows)
 if not rows:raise PolicyError('hosts_empty_draft_nothing_to_apply')
 parsed=hv.parse_hosts(data)
 if parsed['truncated']:raise PolicyError('hosts_truncated_view_edit_refused')
 changes=[dict(domain=r['domain'],action='upsert',addresses=['0.0.0.0','::']) if r['operation']=='sink' else dict(domain=r['domain'],action='remove') for r in rows]
 after,_=he.prepare(data,changes);wanted={r['domain'] for r in rows}
 body=dict(schema='unified-hosts-plan-1',expected_sha256=ho.sha(data),after_sha256=ho.sha(after),operation='draft_batch',changes=changes,before=[r for r in parsed['entries'] if r['domain'] in wanted],after=[r for r in hv.parse_hosts(after)['entries'] if r['domain'] in wanted],system_wide=True,per_EXE=False,whitelist_cannot_override_hosts=True,wildcard_subdomains=False,changes_required=after!=data,blocking_verified=False)
 body['plan_digest']=ho.sha(json.dumps(body,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode());return body

def handle(store,action,payload,job):
 if action in ('workspace_policy_defaults','workspace_policy_backup_list','workspace_policy_backup_restore'):
  from policy_backups import handle as policy_backup_handle
  return policy_backup_handle(store,action,payload,job)
 if action=='workspace_blacklist_inventory':
  from blacklist_inventory import read
  return read(store,job)
 if action=='workspace_hosts_load':
  with locked(store.root/'hosts-workspace.lock'):value=read_hosts(store)
  return dict(workspace_hosts=value,firewall_changed=False,hosts_changed=False)
 if action=='workspace_hosts_save':
  rows=clean_hosts(payload.get('rows'))
  with locked(store.root/'hosts-workspace.lock'):
   value=read_hosts(store)
   if type(payload.get('revision')) is not int or payload['revision']!=value['revision']:raise PolicyError('hosts_draft_changed_reload_required')
   value=dict(schema='unified-hosts-draft-1',revision=value['revision']+1,rows=rows);atomic_json(host_file(store),value)
  return dict(workspace_hosts=value,saved_locally_only=True,firewall_changed=False,hosts_changed=False)
 if action=='workspace_blacklist_save':
  rows=payload.get('rows')
  if not isinstance(rows,list) or len(rows)>256:raise PolicyError('blacklist_limit_256')
  def change(config):
   entries=[];seen=set();programs={p['id']:p for p in config['programs']}
   for row in rows:
    if not isinstance(row,dict) or set(row)!={'program_ids','target','protocol','port','source_path'}:raise PolicyError('blacklist_draft_row_schema')
    e=blacklist_entry(row['program_ids'],row['target'],row['protocol'],row['port'])
    if row['source_path']:
     # A transferred observation must still bind to that exact registered EXE path.
     if len(e['program_ids'])!=1 or e['program_ids'][0] not in programs or path_key(programs[e['program_ids'][0]]['path'])!=path_key(row['source_path']):raise PolicyError('observed_EXE_not_registered_or_bound_use_programs_first')
    if e['id'] not in seen:entries.append(e);seen.add(e['id'])
   config['blacklist']=entries
  return dict(state=store.update(payload.get('generation'),change),saved_only=True,firewall_changed=False,hosts_changed=False)
 if action=='workspace_whitelist_range_preview':
  raw=dict(payload);proto=raw.get('protocol');first=raw.get('port');last=raw.get('port_end')
  if proto=='Any':
   if type(first) is not int or type(last) is not int or first!=0 or last!=0:raise PolicyError('all_ports_requires_explicit_zero_Any')
  elif proto not in ('TCP','UDP') or type(first) is not int or type(last) is not int or not 1<=first<=last<=65535:raise PolicyError('whitelist_port_range')
  raw.update(protocol='TCP',port=1,port_end=1,row_budget=256,program_count=1)
  preview=build_range(raw,lambda x:(interval(x) and x),lambda es:'')
  rules=[whitelist_text(dict(target=e['ip'],protocol=proto,port=first,port_end=last)) for e in preview['entries']]
  return dict(whitelist_range_preview=dict(rules=rules,first_ip=preview['first_ip'],last_ip=preview['last_ip'],address_count=preview['address_count'],protocol=proto,port=first,port_end=last,global_inside_VPN=True,saved=False,applied=False),firewall_changed=False,hosts_changed=False)
 if action=='workspace_range_preview':
  preview=build_range(payload,lambda x: (interval(x) and x),lambda es:'\n'.join(f"{e['ip']}:{e['port']} {e['protocol']}" for e in es))
  preview['scope']='explicit_registered_EXEs_port_protocol_only';return dict(range_preview=preview,firewall_changed=False,hosts_changed=False)
 if action=='workspace_hosts_prepare':
  data,_=ho.read_data();return dict(hosts_plan=hosts_batch_plan(data,payload.get('rows')),firewall_changed=False)
 if action=='workspace_hosts_apply':
  if payload.get('confirmation')!=ho.CONFIRM:raise PolicyError('explicit_system_wide_hosts_confirmation_required')
  root=assert_local_tree(store.root);backups=assert_local_tree(root/'hosts-backups');backups.mkdir(exist_ok=True)
  with locked(root/'hosts-operation.lock'):
   data,_=ho.read_data();prepared=hosts_batch_plan(data,payload.get('rows'))
   if payload.get('expected_sha256')!=prepared['expected_sha256'] or payload.get('plan_digest')!=prepared['plan_digest']:raise PolicyError('hosts_preview_stale_read_and_preview_again')
   if os.name!='nt':raise PolicyError('hosts_edit_requires_Windows')
   import ctypes
   if not ctypes.windll.shell32.IsUserAnAdmin():raise PolicyError('hosts_explicit_Run_as_administrator_required')
   result=he.apply_hosts(root,dict(hosts_edit_consent=True,expected_sha256=prepared['expected_sha256'],changes=prepared['changes']))
  return dict(hosts_result=result,firewall_changed=False,blocking_verified=False,system_wide=True)
 raise PolicyError('unknown_workspace_action')
