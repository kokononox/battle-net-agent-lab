"""Verified, owner-scoped local config snapshots. Never resets Windows firewall or hosts."""
import copy,datetime,hashlib,json,re,uuid
from policy import PolicyError,validate,port_span
from state import assert_local_tree,atomic_json
SCHEMA='unified-policy-backup-1'
def directory(store):return assert_local_tree(store.root/'policy-backups')
def fingerprint(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def clean_ui(v):
 if v is None:return None
 if not isinstance(v,dict) or set(v)!={'ip_rows','whitelist_text','mode'}:raise PolicyError('policy_backup_UI_schema')
 if not isinstance(v['ip_rows'],list) or len(v['ip_rows'])>256 or not isinstance(v['whitelist_text'],str) or len(v['whitelist_text'])>262144 or v['mode'] not in ('blacklist_only','vpn_allowlist','full_isolation','direct_isolation'):raise PolicyError('policy_backup_UI_limit')
 for r in v['ip_rows']:
  if not isinstance(r,dict) or set(r)!={'program_ids','target','protocol','port','source_path'}:raise PolicyError('policy_backup_draft_schema')
  if not isinstance(r['program_ids'],list) or len(r['program_ids'])>32 or any(not isinstance(x,str) or len(x)>64 for x in r['program_ids']):raise PolicyError('policy_backup_draft_EXEs')
  if any(not isinstance(r[k],str) or len(r[k])>32767 for k in ('target','protocol','source_path')) :raise PolicyError('policy_backup_draft_values')
  if r['port']!=0 or type(r['port']) is not int:port_span(r['port'])
 if len(json.dumps(v,ensure_ascii=False).encode())>1048576:raise PolicyError('policy_backup_UI_size')
 return copy.deepcopy(v)
def read_backup(store,ident,owner):
 if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident):raise PolicyError('policy_backup_id')
 p=assert_local_tree(directory(store)/(ident+'.json'))
 if not p.is_file() or p.stat().st_size>4194304 or p.stat().st_nlink!=1:raise PolicyError('policy_backup_missing_size_or_link')
 try:v=json.loads(p.read_text('utf-8-sig'))
 except (OSError,ValueError) as e:raise PolicyError('policy_backup_invalid_keep_file') from e
 if not isinstance(v,dict) or set(v)!={'schema','id','created_utc','reason','state','ui_snapshot','sha256'} or v['schema']!=SCHEMA or v['id']!=ident:raise PolicyError('policy_backup_schema')
 if fingerprint({k:x for k,x in v.items() if k!='sha256'})!=v['sha256']:raise PolicyError('policy_backup_hash_mismatch')
 s=v['state']
 if not isinstance(s,dict) or set(s)!={'schema','owner','config'} or s['schema']!='unified-firewall-state-1' or s['owner']!=owner:raise PolicyError('policy_backup_other_owner_not_imported')
 validate(s['config']);clean_ui(v['ui_snapshot'])
 if not isinstance(v['reason'],str) or len(v['reason'])>120:raise PolicyError('policy_backup_reason')
 try:datetime.datetime.fromisoformat(v['created_utc'])
 except (ValueError,TypeError):raise PolicyError('policy_backup_timestamp')
 return v
def create_backup(store,state,reason='before_config_update',ui_snapshot=None):
 validate(state['config']);ui_snapshot=clean_ui(ui_snapshot);root=directory(store);root.mkdir(exist_ok=True)
 if len(list(root.glob('*.json')))>=2000:raise PolicyError('policy_backup_limit_archive_old_backups_before_change')
 ident=uuid.uuid4().hex
 body=dict(schema=SCHEMA,id=ident,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),reason=reason,state=copy.deepcopy(state),ui_snapshot=ui_snapshot)
 value={**body,'sha256':fingerprint(body)};atomic_json(root/(ident+'.json'),value)
 if read_backup(store,ident,state['owner'])!=value:raise PolicyError('policy_backup_readback_failed_no_config_write')
 return ident
def list_backups(store):
 owner=store.read()['owner'];root=directory(store);items=[];invalid=0
 if root.exists():
  for p in list(root.glob('*.json'))[:2000]:
   try:
    v=read_backup(store,p.stem,owner);c=v['state']['config'];items.append(dict(id=v['id'],created_utc=v['created_utc'],reason=v['reason'],generation=c['generation'],blacklist_count=len(c['blacklist']),whitelist_count=len(c['whitelist']),has_unsaved_UI=v['ui_snapshot'] is not None))
   except (PolicyError,OSError,ValueError,TypeError,KeyError):invalid+=1
 return dict(items=sorted(items,key=lambda x:x['created_utc'],reverse=True),invalid_or_other_owner=invalid)
def handle(store,action,payload,job):
 if action=='workspace_policy_backup_list':return dict(policy_backups=list_backups(store),firewall_changed=False)
 scope=payload.get('scope')
 if scope not in ('blacklist','whitelist'):raise PolicyError('policy_reset_scope_required')
 ui=clean_ui(payload.get('ui_snapshot'));restore=action=='workspace_policy_backup_restore'
 if action not in ('workspace_policy_defaults','workspace_policy_backup_restore'):raise PolicyError('unknown_policy_backup_action')
 if payload.get('confirmation')!=('RESTORE POLICY SETTINGS' if restore else 'RESET POLICY SETTINGS'):raise PolicyError('policy_settings_click_confirmation_required')
 previous=read_backup(store,payload.get('backup_id'),store.read()['owner']) if restore else None
 def change(c):
  if scope=='blacklist':c['blacklist']=copy.deepcopy(previous['state']['config']['blacklist']) if restore else []
  else:
   c['whitelist']=copy.deepcopy(previous['state']['config']['whitelist']) if restore else []
   c['mode']=previous['state']['config']['mode'] if restore else 'blacklist_only'
 result=store.update(payload.get('generation'),change,backup_reason=('before_policy_backup_restore_' if restore else 'before_defaults_')+scope,backup_extra=ui)
 return dict(state=result,policy_settings_result=dict(scope=scope,operation='restore_backup' if restore else 'defaults',prechange_backup_id=store.last_backup_id,restored_UI=previous['ui_snapshot'] if restore else None),firewall_changed=False,hosts_changed=False,saved_settings_only=True,active_rules_restored=False)
