"""Read-only owned native snapshot for the single blacklist table; never applies rules."""
import copy,datetime,json,os,subprocess
from pathlib import Path
from policy import PolicyError,compile_plan
from state import atomic_json,assert_local_tree
from monitor_evidence import inventory
BASE=Path(__file__).resolve().parents[1]
def classify(state,snapshot):
 rows=[];represented=set();config=state['config']
 for e in config['blacklist']:
  c=copy.deepcopy(config);c['mode']='blacklist_only';c['whitelist']=[];c['blacklist']=[e]
  expected=compile_plan(c,state['owner'])['rules'];represented.update(r['name'] for r in expected);actual={r['name'] for r in snapshot['rules']}
  matched=sum(r['name'] in actual for r in expected)
  status='unknown'
  if snapshot['available'] and expected:
   if matched==len(expected):status='active_verified'
   elif matched:status='partial'
   elif snapshot['complete']:status='not_matching_in_snapshot'
  elif not expected:status='no_enabled_program'
  rows.append(dict(entry_id=e['id'],status=status,expected_rules=len(expected),matched_rules=matched))
 return dict(snapshot=snapshot,entries=rows,orphan_rules=[r for r in snapshot['rules'] if r['name'] not in represented],generation=config['generation'],scope='this_owner_registered_EXEs_only; timestamped_native_readback_not_packet_delivery')
def read(store,job):
 state=store.read();programs=state['config']['programs']
 if os.name!='nt':raise PolicyError('blacklist_inventory_requires_Windows')
 if not programs:
  raw=dict(available=True,complete=True,checked_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),rules=[],reason='no_registered_programs')
 else:
  request=assert_local_tree(job/'inventory-request.json');out=assert_local_tree(job/'inventory.json')
  atomic_json(request,dict(owner=state['owner'],programs=programs))
  ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
  with (job/'inventory-stdout.txt').open('wb') as stdout,(job/'inventory-error.txt').open('wb') as stderr:
   r=subprocess.run([str(ps),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(BASE/'app/inventory-read.ps1'),'-Request',str(request),'-Output',str(out)],stdout=stdout,stderr=stderr,timeout=45,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  if r.returncode or not out.is_file() or out.stat().st_size>4194304:raise PolicyError('blacklist_inventory_unavailable_no_mutation')
  raw=json.loads(out.read_text('utf-8-sig'))
 snapshot=inventory(raw,programs)
 return dict(blacklist_inventory=classify(state,snapshot),firewall_changed=False,hosts_changed=False)
