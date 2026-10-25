"""Pure in-memory mutations only, optionally using actual pre-gate task definitions and measurements."""
import copy,hashlib,json,re,sys
from pathlib import Path
from unittest.mock import patch
import Classify as C
from NarrowTimeRules import PINS
from TaskXml import parse,Q
from ShadowSchedule import PATH
REAL_SHA=hashlib.sha256

def tests(before,focus,trust):
 results=[]
 def check(name,condition):results.append({'name':name,'passed':bool(condition)})
 keys={id:next(k for k in before['tasks'] if hashlib.sha256(k.encode()).hexdigest()==id) for id in PINS}
 base=copy.deepcopy(before);basefocus=copy.deepcopy(focus)
 # Align in-memory fixtures to the actual focus snapshot; never write any OS task.
 for id,key in keys.items():
  xml=basefocus['tasks'][id]['xml'];base['task_xml'][key]=xml;base['tasks'][key]=REAL_SHA(xml.encode()).hexdigest()
 ctx={'baseline':basefocus,'current':copy.deepcopy(basefocus)};after=copy.deepcopy(base)
 for id,key in keys.items():
  xml=basefocus['tasks'][id]['xml'];node=parse(xml).find(PATH)
  if node is None:raise ValueError('live_time_boundary_missing')
  old=node.text;new='2026-10-26T21:22:23Z' if old!='2026-10-26T21:22:23Z' else '2026-10-27T21:22:23Z'
  regex=r'(<(?:[A-Za-z_][\w.-]*:)?StartBoundary(?:\s[^>]*)?>)\s*'+re.escape(old)+r'\s*(</(?:[A-Za-z_][\w.-]*:)?StartBoundary>)'
  xml,n=re.subn(regex,lambda m:m.group(1)+new+m.group(2),xml,count=1)
  if n!=1:raise ValueError('live_boundary_fixture_failed')
  after['task_xml'][key]=xml;after['tasks'][key]=REAL_SHA(xml.encode()).hexdigest();ctx['current']['tasks'][id]['xml']=xml
 r=C.evaluate(base,after,trust,ctx);check('two_real_routes_exact_only',r['raw_changes']==2 and r['classified_two_time_reschedules']==2 and r['classified_reschedules']==2 and r['blocked_changes']==0)
 # Any unsupported change remains blocked even when both time rules match.
 bad=copy.deepcopy(after);bad['tasks']['\\Other\\NewTask']='changed';r=C.evaluate(base,bad,trust,ctx);check('unknown_task_still_blocked',r['classified_two_time_reschedules']==2 and r['blocked_changes']==1)
 bad=copy.deepcopy(after);bad['services']['other']='changed';r=C.evaluate(base,bad,trust,ctx);check('service_still_blocked',r['classified_two_time_reschedules']==2 and r['blocked_changes']==1)
 # A PrintJobCleanupTask change has no route into the two approved identities.
 printid='21475573fddc2e641b67691a5d4d3096ea5135278dae645a8fd4a2e0bc4c613a'
 printkeys=[k for k in base['tasks'] if hashlib.sha256(k.encode()).hexdigest()==printid]
 if printkeys:
  bad=copy.deepcopy(after);bad['tasks'][printkeys[0]]='changed_print_definition';r=C.evaluate(base,bad,trust,ctx);check('print_task_never_accepted',r['classified_two_time_reschedules']==2 and r['blocked_changes']==1 and any(d['identity_sha256']==printid and d['allowed'] is False for d in r['details']))
 id=next(iter(PINS));key=keys[id]
 for field in ['actions_sha256','principals_sha256','permissions_sha256']:
  bad=copy.deepcopy(ctx);bad['current']['tasks'][id][field]='changed';r=C.evaluate(base,after,trust,bad);check(field+'_reject',r['classified_two_time_reschedules']==1 and r['blocked_changes']>=1)
 for field in ['file_sha256','binding_hash']:
  bad=copy.deepcopy(ctx);bad['current']['tasks'][id]['binding'][field]='changed';r=C.evaluate(base,after,trust,bad);check(field+'_reject',r['classified_two_time_reschedules']==1 and r['blocked_changes']>=1)
 for flag in ['checked_before_gate','hash_stable','valid_microsoft']:
  bad=copy.deepcopy(ctx);bad['baseline']['tasks'][id]['baseline_signature'][flag]=False;r=C.evaluate(base,after,trust,bad);check(flag+'_required',r['classified_two_time_reschedules']==1 and r['blocked_changes']>=1)
 for flag in ['system_identity','captured_before_gate','captured_before_target']:
  bad=copy.deepcopy(ctx);bad['baseline'][flag]=False;r=C.evaluate(base,after,trust,bad);check(flag+'_required',r['classified_two_time_reschedules']==0 and r['blocked_changes']>=2)
 bad=copy.deepcopy(ctx);bad['current']={};r=C.evaluate(base,after,trust,bad);check('missing_current_fails_closed',r['blocked_changes']>=2)
 bad=copy.deepcopy(ctx);bad['current']['tasks'][id]['xml']=bad['baseline']['tasks'][id]['xml'];r=C.evaluate(base,after,trust,bad);check('inventory_focus_disagreement_reject',r['classified_two_time_reschedules']==1 and r['blocked_changes']>=1)
 # Binding/image drift is a blocker even with completely unchanged registration XML.
 bad={'baseline':copy.deepcopy(basefocus),'current':copy.deepcopy(basefocus)};bad['current']['tasks'][id]['binding']['file_sha256']='changed';r=C.evaluate(base,base,trust,bad);check('image_change_without_xml_blocks',r['blocked_changes']==1 and r['time_rule_guard_blockers']==1)
 r=C.evaluate(base,base,trust,{'baseline':basefocus,'current':basefocus});check('unchanged_trusted_inventory',r['raw_changes']==0 and r['blocked_changes']==0)
 r=C.evaluate(base,base,trust,{});check('missing_all_time_trust_blocks',r['classified_two_time_reschedules']==0 and r['blocked_changes']>=2)
 return results

def unit_fixture():
 before={'tasks':{},'task_xml':{},'services':{},'svc_binding':{}}
 f={'system_identity':True,'captured_before_gate':True,'captured_before_target':True,'tasks':{}};mapping={}
 for i,(id,pin) in enumerate(PINS.items()):
  key='unit_only_key_'+str(i);mapping[key]=id
  xml=f'<Task xmlns="{Q[1:-1]}"><Triggers><TimeTrigger><StartBoundary>2026-10-25T12:00:00Z</StartBoundary></TimeTrigger></Triggers><Settings><Enabled>true</Enabled></Settings></Task>'
  before['tasks'][key]='old';before['task_xml'][key]=xml
  f['tasks'][id]={'capture_complete':True,'xml':xml,'actions_sha256':pin[1],'principals_sha256':pin[2],'permissions_sha256':pin[4],'baseline_signature':dict(checked_before_gate=True,hash_stable=True,valid_microsoft=True),'binding':dict(capture_complete=True,file_sha256=pin[3],binding_hash='bound')}
 printkey='unit_only_print_key';mapping[printkey]='21475573fddc2e641b67691a5d4d3096ea5135278dae645a8fd4a2e0bc4c613a';before['tasks'][printkey]='old';before['task_xml'][printkey]=xml
 def route_sha(data=b''):
  key=data.decode() if isinstance(data,bytes) else ''
  if key not in mapping:return REAL_SHA(data)
  class RouteHash:
   def hexdigest(self):return mapping[key]
  return RouteHash()
 return before,f,route_sha

def main():
 mode,root=sys.argv[1],Path(sys.argv[2]);root.mkdir(exist_ok=True)
 try:
  if mode=='--unit':
   before,focus,route=unit_fixture()
   with patch.object(C.hashlib,'sha256',route):cases=tests(before,focus,{})
   basis='synthetic_metadata_and_mocked_identity_routes_not_live_proof'
  elif mode=='--live':
   def read(n):return json.loads((root/n).read_text(encoding='utf-8-sig'))
   cases=tests(read('registrations-before.json'),read('focus-baseline.json'),read('svc-trust.json'));basis='actual_pre_gate_definitions_signature_measurements_and_real_identity_hashes'
  else:raise ValueError('mode_refused')
  r={'schema':'enforced_time_rules_tests_v1','basis':basis,'os_tasks_modified':False,'all_passed':all(c['passed'] for c in cases),'case_count':len(cases),'cases':cases}
 except Exception as e:r={'schema':'enforced_time_rules_tests_v1','all_passed':False,'os_tasks_modified':False,'error_code':str(e) if re.fullmatch('[a-z_]{1,80}',str(e)) else 'enforced_rule_fixture_failed','error_type':type(e).__name__}
 (root/('enforced-time-rules-live-tests.json' if mode=='--live' else 'enforced-time-rules-unit-tests.json')).write_text(json.dumps(r,indent=2));print(json.dumps({k:v for k,v in r.items() if k!='cases'}));return 0 if r['all_passed'] else 1
if __name__=='__main__':sys.exit(main())
