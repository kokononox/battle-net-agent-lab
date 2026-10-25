import copy,sys,json,hashlib,datetime
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from Classify import *
KEY=r'\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask'
SYNTH=f'''<Task xmlns="{NS}" version="1.2"><Principals><Principal id="NetworkService"><UserId>S-1-5-20</UserId><LogonType>ServiceAccount</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Triggers><CalendarTrigger><StartBoundary>2026-10-25T01:00:00</StartBoundary></CalendarTrigger></Triggers><Settings><Enabled>true</Enabled></Settings><Actions Context="NetworkService"><ComHandler><ClassId>{{11111111-1111-1111-1111-111111111111}}</ClassId></ComHandler></Actions></Task>'''
def tests(xml,trust,binding):
 results=[]
 def check(label,old,new,expected,*,key=KEY,t=trust,b=binding):
  got,reason=reschedule_only(key,old,new,t,b);results.append({'name':label,'passed':got==expected,'expected_allowed':expected,'actual_allowed':got,'reason':reason})
 base=parse(xml);node=base.find(PATH)
 if node is None:raise ValueError('live_calendar_missing')
 newer=copy.deepcopy(base);n=newer.find(PATH);n.text='2026-10-26T01:02:03' if node.text!='2026-10-26T01:02:03' else '2026-10-27T01:02:03'
 good=E.tostring(newer,encoding='unicode');check('exact_calendar_reschedule',xml,good,True)
 def mutation(label,fun):
  z=copy.deepcopy(newer)
  try:fun(z);check(label,xml,E.tostring(z,encoding='unicode'),False)
  except Exception:results.append({'name':label,'passed':False,'error_code':'fixture_mutation_unsupported'})
 mutation('com_class_id_changed',lambda z:setattr(z.find('./'+Q+'Actions/'+Q+'ComHandler/'+Q+'ClassId'),'text','{22222222-2222-2222-2222-222222222222}'))
 mutation('com_data_added',lambda z:E.SubElement(z.find('./'+Q+'Actions/'+Q+'ComHandler'),Q+'Data'))
 mutation('exec_action_added',lambda z:E.SubElement(z.find('./'+Q+'Actions'),Q+'Exec'))
 mutation('arguments_added',lambda z:setattr(E.SubElement(z.find('./'+Q+'Actions'),Q+'Arguments'),'text','--unsafe'))
 mutation('principal_changed',lambda z:setattr(z.find('./'+Q+'Principals/'+Q+'Principal/'+Q+'UserId'),'text','S-1-5-32-544'))
 mutation('principal_attribute_changed',lambda z:z.find('./'+Q+'Principals/'+Q+'Principal').set('id','other'))
 def toggle_enabled(z):
  settings=z.find('./'+Q+'Settings')
  if settings is None:settings=E.SubElement(z,Q+'Settings')
  enabled=settings.find(Q+'Enabled')
  if enabled is None:enabled=E.SubElement(settings,Q+'Enabled');enabled.text='false'
  else:enabled.text='false' if enabled.text=='true' else 'true'
 mutation('enabled_toggled',toggle_enabled)
 mutation('trigger_added',lambda z:E.SubElement(z.find('./'+Q+'Triggers'),Q+'BootTrigger'))
 mutation('boundary_attribute_added',lambda z:z.find(PATH).set('unknown','1'))
 mutation('invalid_boundary',lambda z:setattr(z.find(PATH),'text','not_a_date'))
 check('wrong_task_path',xml,good,False,key=r'\Other\SvcRestartTask')
 check('namespace_changed',xml,good.replace(NS,'urn:other'),False)
 check('dtd_rejected',xml,'<!DOCTYPE Task [<!ENTITY x "x">]>'+good,False)
 check('missing_trust',xml,good,False,t={})
 bad=copy.deepcopy(trust);bad['signature_valid_microsoft']=False;check('untrusted_publisher',xml,good,False,t=bad)
 for field in ['file_sha256','binding_hash','class_id','image_path']:
  bad=copy.deepcopy(binding);bad[field]='changed';check(field+'_changed',xml,good,False,b=bad)
 # Full inventory evaluator: new/deleted task, service change and a second change never disappear.
 def snap(text):return {'services':{},'tasks':{KEY:hashlib.sha256(text.encode()).hexdigest()},'task_xml':{KEY:text},'svc_binding':binding}
 a=snap(xml);b=snap(good)
 for label,edit,expected in [('new_task',lambda b:b['tasks'].update({'\\Other\\NewTask':'new'}),1),('service_change',lambda b:b['services'].update({'other':'new'}),1),('deleted_pinned_task',lambda b:b['tasks'].clear(),1)]:
  c=copy.deepcopy(b);edit(c);v=evaluate(a,c,trust);results.append({'name':label,'passed':v['blocked_changes']==expected,'expected_blocked':expected,'actual_blocked':v['blocked_changes']})
 c=copy.deepcopy(a);c['svc_binding']['file_sha256']='changed';v=evaluate(a,c,trust);results.append({'name':'binding_change_without_xml_change','passed':v['blocked_changes']==1 and v['binding_change_blockers']==1})
 v=evaluate(a,a,trust);results.append({'name':'unchanged_inventory','passed':v['raw_changes']==0 and v['blocked_changes']==0})
 return {'live_shape':{'calendar_boundaries':len(base.findall(PATH)),'enabled_explicit':base.find('./'+Q+'Settings/'+Q+'Enabled') is not None,'baseline_shape_supported':baseline_shape(base)},'schema':'classifier_g19_tests_v1','level':'in_memory_xml_and_inventory_not_live_task_mutation','all_passed':all(x['passed'] for x in results),'case_count':len(results),'cases':results}
def main():
 mode=sys.argv[1];root=Path(sys.argv[2]);root.mkdir(exist_ok=True)
 try:
  if mode=='--synthetic':
   binding={'capture_complete':True,'class_id':'fixture','binding_hash':'fixture','file_sha256':'fixture','image_path':'fixture'};trust={'captured_before_target':True,'system_identity':True,'signature_valid_microsoft':True,'binding':binding};xml=SYNTH
  elif mode=='--live':
   before=json.loads((root/'registrations-before.json').read_text(encoding='utf-8-sig'));trust=json.loads((root/'svc-trust.json').read_text(encoding='utf-8-sig'));binding=before.get('svc_binding',{});xml=before['task_xml'][KEY]
  else:raise ValueError('mode_refused')
  r=tests(xml,trust,binding);r['basis']='synthetic_fixture' if mode=='--synthetic' else 'live_pre_target_baseline_with_com_measurement'
 except Exception as exc:r={'schema':'classifier_g19_tests_v1','all_passed':False,'case_count':0,'error_type':type(exc).__name__,'error_code':str(exc) if re.fullmatch('[a-z_]{1,80}',str(exc)) else 'classifier_tests_unsupported_baseline'}
 (root/('classifier-unit-tests.json' if mode=='--synthetic' else 'classifier-live-tests.json')).write_text(json.dumps(r,indent=2));print(json.dumps({k:v for k,v in r.items() if k!='cases'}));return 0 if r['all_passed'] else 1
if __name__=='__main__':sys.exit(main())
