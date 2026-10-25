"""Exactly one observed Windows task's CalendarTrigger StartBoundary, never general task drift."""
import hashlib,json,re,sys,datetime,copy
from pathlib import Path
import xml.etree.ElementTree as E
PIN='4023f1322db1c44e9afe47a715033f592132e209dd8511b71be83c290ae8c7a2'
NS='http://schemas.microsoft.com/windows/2004/02/mit/task';Q='{'+NS+'}'
PATH='./'+Q+'Triggers/'+Q+'CalendarTrigger/'+Q+'StartBoundary'
def parse(text):
 if not isinstance(text,str) or len(text)>65536 or re.search(r'<!\s*(DOCTYPE|ENTITY)',text,re.I):raise ValueError('xml_refused')
 r=E.fromstring(text)
 if r.tag!=Q+'Task' or sum(1 for _ in r.iter())>512:raise ValueError('xml_refused')
 return r
def canon(n):
 # Preserve meaningful leaf text and ALL qualified names, attributes and child ordering.
 text=n.text or ''
 if len(n) and not text.strip():text=''
 tail=n.tail or ''
 if not tail.strip():tail=''
 return (n.tag,tuple(sorted(n.attrib.items())),text,tail,tuple(canon(x) for x in n))
def baseline_shape(r):
 actions=r.findall('./'+Q+'Actions');principals=r.findall('./'+Q+'Principals/'+Q+'Principal')
 if len(actions)!=1 or len(principals)!=1:return False
 a=actions[0];p=principals[0]
 if len(a)!=1 or a[0].tag!=Q+'ComHandler' or len(a[0].findall(Q+'ClassId'))!=1:return False
 uid=p.find(Q+'UserId')
 if uid is None or uid.text not in {'S-1-5-18','S-1-5-19','S-1-5-20'}:return False
 if a.get('Context') and a.get('Context')!=p.get('id'):return False
 return True
def reschedule_only(key,old,new,trust,current):
 try:
  if hashlib.sha256(key.encode()).hexdigest()!=PIN:return False,'task_identity_not_pinned'
  if trust.get('captured_before_target') is not True or trust.get('system_identity') is not True or trust.get('signature_valid_microsoft') is not True:return False,'baseline_trust_missing'
  b=trust.get('binding',{});a=current
  if b.get('capture_complete') is not True or a.get('capture_complete') is not True:return False,'binding_incomplete'
  for field in ['class_id','binding_hash','file_sha256','image_path']:
   if not b.get(field) or b[field]!=a.get(field):return False,'com_binding_or_image_changed'
  x=parse(old);y=parse(new)
  if not baseline_shape(x) or not baseline_shape(y):return False,'baseline_shape_unsupported'
  bx=x.findall(PATH);by=y.findall(PATH)
  if len(bx)!=1 or len(by)!=1:return False,'boundary_shape_unsupported'
  t0=bx[0].text;t1=by[0].text
  for t in [t0,t1]:
   if not isinstance(t,str) or len(t)>64 or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)?',t):return False,'invalid_boundary'
   datetime.datetime.fromisoformat(t.replace('Z','+00:00'))
  if t0==t1:return False,'no_reschedule'
  bx[0].text=by[0].text='G19_ALLOWED_START_BOUNDARY'
  if canon(x)!=canon(y):return False,'other_task_definition_changed'
  return True,'pinned_svc_calendar_start_only'
 except Exception:return False,'classification_failed_closed'
def evaluate(before,after,trust):
 raw=allowed=0;details=[]
 for kind in ['services','tasks']:
  a=before.get(kind,{});b=after.get(kind,{})
  for key in sorted(set(a)|set(b)):
   if a.get(key)==b.get(key):continue
   raw+=1;ok=False;why='service_or_unclassified_task_change'
   if kind=='tasks' and key in a and key in b:
    ok,why=reschedule_only(key,before.get('task_xml',{}).get(key),after.get('task_xml',{}).get(key),trust,after.get('svc_binding',{}))
   if ok:allowed+=1
   details.append({'kind':kind,'identity_sha256':hashlib.sha256(key.encode()).hexdigest(),'classification':why,'allowed':ok})
  prior=before.get('svc_binding',{});now=after.get('svc_binding',{})
 binding_blocker=int(prior.get('capture_complete') is True and (now.get('capture_complete') is not True or any(prior.get(f)!=now.get(f) for f in ['class_id','binding_hash','file_sha256','image_path'])))
 return {'schema':'narrow_task_g19_v1','raw_changes':raw,'classified_reschedules':allowed,'binding_change_blockers':binding_blocker,'blocked_changes':raw-allowed+binding_blocker,'details':details}
def main():
 root=Path(sys.argv[1]);before=json.loads((root/'registrations-before.json').read_text(encoding='utf-8-sig'));after=json.loads((root/'registrations-after.json').read_text(encoding='utf-8-sig'))
 try:trust=json.loads((root/'svc-trust.json').read_text(encoding='utf-8-sig'))
 except Exception:trust={}
 result=evaluate(before,after,trust);(root/'classification.json').write_text(json.dumps(result));print(json.dumps(result,separators=(',',':')))
if __name__=='__main__':main()
