"""Two pinned TimeTrigger candidates. Shared strict shape check; shadow output itself never authorizes recovery."""
import re,datetime
from TaskXml import parse,canon,Q
PINS={
 '6137a887b08bde613f10c2469a266d09ae1a4771d17512f64acba2c4d4d1e883':('RefreshCache','f0aed5d367be1263be8db9e6163dd48bb99caf8ecf2e5c2a1c0eb0bcc3bee375','6bb901a74e7095cdc5dac12271a22caa48f6abab5a74199d7cef278c859551e3','526781e841584bf9e1d80cca5b770567184d4fc0e1a5fd8338bc0ede7bd04d4b','0e8261a733afe4bcf2776ce7ea4cd60b66b1e3e191ed899cbc3949966be3a88d'),
 '2b11947a6c63d26c27256985033a4d1d7e97e56883cf36ed29a8beb6f79a4559':('Registration','f1381f2334f7696b955a64757cffcfe0ec9e0d5e004496dbefb387689d43c17c','20b7ac06e8c15cf6ef67f555ff2105d0099c8676a47a17294e4cdc3497d0a4c0','a452bfcb6000d03942ddfaddcda5a7eb121447ed99b1ba090446b4a989f1f7ae','aab2bee5d4df25ac30c0f9116c20fe7341265e528fc33268e71639552ac70e64')}
PATH='./'+Q+'Triggers/'+Q+'TimeTrigger/'+Q+'StartBoundary'
def compare_xml(old,new):
 try:
  x,y=parse(old),parse(new);a,b=x.findall(PATH),y.findall(PATH)
  if len(a)!=1 or len(b)!=1:return False,'single_time_boundary_required'
  if a[0].text==b[0].text:return False,'no_reschedule'
  for t in (a[0].text,b[0].text):
   if not isinstance(t,str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)?',t):return False,'invalid_boundary'
   datetime.datetime.fromisoformat(t.replace('Z','+00:00'))
  a[0].text=b[0].text='SHADOW_ONLY_START_BOUNDARY'
  return (True,'strict_time_boundary_only') if canon(x)==canon(y) else (False,'other_xml_changed')
 except Exception:return False,'xml_failed_closed'
def candidate(id,a,b):
 if id not in PINS:return False,'identity_not_pinned'
 _,action,principal,image,permissions=PINS[id]
 if not all(v.get('capture_complete') is True for v in (a,b)):return False,'capture_incomplete'
 sig=a.get('baseline_signature',{})
 if not all(sig.get(k) is True for k in ['checked_before_gate','hash_stable','valid_microsoft']):return False,'baseline_signature_missing'
 for k,pin in [('actions_sha256',action),('principals_sha256',principal),('permissions_sha256',permissions)]:
  if a.get(k)!=pin or b.get(k)!=pin:return False,'pinned_definition_or_permissions_mismatch'
 ba,bb=a.get('binding',{}),b.get('binding',{})
 if not all(v.get('capture_complete') is True and v.get('file_sha256')==image for v in (ba,bb)):return False,'pinned_image_mismatch'
 if not ba.get('binding_hash') or ba['binding_hash']!=bb.get('binding_hash'):return False,'binding_changed'
 return compare_xml(a.get('xml'),b.get('xml'))
def review(baseline,final):
 result={'schema':'shadow_time_schedule_review_v1','mode':'shadow_only','enforcement_changed':False,'automatic_exemptions_added':False,'ready_for_enforcement':False,'pins_source':'verified_G28_G30_observations','tasks':[]}
 for id,pin in PINS.items():
  if baseline.get('system_identity') is not True or final.get('system_identity') is not True:ok,reason=False,'system_snapshot_missing'
  else:ok,reason=candidate(id,baseline.get('tasks',{}).get(id,{}),final.get('tasks',{}).get(id,{}))
  result['tasks'].append({'identifier':pin[0],'identity_sha256':id,'candidate_matches_strict_shape':ok,'reason':reason,'automatic_exemption_granted':False})
 return result
