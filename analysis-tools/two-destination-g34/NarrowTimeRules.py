"""Enforced exact-two reschedules; PrintJobCleanupTask is deliberately NOT a member."""
import hashlib
from ShadowSchedule import PINS,candidate
from TaskXml import parse,canon

def rows(id,context):
 try:
  baseline,current=context['baseline'],context['current']
  if baseline.get('system_identity') is not True or current.get('system_identity') is not True:return None,None,'time_rule_system_snapshot_missing'
  if baseline.get('captured_before_target') is not True or baseline.get('captured_before_gate') is not True:return None,None,'time_rule_baseline_scope_missing'
  a,b=baseline.get('tasks',{}).get(id,{}),current.get('tasks',{}).get(id,{})
  if id not in PINS:return None,None,'time_rule_identity_not_pinned'
  if any(v.get('capture_complete') is not True for v in (a,b)):return None,None,'time_rule_capture_incomplete'
  sig=a.get('baseline_signature',{})
  if not all(sig.get(k) is True for k in ['checked_before_gate','hash_stable','valid_microsoft']):return None,None,'time_rule_baseline_signature_missing'
  _,action,principal,image,permissions=PINS[id]
  for k,pin in [('actions_sha256',action),('principals_sha256',principal),('permissions_sha256',permissions)]:
   if a.get(k)!=pin or b.get(k)!=pin:return None,None,'time_rule_definition_or_acl_pin_mismatch'
  ba,bb=a.get('binding',{}),b.get('binding',{})
  if any(v.get('capture_complete') is not True or v.get('file_sha256')!=image for v in (ba,bb)):return None,None,'time_rule_image_pin_mismatch'
  if not ba.get('binding_hash') or ba['binding_hash']!=bb.get('binding_hash'):return None,None,'time_rule_binding_changed'
  return a,b,None
 except Exception:return None,None,'time_rule_context_failed_closed'

def same_xml(a,b):
 try:return canon(parse(a))==canon(parse(b))
 except Exception:return False

def reschedule_decision(id,old,new,context):
 a,b,why=rows(id,context)
 if why:return False,why
 if not same_xml(old,a.get('xml')) or not same_xml(new,b.get('xml')):return False,'time_rule_inventory_focus_mismatch'
 ok,reason=candidate(id,a,b)
 return (True,'pinned_time_boundary_only') if ok else (False,'time_rule_'+reason)

def time_guard_problem(id,before,after,context):
 a,b,why=rows(id,context)
 if why:return why
 def find(snapshot):
  keys=[k for k in snapshot.get('tasks',{}) if hashlib.sha256(k.encode()).hexdigest()==id]
  return snapshot.get('task_xml',{}).get(keys[0]) if len(keys)==1 else None
 if not same_xml(find(before),a.get('xml')) or not same_xml(find(after),b.get('xml')):return 'time_rule_inventory_focus_mismatch'
 return None
