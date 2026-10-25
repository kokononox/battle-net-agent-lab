"""Bounded task deltas, never a trust decision or proof of the mutation actor."""
import json,re,sys,xml.etree.ElementTree as E
from pathlib import Path
from ShadowSchedule import review as shadow_review
IDS={'6137a887b08bde613f10c2469a266d09ae1a4771d17512f64acba2c4d4d1e883':'RefreshCache','21475573fddc2e641b67691a5d4d3096ea5135278dae645a8fd4a2e0bc4c613a':'PrintJobCleanupTask','2b11947a6c63d26c27256985033a4d1d7e97e56883cf36ed29a8beb6f79a4559':'Registration','4023f1322db1c44e9afe47a715033f592132e209dd8511b71be83c290ae8c7a2':'SvcRestartTask'}
def shape(xml):
 out={}
 def walk(node,path):
  out[path]=(tuple(sorted(node.attrib.items())),(node.text or '').strip());counts={}
  for child in node:
   label=child.tag.split('}')[-1];counts[label]=counts.get(label,0)+1;walk(child,path+'/'+label+'['+str(counts[label])+']')
 try:walk(E.fromstring(xml),'Task')
 except Exception:return None
 return out

def enabled(row):
 if type(row.get('scheduler_enabled'))==bool:return row['scheduler_enabled']
 try:
  d=shape(row.get('xml',''));v=d.get('Task/Settings[1]/Enabled[1]',(None,None))[1];return {'true':True,'false':False}.get(v)
 except Exception:return None
def summarize(baseline,snapshots,final):
 r={'schema':'focus_task_control_summary_v1','scope':'read_only_same_lab_without_setup_execution','mutation_actor_proven':False,'automatic_exemptions_added':False,'image_signatures_newly_verified':False,'requested_snapshot_poll_interval_seconds':10,'maximum_poll_gap_proven':False,'continuous_event_coverage_proven':False,'baseline_system_identity':baseline.get('system_identity') is True,'snapshot_count':len(snapshots),'final_snapshot_available':bool(final),'target_process_polling_not_kernel_barrier':True,'enabled_source':'scheduler_api_when_available_else_explicit_xml','atomic_task_snapshot_proven':False,'target_processes_observed_max':max([x.get('target_processes_observed',0) for x in [baseline,*snapshots,final] if x],default=0),'query_error_count':sum(x.get('query_errors',0) for x in [baseline,*snapshots,final] if x),'tasks':[]}
 for id,name in IDS.items():
  a=baseline.get('tasks',{}).get(id,{});last=a;events=[]
  for snap in [*snapshots,final]:
   b=snap.get('tasks',{}).get(id,{})
   if not b:continue
   if last.get('xml_sha256')!=b.get('xml_sha256') or last.get('permissions_sha256')!=b.get('permissions_sha256'):
    x,y=shape(last.get('xml','')),shape(b.get('xml',''));fields=[k for k in sorted(set(x or {})|set(y or {})) if (x or {}).get(k)!=(y or {}).get(k)] if x is not None and y is not None else []
    events.append({'phase':snap.get('phase','unknown'),'elapsed_seconds':None if snap.get('phase')=='final' else snap.get('elapsed_seconds'), 'timing_basis':'phase_only_nominal_final' if snap.get('phase')=='final' else 'snapshot_watch_relative','changed_xml_fields':fields[:16],'xml_diff_complete':x is not None and y is not None,'actions_definition_changed':(last['actions_sha256']!=b['actions_sha256']) if 'actions_sha256' in last and 'actions_sha256' in b else None,'principal_definition_changed':(last['principals_sha256']!=b['principals_sha256']) if 'principals_sha256' in last and 'principals_sha256' in b else None,'permissions_changed':(last['permissions_sha256']!=b['permissions_sha256']) if 'permissions_sha256' in last and 'permissions_sha256' in b else None,'enabled_before':enabled(last),'enabled_after':enabled(b),'capture_complete':last.get('capture_complete') is True and b.get('capture_complete') is True})
   last=b
  end=final.get('tasks',{}).get(id,{})
  def equal(key):return a.get(key)==end.get(key) if key in a and key in end else None
  ba,bb=a.get('binding',{}),end.get('binding',{});binding_complete=ba.get('capture_complete') is True and bb.get('capture_complete') is True
  row={'identifier':name,'identity_sha256':id,'baseline_enabled':enabled(a),'final_enabled':enabled(end),'baseline_signature_checked_before_gate':a.get('baseline_signature',{}).get('checked_before_gate') is True,'baseline_signature_valid_microsoft':a.get('baseline_signature',{}).get('valid_microsoft') is True,'baseline_signature_hash_stable':a.get('baseline_signature',{}).get('hash_stable') is True,'baseline_capture_complete':a.get('capture_complete') is True,'final_capture_complete':end.get('capture_complete') is True,'baseline_failure_stage':a.get('failure_stage') if a.get('failure_stage') in {'task_xml','task_permissions','task_binding','baseline_signature_before_gate'} else None,'final_failure_stage':end.get('failure_stage') if end.get('failure_stage') in {'task_xml','task_permissions','task_binding','baseline_signature_before_gate'} else None,'baseline_failure_hresult':a.get('failure_hresult') if re.fullmatch('[a-f0-9]{8}',a.get('failure_hresult','')) else None,'final_failure_hresult':end.get('failure_hresult') if re.fullmatch('[a-f0-9]{8}',end.get('failure_hresult','')) else None,'observed_change_count':len(events),'changed_without_setup':bool(events),'automatic_exemption_granted':False,'observed_changes':events[:8],'changes_omitted':max(0,len(events)-8),'baseline_final_actions_equal':equal('actions_sha256'),'baseline_final_principals_equal':equal('principals_sha256'),'baseline_final_permissions_equal':equal('permissions_sha256'),'deep_binding_complete_both':binding_complete,'baseline_final_binding_equal':(ba.get('binding_hash')==bb.get('binding_hash') and ba.get('file_sha256')==bb.get('file_sha256')) if binding_complete else None,'baseline_image_sha256':ba.get('file_sha256') if re.fullmatch('[a-f0-9]{64}',ba.get('file_sha256','')) else None,'final_image_sha256':bb.get('file_sha256') if re.fullmatch('[a-f0-9]{64}',bb.get('file_sha256','')) else None}
  r['tasks'].append(row)
 r['baseline_signatures_verified_count']=sum(all(t.get(k) is True for k in ['baseline_signature_checked_before_gate','baseline_signature_valid_microsoft','baseline_signature_hash_stable']) for t in r['tasks'])
 r['image_signatures_newly_verified']=r['baseline_signatures_verified_count']>0
 r['image_signature_scope']='baseline_pre_gate_only'
 r['shadow_schedule_review']=shadow_review(baseline,final)
 return r

def read(p):
 try:
  if p.stat().st_size>2097152:return {}
  return json.loads(p.read_text(encoding='utf-8-sig'))
 except Exception:return {}
def main():
 root=Path(sys.argv[1]);b=read(root/'focus-baseline.json');pre=read(root/'focus-prelaunch.json');hist=read(root/'focus-history.json');end=read(root/'focus-final.json') or read(root/'focus-observation-end.json');snaps=([pre] if pre else [])+hist.get('samples',[])[:32];r=summarize(b,snaps,end);classification=read(root/'classification.json');allowed={x.get('identity_sha256') for x in classification.get('details',[]) if x.get('allowed') is True};r['authorization_source']='runtime_classification_not_shape_review';r['automatic_exemptions_added']=classification.get('classified_two_time_reschedules',0)>0
 for t in r['tasks']:t['automatic_exemption_granted']=t['identity_sha256'] in allowed
 (root/'focus-task-summary.json').write_text(json.dumps(r))
if __name__=='__main__':main()
