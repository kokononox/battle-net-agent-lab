"""Read-only conservative review gate; NEVER authorizes exceptions or changes recovery."""
import json,sys
from pathlib import Path
TRUSTED_CONTROL={'local_system','administrators'}
# Only standard rights, independent of object-specific task rights.
CONTROL_MASK=0x00040000|0x00080000|0x10000000|0x40000000
READ_ONLY_MASK=0x001200A9

def review_permissions(p):
 if not isinstance(p,dict) or p.get('complete') is not True or p.get('descriptor_parsed') is not True:return {'status':'unknown','reason':'permissions_incomplete'}
 aces=p.get('aces')
 if not isinstance(aces,list) or not aces or len(aces)>64:return {'status':'unknown','reason':'aces_missing_or_unbounded'}
 flags=[]
 for a in aces:
  if type(a)!=dict or a.get('ace_type')!='AccessAllowed' or a.get('ace_flags')!='None':return {'status':'unknown','reason':'ace_semantics_not_supported'}
  n=a.get('access_mask');cat=a.get('identity_category')
  if type(n)!=int or not 0<=n<=0xffffffff:return {'status':'unknown','reason':'mask_invalid'}
  if cat not in TRUSTED_CONTROL:
   if n&CONTROL_MASK:
    flags.append({'identity_category':cat if cat in {'everyone','authenticated_users','users','local_service','network_service','other_identity'} else 'unclassified','write_dac':bool(n&0x40000),'write_owner':bool(n&0x80000),'generic_all':bool(n&0x10000000),'generic_write':bool(n&0x40000000),'mask_hex':format(n,'08x')})
   elif n&~READ_ONLY_MASK:return {'status':'unknown','reason':'object_specific_rights_not_approved'}
 if flags:return {'status':'blocked_for_automatic_exception','reason':'non_admin_control_ace','control_aces':flags,'effective_token_access_proven':False}
 return {'status':'no_non_admin_control_ace_in_supported_shape','effective_token_access_proven':False,'authorizes_exception':False}

def review_report(r):
 if r.get('schema')!='task_security_g30_v1' or r.get('system_identity') is not True:raise ValueError('input_identity')
 if len(r.get('samples',[]))!=2:raise ValueError('sample_count')
 out=[]
 for s in r['samples']:
  rows=[]
  for t in s.get('tasks',[]):rows.append({'identifier':t['identifier'],'identity_sha256':t['identity_sha256'],'permissions_review':review_permissions(t.get('normalized_folder_permissions')),'settings_enabled':t.get('settings_enabled')})
  out.append({'captured_utc':s['captured_utc'],'tasks':rows})
 return {'schema':'task_security_review_v1','source_commit':r['source_commit'],'run_id':r['run_id'],'automatic_exemptions_added':False,'recovery_policy_changed':False,'signature_alone_authorizes_exception':False,'mutation_actor_proven':False,'samples':out}
if __name__=='__main__':
 r=json.loads(Path(sys.argv[1]).read_text());result=review_report(r);Path(sys.argv[2]).write_text(json.dumps(result,indent=2))
