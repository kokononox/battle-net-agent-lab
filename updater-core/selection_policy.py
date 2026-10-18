"""Typed profile-to-candidate policy gate. Never vendor qualification or apply.
No optional/missing core dimensions; speech/text locales form separate clauses.
Feature tags are audited, not guessed to be install preferences. Offline only.
"""
import hashlib,json,re
from pathlib import Path
from release_core import need,strict_json,TargetSnapshot
from required_set import select_bitmap
from catalogue_readers import parse_install,DownloadReader
from config_binding import bind,ManifestDescriptor
from reuse_candidates import sha_file

KINDS={1:'platform',2:'architecture',3:'locale',4:'region',5:'category',16384:'alternate_or_feature_UNQUALIFIED'}
PROFILE_KEYS={'platform','architecture','region','text_locales','speech_locales'}
TOKEN=re.compile(r'[A-Za-z0-9_-]{1,64}\Z')

def normalize_profile(profile):
 need(type(profile)is dict and set(profile)==PROFILE_KEYS,'policy_profile_shape')
 result={}
 for name in ('platform','architecture','region'):
  v=profile[name];need(type(v)is str and TOKEN.fullmatch(v)is not None,'policy_profile_token');result[name]=v
 for name in ('text_locales','speech_locales'):
  vs=profile[name];need(type(vs)is list and len(vs)<=16 and all(type(v)is str and TOKEN.fullmatch(v)is not None for v in vs),'policy_locale_list');need(len(set(vs))==len(vs),'policy_duplicate_locale');result[name]=sorted(vs)
 need(result['text_locales']or result['speech_locales'],'policy_no_locale');need(sum(len(result[n])for n in ('text_locales','speech_locales'))<=16,'policy_clause_budget');return result

def tag_table(tags,count):
 # Reuse structural/bit geometry checks; NEVER select a fallback default.
 need(type(tags)in(list,tuple) and bool(tags),'policy_no_tags')
 select_bitmap(tags,count,tags[0][1])
 table={}
 for _,name,kind,bits in tags:
  need(kind in KINDS,'policy_unknown_tag_type');table[name]=(kind,bits)
 return table

def compile_profile(profile,table):
 p=normalize_profile(profile)
 def require(name,kind):
  need(name in table,'policy_required_dimension_missing:'+name)
  need(table[name][0]==kind,'policy_dimension_type_mismatch:'+name)
 for key,kind in (('platform',1),('architecture',2),('region',4)):require(p[key],kind)
 clauses=[]
 for category,key in (('speech','speech_locales'),('text','text_locales')):
  if not p[key]:continue
  require(category,5)
  for locale in p[key]:
   require(locale,3);terms=[p['platform'],p['architecture'],p['region'],locale,category];need(len(set(terms))==5,'policy_dimension_name_collision');clauses.append(' '.join(terms))
 return ':'.join(clauses),p

def review_tags(install_tags,install_count,download_tags,download_count,profile):
 it=tag_table(install_tags,install_count);dt=tag_table(download_tags,download_count)
 need({k:v[0]for k,v in it.items()}=={k:v[0]for k,v in dt.items()},'policy_manifest_tag_schema_disagreement')
 expression,p=compile_profile(profile,it);other,_=compile_profile(profile,dt);need(expression==other,'policy_manifest_expression_disagreement')
 reviews={};masks={}
 for label,tags,count,table in (('install',install_tags,install_count,it),('download',download_tags,download_count,dt)):
  mask,selection=select_bitmap(tags,count,expression);masks[label]=mask;mi=int.from_bytes(mask,'big');feature=[]
  for name,(kind,bits)in sorted(table.items()):
   if kind!=16384:continue
   bi=int.from_bytes(bits,'big');feature.append({'tag':name,'kind':kind,'selected_members':(mi&bi).bit_count(),'selected_nonmembers':(mi&~bi).bit_count(),'meaning_and_preference_qualified':False})
  from selection_semantics import discriminate
  reviews[label]={'records':count,'selected_records':selection['selected_records'],'bitmap_sha256':selection['bitmap_sha256'],'unresolved_feature_tags':feature,'semantic_discrimination':discriminate(tags,count,p,mask)}
 return expression,masks,{'format':'typed-profile-selection-review-1','profile':p,'expression':expression,'expression_generated_from_typed_dimensions':True,'optional_missing_dimensions_allowed':False,'schema_name_and_kind_agreement':True,'manifest_tag_schema':[{'name':n,'kind':k}for n,(k,b)in sorted(it.items())],'manifests':reviews,'vendor_selection_policy_qualified':False,'fresh_installed_preferences_proven':False,'dependency_and_variant_policy_qualified':False,'patch_route_policy_qualified':False,'required_set_selected':False,'promotion_to_required_set_permitted':False,'blockers':['independent_vendor_selection_policy_not_qualified','live_installed_preferences_not_proven','dependency_variant_and_patch_policy_not_qualified']+(['feature_tag_meanings_and_preferences_not_qualified']if any(k==16384 for k,b in it.values())else[]),'required_network_download_bytes':None,'network_requests':0,'game_access':False,'installation_ready':False,'apply_authorized':False}

def review_existing_candidate(base,objects,plan_dir,profile):
 """Read-only gate on owned metadata and candidate; does not modify any plan.
 Rehash all files consumed and the full catalogue/plan; no live install inference.
 """
 base,objects,plan_dir=map(Path,(base,objects,plan_dir));plan=strict_json((plan_dir/'CANDIDATE-PLAN-to-share.json').read_bytes());cat=strict_json((objects/'CATALOGUE-VERIFIED-to-share.json').read_bytes());receipt=strict_json((objects/'METADATA-VERIFIED-to-share.json').read_bytes())
 need(plan['status']=='candidate_selection_and_crosswalk_checked_NOT_vendor_required_set' and plan['required_set_selected']is False,'policy_candidate_receipt_required')
 need(receipt['status']=='three_metadata_objects_identity_and_blte_verified' and cat['status']=='full_target_metadata_crosswalk_verified','policy_verified_sources_required')
 target=TargetSnapshot.restore(plan['target']);need(plan['target']==cat['target']==receipt['target'],'policy_target_mismatch');p=normalize_profile(profile);need(p['region'].lower()==target.scope.region,'policy_target_region_mismatch')
 binding=bind(target,(base/'observed-build.config').read_bytes(),(base/'observed-cdn.config').read_bytes());descriptors={d['name']:ManifestDescriptor(**d)for d in binding['manifest_descriptors']};proofs={d['name']:d for d in receipt['metadata']}
 need(plan['source_catalogue_sha256']==cat['database']['sha256'],'policy_catalogue_disagreement')
 for db,expected in ((plan_dir/'CANDIDATE-PLAN.sqlite',plan['database']),(objects/'TARGET-CATALOGUE.sqlite',cat['database'])):
  need(db.is_file()and not db.is_symlink()and db.stat().st_size==expected['bytes']and sha_file(db)==expected['sha256'],'policy_database_identity')
 inputs={}
 for name in ('install','download'):
  path=objects/(name+'.decoded');desc=descriptors[name];need(path.is_file()and not path.is_symlink()and path.stat().st_size==desc.decoded_size,'policy_metadata_geometry')
  sha=sha_file(path)
  with path.open('rb')as f:md5=hashlib.file_digest(f,'md5').hexdigest()
  need(md5==desc.ckey==proofs[name]['ckey']and sha==proofs[name]['decoded_sha256']==cat['source_metadata_sha256'][name]==plan['source_metadata_sha256'][name],'policy_metadata_identity');inputs[name]=sha
 it,entries=parse_install((objects/'install.decoded').read_bytes())
 with(objects/'download.decoded').open('rb')as f:
  dr=DownloadReader(f,(objects/'download.decoded').stat().st_size);dt=list(dr.tags());n=dr.n
 expression,masks,report=review_tags(it,len(entries),dt,n,p)
 for name,tags,count in (('install',it,len(entries)),('download',dt,n)):
  old=plan[name+'_selection'];oldmask,audit=select_bitmap(tags,count,old['expression']);need(oldmask==masks[name],'policy_candidate_selection_disagrees');need(audit['bitmap_sha256']==old['bitmap_sha256']and audit['selected_records']==old['selected_records']==report['manifests'][name]['selected_records'],'policy_candidate_receipt_disagrees')
 for name in inputs:need(sha_file(objects/(name+'.decoded'))==inputs[name],'policy_metadata_changed')
 report.update(target=target.public(),source_metadata_sha256=inputs,candidate_database_sha256=plan['database']['sha256'],source_catalogue_sha256=cat['database']['sha256'],candidate_bitmaps_agree_with_typed_profile=True,profile_origin='explicit_public_profile_NOT_live_install_preferences',scope='owned_copied_metadata_only')
 return report

if __name__=='__main__':
 import argparse
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--binding-workspace',required=True);a.add_argument('--objects-workspace',required=True);a.add_argument('--candidate-workspace',required=True);a.add_argument('--profile-json',required=True);a.add_argument('--output',required=True);x=a.parse_args();r=review_existing_candidate(x.binding_workspace,x.objects_workspace,x.candidate_workspace,strict_json(Path(x.profile_json).read_bytes()))
 with Path(x.output).open('x')as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps({'status':'typed_profile_candidate_reviewed_NOT_vendor_qualification','promotion_to_required_set_permitted':False,'blockers':r['blockers']}))
