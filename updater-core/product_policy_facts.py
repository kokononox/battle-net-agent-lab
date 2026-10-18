"""Offline, release-bound ProductConfig FACTS, not a complete selection policy.
Consumes bytes only. No paths, network, install/uninstall actions or file selection.
ProductConfig is bound to the exact saved versions table of a pinned target;
legacy TargetSnapshot/checkpoint identities are deliberately not reinterpreted.
"""
import hashlib,re
from release_core import TargetSnapshot,need,table,only,ck,strict_json
from selection_policy import normalize_profile
TOKEN=re.compile(r'[A-Za-z0-9_-]{1,64}\Z')

def obj(v):
 need(type(v)is dict,'product_config_object');return v

def words(v):
 need(type(v)is list and len(v)<=256 and all(type(x)is str and TOKEN.fullmatch(x)for x in v),'product_config_tokens')
 need(len(set(v))==len(v),'product_config_duplicate_token');return list(v)

def section(root,key):
 # Missing optional sections are absent evidence, NOT proof of disabled features.
 return obj(obj(root.get(key,{})).get('config',{}))

def inspect_product_config(target,versions_raw,config_raw,profile):
 need(type(target)is TargetSnapshot,'product_config_target_type')
 need(type(versions_raw)is bytes and hashlib.sha256(versions_raw).hexdigest()==target.versions_sha256,'product_config_versions_identity')
 row=only(table(versions_raw),'Region',target.scope.region)
 need(row.get('VersionsName')==target.version and row.get('BuildId')==str(target.build_id)and row.get('BuildConfig')==target.build_config and row.get('CDNConfig')==target.cdn_config,'product_config_release_disagreement')
 key=ck(row.get('ProductConfig'))
 need(type(config_raw)is bytes and 0<len(config_raw)<=65536,'product_config_size')
 need(hashlib.md5(config_raw).hexdigest()==key,'product_config_content_key')
 root=obj(strict_json(config_raw));allc=section(root,'all')
 need(allc.get('product')=='WoW' and allc.get('update_method')=='ngdp' and allc.get('shared_container_default_subfolder')=='_retail_','product_config_unsupported_product_layout')
 p=normalize_profile(profile);need(p['platform']=='Windows' and p['region'].lower()==target.scope.region,'product_config_profile_scope')
 win=section(obj(root.get('platform')),'win');need(bool(win),'product_config_windows_missing')
 arch_fields={'x86_64':'tags_64bit','x86_32':'tags_32bit','arm64':'tags_arm64'}
 need(p['architecture']in arch_fields,'product_config_architecture_unsupported')
 platform_tags=words(win.get('tags'));architecture_tags=words(win.get(arch_fields[p['architecture']]))
 need(platform_tags==['Windows']and architecture_tags==[p['architecture']],'product_config_tag_mapping_unsupported')
 supported=words(allc.get('supported_locales'));aliases=obj(allc.get('replacement_locales',{}));need(len(aliases)<=256,'product_config_alias_budget')
 for a,b in aliases.items():
  need(type(a)is str and TOKEN.fullmatch(a)and type(b)is str and TOKEN.fullmatch(b),'product_config_alias_token')
 def canonical(name):
  seen=set()
  while name in aliases:
   need(name not in seen and len(seen)<16,'product_config_alias_cycle_or_depth');seen.add(name);name=aliases[name]
  need(name in supported,'product_config_locale_unsupported');return name
 for name in aliases:canonical(name)
 normalized={k:sorted(set(canonical(x)for x in p[k]))for k in ('text_locales','speech_locales')}
 reg=section(root,target.scope.region)
 sources=[('all.config',allc),('platform.win.config',win),(target.scope.region+'.config',reg)]
 # Locale sections can advertise extra tags too. Never confuse zhCN with CN.
 for name in sorted(set(normalized['text_locales']+normalized['speech_locales'])):
  sources.append((name.lower()+'.config',section(root,name.lower())))
 extra=[{'source':name+'.extra_tags','tags':words(s['extra_tags'])}for name,s in sources if 'extra_tags'in s]
 block_copy=allc.get('enable_block_copy_patch')
 need(block_copy is None or type(block_copy)is bool,'product_config_patch_flag')
 return {'format':'release-bound-product-config-facts-1','target':target.public(),'product_config_key':key,'product_config_sha256':hashlib.sha256(config_raw).hexdigest(),'product_config_bytes':len(config_raw),'versions_table_sha256':target.versions_sha256,'release_table_and_content_key_bound':True,'publisher_signature_verified':False,'profile_input':p,'canonical_locale_facts':normalized,'supported_locales':supported,'replacement_locales':dict(aliases),'windows_platform_tags':platform_tags,'windows_architecture_tags':architecture_tags,'applicable_explicit_extra_tag_declarations':extra,'absent_extra_tags_mean_disabled':False,'region_inferred_from_locale':False,'region_tag_rule_qualified':False,'block_copy_patch_advertised':block_copy,'block_copy_patch_implemented':False,'install_uninstall_actions_interpreted':False,'external_paths_used':False,'profile_origin':'explicit_input_NOT_live_preferences','vendor_selection_policy_qualified':False,'feature_selection_semantics_qualified':False,'dependency_and_variant_policy_qualified':False,'active_generation_proven':False,'required_set_selected':False,'promotion_to_required_set_permitted':False,'required_network_download_bytes':None,'network_requests':0,'game_access':False,'installation_ready':False,'apply_authorized':False}

def review_candidate_product_facts(base,objects,plan_dir,profile,versions_raw,config_raw):
 """Integrate facts with the existing hash-verified candidate; never mutate it."""
 from selection_policy import review_existing_candidate
 candidate=review_existing_candidate(base,objects,plan_dir,profile)
 facts=inspect_product_config(TargetSnapshot.restore(candidate['target']),versions_raw,config_raw,profile)
 facts['candidate_database_sha256']=candidate['candidate_database_sha256']
 facts['source_metadata_sha256']=candidate['source_metadata_sha256']
 facts['existing_candidate_identity_reverified']=True
 facts['candidate_plan_modified']=False
 facts['canonical_locale_differs_from_input']=any(facts['canonical_locale_facts'][k]!=facts['profile_input'][k]for k in ('text_locales','speech_locales'))
 facts['locale_alias_replan_review_required']=facts['canonical_locale_differs_from_input']
 return facts

if __name__=='__main__':
 import argparse,json
 from pathlib import Path
 a=argparse.ArgumentParser(description=__doc__)
 for name in ('binding-workspace','objects-workspace','candidate-workspace','profile-json','versions-file','product-config-file','output'):a.add_argument('--'+name,required=True)
 x=a.parse_args()
 def bounded(path,cap):
  with Path(path).open('rb')as f:raw=f.read(cap+1)
  need(0<len(raw)<=cap,'product_config_input_budget');return raw
 r=review_candidate_product_facts(x.binding_workspace,x.objects_workspace,x.candidate_workspace,strict_json(bounded(x.profile_json,65536)),bounded(x.versions_file,4*1024**2),bounded(x.product_config_file,65536))
 with Path(x.output).open('x',encoding='utf-8')as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps({'status':'release_bound_product_facts_NOT_complete_policy','product_config_key':r['product_config_key'],'promotion_to_required_set_permitted':False}))
