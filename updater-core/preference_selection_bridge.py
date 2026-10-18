"""Offline bridge: observed preference clauses -> audited candidate bitmaps.
Not an official tag-query implementation, required set, live capture or updater.
Never accepts a caller-supplied facts dict as an authority. Revalidates raw
metadata; private optional terms may be dropped ONLY if absent in BOTH tables.
"""
import hashlib
from release_core import need
from installed_identity import select_active
from installed_preferences import inspect_preferences,PRIVATE
from selection_policy import tag_table,compile_profile
from required_set import select_bitmap
KINDS={'platform':1,'architecture':2,'locale':3,'region':4,'category':5}

def review_preference_tags(info,config,install_tags,install_count,download_tags,download_count):
 facts=inspect_preferences(info,config)
 # Validate complete geometry and known type IDs, even unused tags.
 tables={'install':tag_table(install_tags,install_count),'download':tag_table(download_tags,download_count)}
 raw_clauses=select_active(info)['tags'].split(':')
 for clause in raw_clauses:
  for token in clause.split():
   name=token[:-1]if token.endswith('?')else token
   if PRIVATE.fullmatch(name):
    need(all(name not in t for t in tables.values()),'bridge_private_qualifier_present_in_manifest')
 clauses=facts['public_clauses']
 # Duplicate clauses are not silently deduplicated, even when private terms differ.
 expression=':'.join(' '.join(t['name']+('?'if t['optional']else'')for t in c)for c in clauses)
 masks={};reports={}
 for label,tags,count in (('install',install_tags,install_count),('download',download_tags,download_count)):
  table=tables[label];missing=[]
  for ci,clause in enumerate(clauses):
   for term in clause:
    if term['name']in table:
     need(table[term['name']][0]==KINDS[term['kind']],'bridge_dimension_type_mismatch')
    else:
     need(term['optional'],'bridge_required_dimension_missing')
     missing.append({'clause':ci,'name':term['name'],'kind':term['kind']})
  mask,audit=select_bitmap(tags,count,expression);masks[label]=mask
  # Legacy strict typed-profile model is a comparison, never a fallback.
  strict_available=all(name in table and table[name][0]==KINDS[term['kind']]for clause in clauses for term in clause for name in [term['name']])
  # Canonical ARM64 -> arm64 does not authorize changing original observed terms.
  strict_available=strict_available and all(n in table for n in [facts['profile']['platform'],facts['profile']['architecture'],facts['profile']['region']])
  strict=None
  if strict_available:
   strict_expression,_=compile_profile(facts['profile'],table);strict_mask,strict_audit=select_bitmap(tags,count,strict_expression)
   strict={'expression':strict_expression,'bitmap_sha256':strict_audit['bitmap_sha256'],'same_bitmap':strict_mask==mask}
   need(strict_mask==mask,'bridge_strict_profile_bitmap_disagreement')
  reports[label]={'records':count,'expression':expression,'selection_audit':audit,'optional_public_dimensions_absent':missing,'strict_profile_comparison_available':strict_available,'strict_profile_comparison':strict,'feature_selection_semantics_qualified':False}
 return masks,{'format':'installed-preference-candidate-bridge-1','scope':'owned_saved_metadata_only','baseline':facts['baseline'],'profile':facts['profile'],'public_clauses':clauses,'private_optional_qualifiers_withheld':facts['private_optional_qualifiers_withheld'],'private_terms_absent_in_both_manifest_tables':True,'raw_private_terms_or_install_path_exported':False,'manifests':reports,'candidate_query_semantics':'OR of AND clauses; absent optional terms ignored with audit; NOT independently vendor-qualified','public_optional_markers_preserved':True,'locale_category_pairing_preserved':True,'automatic_locale_or_architecture_remapping':False,'fresh_installed_preferences_proven':False,'active_generation_proven':False,'vendor_selection_policy_qualified':False,'feature_variant_dependency_policy_qualified':False,'required_set_selected':False,'promotion_to_required_set_permitted':False,'candidate_plan_modified':False,'required_network_download_bytes':None,'network_requests':0,'game_access':False,'installation_ready':False,'apply_authorized':False}

def review_preference_candidate(base,objects,plan_dir,info,config,versions_raw,product_config_raw):
 from pathlib import Path
 from product_policy_facts import inspect_product_config
 from selection_policy import review_existing_candidate
 from release_core import TargetSnapshot
 from catalogue_readers import parse_install,DownloadReader
 from reuse_candidates import sha_file
 facts=inspect_preferences(info,config)
 # Includes full target/catalogue/plan/decoded metadata identity gates.
 bound=review_existing_candidate(base,objects,plan_dir,facts['profile'])
 product=inspect_product_config(TargetSnapshot.restore(bound['target']),versions_raw,product_config_raw,facts['profile'])
 need(all(product['canonical_locale_facts'][k]==facts['profile'][k]for k in ('text_locales','speech_locales')),'bridge_locale_alias_replan_required')
 objects=Path(objects);expected=bound['source_metadata_sha256']
 for name in ('install','download'):need(sha_file(objects/(name+'.decoded'))==expected[name],'bridge_metadata_identity_changed')
 it,entries=parse_install((objects/'install.decoded').read_bytes())
 with(objects/'download.decoded').open('rb')as f:
  dr=DownloadReader(f,(objects/'download.decoded').stat().st_size);dt=list(dr.tags());n=dr.n
 masks,report=review_preference_tags(info,config,it,len(entries),dt,n)
 for name in ('install','download'):
  need(sha_file(objects/(name+'.decoded'))==expected[name],'bridge_metadata_identity_changed')
  need(report['manifests'][name]['strict_profile_comparison_available'],'bridge_strict_candidate_comparison_required')
  need(hashlib.sha256(masks[name]).hexdigest()==bound['manifests'][name]['bitmap_sha256'],'bridge_existing_candidate_bitmap_disagreement')
 report.update(target=bound['target'],source_metadata_sha256=expected,candidate_database_sha256=bound['candidate_database_sha256'],source_catalogue_sha256=bound['source_catalogue_sha256'],existing_candidate_identity_reverified=True,existing_candidate_bitmaps_unchanged=True,product_config_facts=product)
 return report
