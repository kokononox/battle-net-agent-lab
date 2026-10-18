"""Lossless public clause/profile facts from two owned metadata byte copies.
No token-union across clauses, raw private tags, live claims or file selection.
"""
import hashlib,re
from installed_identity import validate,select_active,LOCALES,InvalidMetadata
from release_core import need
from selection_policy import normalize_profile
TOKEN=re.compile(r'([A-Za-z0-9_-]{1,64})(\?)?\Z')
PRIVATE=re.compile(r'(?:acct|geoip)-[A-Za-z0-9_]{1,32}\Z')

def inspect_preferences(info,config):
 # Existing strict config-MD5 / retail identity gate is retained.
 baseline=validate(info,config);row=select_active(info);clauses=row['tags'].split(':')
 need(1<=len(clauses)<=16,'preferences_clause_budget');public=[];private=0;identities=[];locales={'text':set(),'speech':set()}
 for clause in clauses:
  groups={'platform':[],'architecture':[],'region':[],'locale':[],'category':[]};seen=set();terms=[]
  tokens=clause.split();need(1<=len(tokens)<=64,'preferences_token_budget')
  for token in tokens:
   match=TOKEN.fullmatch(token);need(match is not None,'preferences_token_syntax');name,optional=match[1],bool(match[2])
   if PRIVATE.fullmatch(name):need(optional,'preferences_private_must_be_optional');private+=1;continue
   need(name not in seen,'preferences_duplicate_public_token');seen.add(name)
   if name=='Windows':kind='platform'
   elif name in ('x86_32','x86_64','ARM64'):kind='architecture'
   elif name in ('EU','US','KR','TW','CN'):kind='region'
   elif name in LOCALES:kind='locale'
   elif name in ('text','speech'):kind='category'
   else:need(False,'preferences_unqualified_token')
   groups[kind].append((name,optional));terms.append({'name':name,'kind':kind,'optional':optional})
  need(all(len(v)==1 for v in groups.values()),'preferences_clause_dimensions')
  need(not groups['platform'][0][1]and not groups['architecture'][0][1]and not groups['locale'][0][1],'preferences_optional_core_dimension')
  platform,architecture,region=(groups[n][0][0]for n in ('platform','architecture','region'));category=groups['category'][0][0];locale=groups['locale'][0][0]
  identities.append((platform,architecture,region));locales[category].add(locale);public.append(terms)
 need(len(set(identities))==1,'preferences_clause_scope_disagreement')
 # Preserve ARM64 in observed terms; normalize using explicit compatibility map.
 platform,architecture,region=identities[0];canonical_arch={'ARM64':'arm64'}.get(architecture,architecture)
 p=normalize_profile({'platform':platform,'architecture':canonical_arch,'region':region,'text_locales':sorted(locales['text']),'speech_locales':sorted(locales['speech'])})
 # Re-expanding the typed profile must reproduce EXACT locale/category pairs.
 observed={(next(t['name']for t in c if t['kind']=='locale'),next(t['name']for t in c if t['kind']=='category'))for c in public}
 reconstructed={(loc,cat)for cat,key in (('text','text_locales'),('speech','speech_locales'))for loc in p[key]}
 need(observed==reconstructed,'preferences_pairing_not_representable')
 return {'format':'installed-preference-clause-facts-1','baseline':baseline,'profile':p,'public_clauses':public,'private_optional_qualifiers_withheld':private,'raw_tags_or_private_qualifiers_exported':False,'clause_pairing_preserved':True,'optional_markers_preserved':True,'architecture_normalization_applied':architecture!=canonical_arch,'profile_origin':'metadata_tags_NOT_current_launcher_UI','source':'owned_metadata_bytes','metadata_content_identity_verified':True,'live_installation_state_revalidated':False,'fresh_installed_preferences_proven':False,'feature_preferences_proven':False,'vendor_query_semantics_qualified':False,'active_generation_proven':False,'required_set_selected':False,'required_network_download_bytes':None,'game_access':False,'network_requests':0,'installation_ready':False,'apply_authorized':False}

def review_target_preferences(info,config,target,versions_raw,product_config_raw):
 from product_policy_facts import inspect_product_config
 facts=inspect_preferences(info,config)
 product=inspect_product_config(target,versions_raw,product_config_raw,facts['profile'])
 facts['target_product_config_facts']=product
 facts['canonical_locale_replan_review_required']=any(product['canonical_locale_facts'][k]!=facts['profile'][k]for k in ('text_locales','speech_locales'))
 return facts
