"""Selection hypothesis discrimination, NOT a vendor policy or required set.
Typed profile inputs only; never parse an Agent query using candidate DNF syntax.
No IO, fallback, feature preference inference or independent-reference claim.
"""
import hashlib
from release_core import need

def _summary(value,count):
 width=(count+7)//8;full=((1<<count)-1)<<(width*8-count);value&=full
 # Earliest ordinals, bounded output. Not a representative statistical sample.
 samples=[];v=value
 while v and len(samples)<2:
  index=width*8-v.bit_length();samples.append(index);v^=1<<(width*8-1-index)
 return {'records':value.bit_count(),'bitmap_sha256':hashlib.sha256(value.to_bytes(width,'big')).hexdigest(),'earliest_ordinals':samples}

def discriminate(tags,count,profile,candidate):
 from selection_policy import tag_table,compile_profile
 from required_set import select_bitmap
 table=tag_table(tags,count);expression,p=compile_profile(profile,table)
 expected,_=select_bitmap(tags,count,expression)
 need(type(candidate)is bytes and candidate==expected,'semantic_candidate_disagreement')
 width=(count+7)//8;full=((1<<count)-1)<<(width*8-count);paired=int.from_bytes(candidate,'big')
 groups=[[p['platform']],[p['architecture']],[p['region']],p['text_locales']+p['speech_locales']]
 categories=[n for n,k in [('text','text_locales'),('speech','speech_locales')]if p[k]];groups.append(categories)
 grouped=full
 for names in groups:
  union=0
  for name in names:union|=int.from_bytes(table[name][1],'big')
  grouped&=union
 need(paired&~grouped==0,'semantic_grouped_not_superset')
 # 0x4000 names are opaque alternatives, not Boolean user preferences.
 special_union=0
 for kind,bits in table.values():
  if kind==16384:special_union|=int.from_bytes(bits,'big')
 special_union&=full;hypotheses=[]
 for name,(kind,bits)in sorted(table.items()):
  if kind!=16384:continue
  member=int.from_bytes(bits,'big')&full
  hypotheses.append({'tag':name,'kind':kind,'hypothetical_explicit_choice_NOT_actual_preference':True,
   'strict_membership':_summary(grouped&member,count),
   'member_or_untagged_in_kind':_summary(grouped&(member|(full^special_union)),count),
   'exclude_this_tag':_summary(grouped&(full^member),count),
   'choice_qualified':False})
 return {'format':'selection-semantic-discrimination-1','candidate_dnf_grammar_is_agent_query_grammar':False,
  'profile_locale_category_pairing_preserved_in_existing_candidate':True,
  'grouped_model':'OR_within_numeric_kind_AND_between_requested_kinds_no_special_filter',
  'paired_candidate':_summary(paired,count),'grouped_hypothesis':_summary(grouped,count),
  'grouped_only':_summary(grouped&~paired,count),'paired_only':_summary(paired&~grouped,count),
  'grouping_hypotheses_agree_for_this_input':paired==grouped,
  'agreement_qualifies_vendor_policy':False,'hypotheses_exhaustive':False,
  'hypothesis_intersection_is_required_set':False,'hypothesis_union_is_required_set':False,
  'opaque_kind_16384_hypotheses':hypotheses,'unknown_tags_select_all_permitted':False,
  'candidate_bitmap_modified':False,'independent_reference_available':False,
  'feature_selection_semantics_qualified':False,'dependency_and_variant_policy_qualified':False,
  'patch_route_policy_qualified':False,'vendor_selection_policy_qualified':False,
  'required_set_selected':False,'promotion_to_required_set_permitted':False,
  'required_network_download_bytes':None,'game_access':False,'network_requests':0,
  'installation_ready':False,'apply_authorized':False}
