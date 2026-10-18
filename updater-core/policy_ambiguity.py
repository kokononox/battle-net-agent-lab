"""Offline questions for independent selection evidence, NOT selection policy.
Consumes copied manifest records only. No IO/network in this module. Candidate
membership is an input, not a verdict. No variant is picked, no tag is excluded.
"""
import hashlib
from release_core import need
from selection_policy import tag_table
from required_set import selected_indices
SAMPLE_LIMIT=2
VARIANT_GROUP_LIMIT=16
VARIANT_ROW_LIMIT=8

def first_indices(value,count,limit=SAMPLE_LIMIT):
 # Highest set bit is the earliest manifest ordinal; ignore padded tail bits.
 out=[];width=(count+7)//8;tail=width*8-count
 value&=((1<<count)-1)<<tail
 while value and len(out)<limit:
  i=width*8-value.bit_length();out.append(i);value^=1<<(width*8-1-i)
 return out

def audit_membership(tags,count,candidate):
 table=tag_table(tags,count);width=(count+7)//8;need(type(candidate)is bytes and len(candidate)==width,'audit_candidate_geometry');full=((1<<count)-1)<<(width*8-count);chosen=int.from_bytes(candidate,'big');need(chosen&~full==0,'audit_candidate_padding')
 partitions=[]
 for name,(kind,bits)in sorted(table.items()):
  if kind!=16384:continue
  feature=int.from_bytes(bits,'big')&full;cells=[]
  for selected in (False,True):
   for tagged in (False,True):
    value=(chosen if selected else full^chosen)&(feature if tagged else full^feature)
    cells.append({'candidate_selected':selected,'tag_member':tagged,'records':value.bit_count(),'sample_indices':first_indices(value,count)})
  need(sum(c['records']for c in cells)==count,'audit_partition_crossfoot');partitions.append({'tag':name,'kind':kind,'meaning_and_preference_qualified':False,'cells':cells})
 unassigned=[]
 for kind in range(1,6):
  union=0
  for k,bits in table.values():
   if k==kind:union|=int.from_bytes(bits,'big')
  value=full&~union;unassigned.append({'kind':kind,'records_without_any_tag_of_kind':value.bit_count(),'candidate_selected_without_any_tag_of_kind':(value&chosen).bit_count(),'sample_indices':first_indices(value,count),'untagged_semantics_qualified':False})
 return {'manifest_records':count,'candidate_records':chosen.bit_count(),'candidate_bitmap_sha256':hashlib.sha256(candidate).hexdigest(),'feature_partitions':partitions,'unassigned_dimensions':unassigned,'sample_policy':'earliest two manifest ordinals per nonempty cell; deterministic NOT statistical or completeness proof','required_set_selected':False,'vendor_selection_policy_qualified':False,'promotion_to_required_set_permitted':False,'required_network_download_bytes':None,'installation_ready':False,'apply_authorized':False}

def audit_install_variants(entries,candidate):
 need(type(entries)in(list,tuple)and 0<len(entries)<=1000000,'audit_install_count');need(type(candidate)is bytes and len(candidate)==(len(entries)+7)//8,'audit_candidate_geometry');tail=len(candidate)*8-len(entries);need(not tail or candidate[-1]&((1<<tail)-1)==0,'audit_candidate_padding');selected=set(selected_indices(candidate,len(entries)));groups={}
 for i,row in enumerate(entries):
  need(type(row)in(list,tuple)and len(row)==4 and type(row[0])is int and row[0]==i,'audit_install_order');ordinal,label,ckey,size=row
  need(type(label)is str and 0<len(label)<=4096 and all(ord(c)>=32 and ord(c)!=127 for c in label)and type(ckey)is bytes and len(ckey)==16 and any(ckey)and type(size)is int and size>=0,'audit_install_record')
  # Opaque manifest metadata only: this normalization is NOT a host pathname.
  folded=label.replace('\\','/').casefold();groups.setdefault(folded,[]).append((ordinal,label,ckey,size))
 conflicts=[(name,rows)for name,rows in sorted(groups.items())if len(rows)>1];questions=[]
 for name,rows in conflicts[:VARIANT_GROUP_LIMIT]:
  questions.append({'manifest_label_folded':name,'total_records':len(rows),'distinct_content_identities':len({(key,size)for i,label,key,size in rows}),'candidate_selected_records':sum(i in selected for i,label,key,size in rows),'records':[{'record_index':i,'manifest_label':label,'ckey':key.hex(),'decoded_size':size,'candidate_selected':i in selected}for i,label,key,size in rows[:VARIANT_ROW_LIMIT]],'omitted_records':max(0,len(rows)-VARIANT_ROW_LIMIT),'chosen_variant':None})
 return {'duplicate_manifest_label_groups':len(conflicts),'groups':questions,'omitted_groups':max(0,len(conflicts)-VARIANT_GROUP_LIMIT),'normalization':'opaque manifest labels; slash fold and Unicode casefold only; NOT Windows path safety or final collision qualification','all_collisions_resolved':False,'variant_choice_policy_qualified':False}
