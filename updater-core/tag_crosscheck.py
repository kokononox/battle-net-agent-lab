"""Cross-manifest tag membership evidence, not Agent selection-policy proof.
Uses trusted identity-checked catalogue plus raw tags. No game/network I/O.
"""
from release_core import need


def check_install_download_tags(install_tags,install_entries,download_tags,links):
 it={(n,k):b for _,n,k,b in install_tags};dt={(n,k):b for _,n,k,b in download_tags}
 need(len(it)==len(install_tags)and len(dt)==len(download_tags)and set(it)==set(dt),'crosscheck_tag_schema_conflict')
 rows={i:(ck,size)for i,_,ck,size in install_entries};groups={}
 for i,(_,_,ck,size)in enumerate(install_entries):
  need(i in rows and rows[i]==(ck,size),'crosscheck_install_ordinals');groups.setdefault(ck,[]).append(i)
 by_ck={};seen=set()
 for index,ck,ek,di,decoded_size in links:
  need(type(index)is int and index in rows and rows[index]==(ck,decoded_size) and type(ek)is bytes and len(ek)==16 and type(di)is int and di>=0,'crosscheck_link_conflict');seen.add(index);by_ck.setdefault(ck,set()).add((ek,di))
 need(seen==set(rows),'crosscheck_install_mapping_missing');checks=0
 for ck,indices in groups.items():
  need(len(by_ck[ck])==1,'crosscheck_multiple_encoded_representations_need_policy')
  _,di=next(iter(by_ck[ck]))
  for key in it:
   need(all(i//8<len(it[key])for i in indices)and di//8<len(dt[key]),'crosscheck_bitmap_geometry')
   union=any(it[key][i//8]&(0x80>>(i%8))for i in indices);download=bool(dt[key][di//8]&(0x80>>(di%8)))
   need(union==download,'crosscheck_tag_union_disagreement');checks+=1
 return {'format':'install-download-tag-membership-crosscheck-1','install_variants_checked':len(rows),'unique_content_keys_checked':len(groups),'tag_definitions_checked':len(it),'membership_pairs_checked':checks,'install_ckey_group_union_matches_download':True,'independent_vendor_policy_oracle':False,'vendor_policy_qualified':False,'required_set_selected':False,'installation_ready':False,'apply_authorized':False}
