"""Bounded, filename-independent local cross-link prefix test; no I/O here."""
import hashlib,lookup3
MAX_PREFIX=65536

def blank():
 return dict(method='bounded_owned_file_prefix_crosslink_prediction',max_prefix_bytes=MAX_PREFIX,file_prefixes_checked=0,candidate_blocks_checked=0,matching_blocks=0,checksum_a_verified_matching_records=0,negative_control_blocks=0,prediction_bound_before_form_post=False,local_hostname_prediction_unchanged=False,host_related_container_marker_observed=False,raw_hostname_exported=False,identifier_digest_exported=False,game_payload_watermark_proven=False,account_identity_proven=False,unique_machine_identity_proven=False,unforgeable_origin_proven=False)
def validate(r):
 if type(r)is not dict or set(r)!=set(blank())or r['method']!=blank()['method']or r['max_prefix_bytes']!=MAX_PREFIX:raise ValueError('prefix_schema')
 for k,cap in [('file_prefixes_checked',2048),('candidate_blocks_checked',64),('matching_blocks',64),('checksum_a_verified_matching_records',1024),('negative_control_blocks',64)]:
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('prefix_count')
 for k in ('prediction_bound_before_form_post','local_hostname_prediction_unchanged','host_related_container_marker_observed'):
  if type(r[k])is not bool:raise ValueError('prefix_bool')
 for k in ('raw_hostname_exported','identifier_digest_exported','game_payload_watermark_proven','account_identity_proven','unique_machine_identity_proven','unforgeable_origin_proven'):
  if r[k]is not False:raise ValueError('prefix_fixed')
 if r['matching_blocks']>r['candidate_blocks_checked']or r['checksum_a_verified_matching_records']!=16*r['matching_blocks']:raise ValueError('prefix_relation')
 positive=r['matching_blocks']>0 and r['negative_control_blocks']==0
 if r['host_related_container_marker_observed']!=positive:raise ValueError('prefix_proof')
 if positive and(not r['prediction_bound_before_form_post']or not r['local_hostname_prediction_unchanged']or r['file_prefixes_checked']<1):raise ValueError('prefix_prerequisite')
 return r

def block_valid(raw,offset,seed):
 if offset<0 or offset+480>len(raw)or len(seed)!=7:return False
 seen=set();archive=None
 for i in range(16):
  h=raw[offset+i*30:offset+(i+1)*30];key=h[:16][::-1]
  if len(h)!=30 or int.from_bytes(h[16:20],'little')!=30 or h[20:22]!=b'\x01\x00'or key[0]>=16 or key[9:]!=bytes(7)or key[2:9]!=seed:return False
  if lookup3.hashlittle(h[:22],0x3D6BE971)!=int.from_bytes(h[22:26],'little'):return False
  if archive is None:archive=key[1]
  if archive!=key[1]or key[0]in seen:return False
  seen.add(key[0])
 return len(seen)==16

def scan(raw,seed,negative,r):
 if type(raw)is not bytes or len(raw)>MAX_PREFIX or len(seed)!=7 or len(negative)!=7 or seed==negative:raise ValueError('prefix_scope')
 if r['file_prefixes_checked']>=2048:raise ValueError('prefix_files')
 r['file_prefixes_checked']+=1
 for prediction,positive in ((seed,True),(negative,False)):
  start=0
  while True:
   at=raw.find(prediction[::-1],start)
   if at<0:break
   start=at+1;offset=at-7
   # Only the first record of each complete 16-record block can count.
   if offset<0 or offset+480>len(raw):continue
   if r['candidate_blocks_checked']>=64:raise ValueError('prefix_candidates')
   r['candidate_blocks_checked']+=1
   if block_valid(raw,offset,prediction):
    if positive:r['matching_blocks']+=1;r['checksum_a_verified_matching_records']+=16
    else:r['negative_control_blocks']+=1
 r['host_related_container_marker_observed']=r['matching_blocks']>0 and r['negative_control_blocks']==0
 return validate(r)
