"""Finite counters over already-read archive prefixes. No I/O, raw export or relaxed proof."""
import lookup3
MAX_PREFIX=65536
COUNTS=('archives_examined','prefixes_shorter_than_header','prefixes_begin_blte','prefixes_first480_all_zero','records_walked','record_span_30','record_span_larger_than30','flags_1_0','flags_0_0','flags_other','checksum_a_seeded_valid','checksum_a_seeded_not_verified','checksum_a_zero_seed_valid','record_payload_starts_blte','size_big_endian_only_plausible','reversed_key_shape_records','forward_key_shape_records','hostname_hint_candidate_records','hostname_hint_matches','negative_control_hint_matches','first16_coherent_reversed_ignoring_flags','first16_coherent_forward_ignoring_flags','first16_reversed_duplicate_bucket_indices','stopped_invalid_record_span','stopped_record_extends_prefix','stopped_not_enough_header','stopped_record_count_limit')
FLAGS=('raw_fields_exported','identifier_hash_exported','raw_hostname_exported','checksum_b_checked','marker_acceptance_rules_changed','account_identity_proven','unique_machine_identity_proven','game_payload_watermark_proven')
def blank():
 r=dict(schema='casc-prefix-format-diagnostics-1',scope='already_read_bounded_prefixes_only',max_walk_records_per_archive=64,hints_are_not_marker_proof=True)
 r.update({k:0 for k in COUNTS});r.update({k:False for k in FLAGS});return r

def validate(r):
 if type(r)is not dict or set(r)!=set(blank())or r['schema']!=blank()['schema']or r['scope']!=blank()['scope']or type(r['max_walk_records_per_archive'])is not int or r['max_walk_records_per_archive']!=64 or r['hints_are_not_marker_proof']is not True:raise ValueError('diagnostic_schema')
 for k in COUNTS:
  cap=64 if k.startswith(('archives_','prefixes_','first16_','stopped_'))else 4096
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('diagnostic_count')
 if any(r[k]is not False for k in FLAGS):raise ValueError('diagnostic_fixed')
 n=r['records_walked']
 if r['flags_1_0']+r['flags_0_0']+r['flags_other']!=n or r['checksum_a_seeded_valid']+r['checksum_a_seeded_not_verified']!=n or r['record_span_30']+r['record_span_larger_than30']!=n:raise ValueError('diagnostic_partition')
 if r['hostname_hint_matches']>r['hostname_hint_candidate_records']or r['negative_control_hint_matches']>r['hostname_hint_candidate_records']or r['hostname_hint_candidate_records']>r['checksum_a_seeded_valid']:raise ValueError('diagnostic_hint')
 if n>64*r['archives_examined']:raise ValueError('diagnostic_limit')
 return r

def shape(key,archive):return len(key)==16 and key[0]<16 and key[1]==archive and key[9:]==bytes(7)
def checksum_ok(h,seed=0x3D6BE971):return len(h)==30 and lookup3.hashlittle(h[:22],seed)==int.from_bytes(h[22:26],'little')
def coherent(raw,archive,reverse,distinct=True):
 if len(raw)<480:return False
 seen=set();seeds=set()
 for i in range(16):
  h=raw[i*30:(i+1)*30];key=h[:16][::-1]if reverse else h[:16]
  if int.from_bytes(h[16:20],'little')!=30 or not checksum_ok(h)or not shape(key,archive):return False
  seen.add(key[0]);seeds.add(key[2:9])
 return len(seeds)==1 and(len(seen)==16 if distinct else len(seen)<16)

def observe(raw,archive,local_prediction,negative_prediction,r):
 if type(raw)is not bytes or len(raw)>MAX_PREFIX or type(archive)is not int or not 0<=archive<=255 or type(local_prediction)is not bytes or type(negative_prediction)is not bytes or len(local_prediction)!=7 or len(negative_prediction)!=7 or local_prediction==negative_prediction:raise ValueError('diagnostic_scope')
 if r['archives_examined']>=64:raise ValueError('diagnostic_archive_limit')
 r['archives_examined']+=1
 r['prefixes_shorter_than_header']+=len(raw)<30;r['prefixes_begin_blte']+=raw.startswith(b'BLTE');r['prefixes_first480_all_zero']+=len(raw)>=480 and raw[:480]==bytes(480)
 r['first16_coherent_reversed_ignoring_flags']+=coherent(raw,archive,True)
 r['first16_coherent_forward_ignoring_flags']+=coherent(raw,archive,False)
 r['first16_reversed_duplicate_bucket_indices']+=coherent(raw,archive,True,False)
 offset=0
 for _ in range(64):
  if offset+30>len(raw):r['stopped_not_enough_header']+=1;break
  h=raw[offset:offset+30];span=int.from_bytes(h[16:20],'little');big=int.from_bytes(h[16:20],'big')
  if not 30<=span<=len(raw)-offset and 30<=big<=len(raw)-offset:r['size_big_endian_only_plausible']+=1
  if span<30:r['stopped_invalid_record_span']+=1;break
  r['records_walked']+=1;r['record_span_30'if span==30 else'record_span_larger_than30']+=1
  flags=h[20:22];r['flags_1_0'if flags==b'\x01\x00'else'flags_0_0'if flags==bytes(2)else'flags_other']+=1
  valid=checksum_ok(h);r['checksum_a_seeded_valid'if valid else'checksum_a_seeded_not_verified']+=1;r['checksum_a_zero_seed_valid']+=checksum_ok(h,0)
  reverse=h[:16][::-1];forward=h[:16];r['reversed_key_shape_records']+=span==30 and shape(reverse,archive);r['forward_key_shape_records']+=span==30 and shape(forward,archive)
  if span==30 and valid and shape(reverse,archive):
   r['hostname_hint_candidate_records']+=1;r['hostname_hint_matches']+=reverse[2:9]==local_prediction;r['negative_control_hint_matches']+=reverse[2:9]==negative_prediction
  r['record_payload_starts_blte']+=raw[offset+30:offset+34]==b'BLTE'
  if span>len(raw)-offset:r['stopped_record_extends_prefix']+=1;break
  offset+=span
 else:r['stopped_record_count_limit']+=1
 return validate(r)
