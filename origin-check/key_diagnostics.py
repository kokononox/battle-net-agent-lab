"""Independent shape conditions over first 16 verified 30-byte headers. No I/O."""
import lookup3
MAX_PREFIX=65536
COUNT_FIELDS=('bucket_lt16_records','archive_byte_matches_records','tail7_zero_records','first9_shape_records','strict_shape_records','only_bucket_condition_failed','only_archive_condition_failed','only_tail_condition_failed','multiple_conditions_failed','documented_hostname_slice_matches','negative_hostname_slice_matches','full_hostname_md5_suffix_matches','negative_full_md5_suffix_matches','blocks_common_middle7','blocks_distinct16_bucket_values','blocks_bucket_set_0_to15')
MATRIX_FIELDS=('zero_at_position_all16','constant_at_position_all16','bucket_set_at_position_0_to15','filename_archive_at_position_all16','filename_archive_plus1_at_position_all16','filename_archive_minus1_at_position_all16')
FIXED_FALSE=('raw_key_exported','raw_hostname_exported','identifier_hash_exported','marker_acceptance_rules_changed','hostname_marker_proven','account_identity_proven','unique_machine_identity_proven')
def orientation():
 r={k:0 for k in COUNT_FIELDS};r.update({k:[0]*16 for k in MATRIX_FIELDS});return r

def blank():
 r=dict(schema='casc-key-shape-diagnostics-1',scope='first16_checksum_a_verified_30byte_flag10_records_only',archives_examined=0,eligible_header_records=0,eligible_complete_first16_blocks=0,hash_matches_are_hints_not_origin_proof=True,reversed=orientation(),forward=orientation())
 r.update({k:False for k in FIXED_FALSE});return r

def validate(r):
 if type(r)is not dict or set(r)!=set(blank())or r['schema']!=blank()['schema']or r['scope']!=blank()['scope']or r['hash_matches_are_hints_not_origin_proof']is not True:raise ValueError('key_diagnostic_schema')
 for k,cap in [('archives_examined',64),('eligible_header_records',1024),('eligible_complete_first16_blocks',64)]:
  if type(r[k])is not int or not 0<=r[k]<=cap:raise ValueError('key_diagnostic_count')
 if r['eligible_header_records']>16*r['archives_examined']or r['eligible_complete_first16_blocks']*16>r['eligible_header_records']:raise ValueError('key_diagnostic_bounds')
 if any(r[k]is not False for k in FIXED_FALSE):raise ValueError('key_diagnostic_fixed')
 for name in ('reversed','forward'):
  o=r[name]
  if type(o)is not dict or set(o)!=set(orientation()):raise ValueError('key_diagnostic_orientation')
  for k in COUNT_FIELDS:
   cap=r['eligible_complete_first16_blocks']if k.startswith('blocks_')else r['eligible_header_records']
   if type(o[k])is not int or not 0<=o[k]<=cap:raise ValueError('key_diagnostic_count')
  if sum(o[k]for k in ('strict_shape_records','only_bucket_condition_failed','only_archive_condition_failed','only_tail_condition_failed','multiple_conditions_failed'))!=r['eligible_header_records']:raise ValueError('key_diagnostic_partition')
  if o['strict_shape_records']>o['first9_shape_records']or o['first9_shape_records']>min(o['bucket_lt16_records'],o['archive_byte_matches_records']):raise ValueError('key_diagnostic_relation')
  for k in MATRIX_FIELDS:
   if type(o[k])is not list or len(o[k])!=16 or any(type(v)is not int or not 0<=v<=r['eligible_complete_first16_blocks']for v in o[k]):raise ValueError('key_diagnostic_matrix')
 return r

def eligible(h):return len(h)==30 and int.from_bytes(h[16:20],'little')==30 and h[20:22]==b'\x01\x00'and lookup3.hashlittle(h[:22],0x3D6BE971)==int.from_bytes(h[22:26],'little')
def observe(raw,archive,current_digest,negative_digest,r):
 if type(raw)is not bytes or len(raw)>MAX_PREFIX or type(archive)is not int or not 0<=archive<=255 or type(current_digest)is not bytes or type(negative_digest)is not bytes or len(current_digest)!=16 or len(negative_digest)!=16 or current_digest==negative_digest:raise ValueError('key_diagnostic_scope')
 if r['archives_examined']>=64:raise ValueError('key_diagnostic_archive_limit')
 r['archives_examined']+=1
 headers=[raw[i*30:(i+1)*30]for i in range(16)];selected=[h for h in headers if eligible(h)];r['eligible_header_records']+=len(selected)
 complete=len(selected)==16
 r['eligible_complete_first16_blocks']+=complete
 for name,reverse in (('reversed',True),('forward',False)):
  o=r[name];keys=[h[:16][::-1]if reverse else h[:16]for h in selected]
  for key in keys:
   bucket=key[0]<16;index=key[1]==archive;tail=key[9:]==bytes(7)
   o['bucket_lt16_records']+=bucket;o['archive_byte_matches_records']+=index;o['tail7_zero_records']+=tail;o['first9_shape_records']+=bucket and index
   failed=[not bucket,not index,not tail];count=sum(failed)
   label='strict_shape_records'if count==0 else'multiple_conditions_failed'if count>1 else('only_bucket_condition_failed','only_archive_condition_failed','only_tail_condition_failed')[failed.index(True)]
   o[label]+=1
   o['documented_hostname_slice_matches']+=key[2:9]==current_digest[2:9];o['negative_hostname_slice_matches']+=key[2:9]==negative_digest[2:9]
   o['full_hostname_md5_suffix_matches']+=key[2:]==current_digest[2:];o['negative_full_md5_suffix_matches']+=key[2:]==negative_digest[2:]
  if complete:
   o['blocks_common_middle7']+=len({k[2:9]for k in keys})==1
   o['blocks_distinct16_bucket_values']+=len({k[0]for k in keys})==16
   o['blocks_bucket_set_0_to15']+={k[0]for k in keys}==set(range(16))
   for pos in range(16):
    values={k[pos]for k in keys}
    o['zero_at_position_all16'][pos]+=values=={0};o['constant_at_position_all16'][pos]+=len(values)==1;o['bucket_set_at_position_0_to15'][pos]+=values==set(range(16))
    o['filename_archive_at_position_all16'][pos]+=values=={archive};o['filename_archive_plus1_at_position_all16'][pos]+=values=={(archive+1)%256};o['filename_archive_minus1_at_position_all16'][pos]+=values=={(archive-1)%256}
 return validate(r)
