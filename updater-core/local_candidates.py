"""Generic read-only V7 candidates and identity checks; no game I/O or writer.
Supported profile: primary continuous block, zero tail, native rolling lookup3.
9-byte prefix/size is a candidate, not proof of possession or required content.
"""
from dataclasses import dataclass,asdict
import hashlib,re,struct
from release_core import need,ck,sha
from lookup3 import hashlittle2
from local_blte import verify_blte
@dataclass(frozen=True)
class ObjectSpec:
 ckey:str
 ekey:str
 decoded_size:int
 encoded_size:int
 def __post_init__(self):
  ck(self.ckey);ck(self.ekey);need(type(self.decoded_size)is int and 0<self.decoded_size<=16*1024**2,'object_decoded_budget');need(type(self.encoded_size)is int and 9<=self.encoded_size<=4*1024**2,'object_encoded_budget')
 def public(self):return asdict(self)
@dataclass(frozen=True)
class LocalRef:
 prefix:bytes
 archive_id:int
 offset:int
 span:int
 ordinal:int
 def __post_init__(self):
  need(type(self.prefix)is bytes and len(self.prefix)==9,'reference_prefix')
  for k in ('archive_id','offset','span','ordinal'):need(type(getattr(self,k))is int and getattr(self,k)>=0,'reference_geometry')
  need(self.archive_id<1024 and self.offset<1<<30 and self.span<1<<32,'reference_bounds')
def parse_v7(raw,member):
 need(type(raw)is bytes and 40<=len(raw)<=4*1024**2 and type(member)is str and re.fullmatch('[0-9a-f]{10}\\.idx',member),'index_input_bounds');n,h=struct.unpack_from('<II',raw)
 need(n==16 and hashlittle2(raw[8:24])[0]==h,'index_header_checksum')
 v,b,f,sw,ow,kw,bits,maxoff=struct.unpack_from('<HBBBBBBQ',raw,8)
 need((v,b,f,sw,ow,kw,bits)==(7,int(member[:2],16),0,4,5,9,30) and b<16 and raw[24:32]==bytes(8),'unsupported_v7_profile');size,stored=struct.unpack_from('<II',raw,32)
 need(size%18==0 and size//18<=250000 and 40+size<=len(raw),'index_primary_bounds');a=b=0;refs=[];last=None
 for ordinal,pos in enumerate(range(40,40+size,18)):
  r=raw[pos:pos+18];a,b=hashlittle2(r,a,b);key=r[:9];need(last is None or last<=key,'index_key_order');last=key;packed=int.from_bytes(r[9:14],'big');refs.append(LocalRef(key,packed>>30,packed&((1<<30)-1),int.from_bytes(r[14:18],'little'),ordinal))
 need(a==stored,'index_primary_checksum');need(not any(raw[40+size:]),'nonzero_tail_requires_another_profile')
 return tuple(refs),{'member':member,'sha256':hashlib.sha256(raw).hexdigest(),'records':len(refs),'header_checksum_verified':True,'primary_checksum_verified':True,'zero_tail_verified':True,'max_offset_field_opaque':maxoff,'duplicate_prefixes_allowed_NOT_damage':True,'content_verified':False}
def classify(ref,spec,archive_bytes):
 need(type(ref)is LocalRef and type(spec)is ObjectSpec,'candidate_types');need(type(archive_bytes)is int and archive_bytes>=0,'archive_stat_size')
 if ref.prefix!=bytes.fromhex(spec.ekey)[:9]:return 'different_prefix_UNKNOWN'
 if ref.span==0 or ref.offset+ref.span>archive_bytes:return 'outside_observed_stat_bounds_UNKNOWN'
 if ref.span==spec.encoded_size:return 'direct_blte_candidate_NOT_proof'
 if ref.span==spec.encoded_size+30:return 'archive_header_policy_unqualified_NOT_proof'
 return 'size_not_compatible_UNKNOWN'
def verify_direct_bytes(index_raw,index_sha256,member,ref,archive_bytes,encoded,spec):
 """Pure check of caller-supplied copied bytes; caller must enforce live read scope.
 It does not claim held handles, fresh disk state, active generation or reuse authority.
 """
 sha(index_sha256);need(type(index_raw)is bytes and len(index_raw)<=4*1024**2 and hashlib.sha256(index_raw).hexdigest()==index_sha256,'index_copy_identity');need(type(member)is str and re.fullmatch('[0-9a-f]{10}\\.idx',member),'member_name')
 need(classify(ref,spec,archive_bytes)=='direct_blte_candidate_NOT_proof','not_a_qualified_direct_candidate');at=40+18*ref.ordinal;row=index_raw[at:at+18];packed=(ref.archive_id<<30)|ref.offset
 need(len(row)==18 and row==ref.prefix+packed.to_bytes(5,'big')+ref.span.to_bytes(4,'little'),'reference_copy_conflict');proof=verify_blte(encoded,spec.public())
 return dict(proof,provenance='caller_supplied_bytes_verified_in_memory',fresh_disk_state_proven=False,active_generation_proven=False,reuse_authorized=False,installation_ready=False)
