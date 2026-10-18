import hashlib,struct,zlib,json,unittest
from pathlib import Path
from release_core import InvalidRelease,TargetSnapshot
from lookup3 import hashlittle2
from local_candidates import ObjectSpec,LocalRef,parse_v7,classify,verify_direct_bytes
from proof_history import import_receipt

def fixture(mode=b'Z',extra=0):
 data=b'future-fixture-payload'*8;block=mode+(zlib.compress(data) if mode==b'Z' else data);head=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+struct.pack('>II',len(block),len(data))+hashlib.md5(block).digest();raw=head+block;spec=ObjectSpec(hashlib.md5(data).hexdigest(),hashlib.md5(head).hexdigest(),len(data),len(raw));ref=LocalRef(bytes.fromhex(spec.ekey)[:9],3,700,len(raw)+extra,0);row=ref.prefix+((3<<30)|700).to_bytes(5,'big')+ref.span.to_bytes(4,'little');hdr=struct.pack('<HBBBBBBQ',7,0,0,4,5,9,30,0xffc0000000);a,b=hashlittle2(row);index=struct.pack('<II',16,hashlittle2(hdr)[0])+hdr+bytes(8)+struct.pack('<II',18,a)+row+bytes(6)
 return data,raw,spec,ref,index
class CandidateTests(unittest.TestCase):
 def test_native_v7(self):
  d,raw,s,r,i=fixture();refs,p=parse_v7(i,'0000000001.idx');self.assertEqual(refs,(r,));self.assertTrue(p['primary_checksum_verified']);self.assertFalse(p['content_verified'])
 def test_header_corruption(self):
  *_,i=fixture();i=bytearray(i);i[4]^=1
  with self.assertRaises(InvalidRelease):parse_v7(bytes(i),'0000000001.idx')
 def test_primary_corruption(self):
  *_,i=fixture();i=bytearray(i);i[44]^=1
  with self.assertRaises(InvalidRelease):parse_v7(bytes(i),'0000000001.idx')
 def test_nonzero_tail(self):
  *_,i=fixture()
  with self.assertRaises(InvalidRelease):parse_v7(i[:-1]+b'x','0000000001.idx')
 def test_wrong_bucket(self):
  *_,i=fixture()
  with self.assertRaises(InvalidRelease):parse_v7(i,'0100000001.idx')
 def test_unknown_v8(self):
  *_,i=fixture();i=bytearray(i);i[8]=8;i[4:8]=hashlittle2(i[8:24])[0].to_bytes(4,'little')
  with self.assertRaises(InvalidRelease):parse_v7(bytes(i),'0000000001.idx')
 def test_raw_size_bound(self):
  with self.assertRaises(InvalidRelease):parse_v7(b'x'*39,'0000000001.idx')
 def test_unsafe_member(self):
  *_,i=fixture()
  with self.assertRaises(InvalidRelease):parse_v7(i,'../0000000001.idx')
 def test_candidate_only(self):
  d,p,s,r,i=fixture();self.assertEqual(classify(r,s,10000),'direct_blte_candidate_NOT_proof')
 def test_header_policy_not_assumed(self):
  d,p,s,r,i=fixture(extra=30);self.assertIn('unqualified',classify(r,s,10000))
  with self.assertRaises(InvalidRelease):verify_direct_bytes(i,hashlib.sha256(i).hexdigest(),'0000000001.idx',r,10000,p,s)
 def test_bounds_unknown_not_damage(self):
  d,p,s,r,i=fixture();self.assertIn('UNKNOWN',classify(r,s,700))
 def test_wrong_prefix_unknown(self):
  d,p,s,r,i=fixture();r=LocalRef(bytes(9),3,700,len(p),0);self.assertEqual(classify(r,s,10000),'different_prefix_UNKNOWN')
 def test_full_in_memory_proof(self):
  d,p,s,r,i=fixture();proof=verify_direct_bytes(i,hashlib.sha256(i).hexdigest(),'0000000001.idx',r,10000,p,s);self.assertTrue(proof['full_ckey_verified']);self.assertTrue(proof['full_ekey_verified']);self.assertFalse(proof['reuse_authorized']);self.assertFalse(proof['fresh_disk_state_proven'])
 def test_raw_mode(self):
  d,p,s,r,i=fixture(b'N');self.assertTrue(verify_direct_bytes(i,hashlib.sha256(i).hexdigest(),'0000000001.idx',r,10000,p,s)['full_ckey_verified'])
 def test_wrong_index_digest(self):
  d,p,s,r,i=fixture()
  with self.assertRaises(InvalidRelease):verify_direct_bytes(i,'0'*64,'0000000001.idx',r,10000,p,s)
 def test_wrong_row(self):
  d,p,s,r,i=fixture();r=LocalRef(r.prefix,3,701,len(p),0)
  with self.assertRaises(InvalidRelease):verify_direct_bytes(i,hashlib.sha256(i).hexdigest(),'0000000001.idx',r,10000,p,s)
 def test_wrong_payload(self):
  d,p,s,r,i=fixture()
  with self.assertRaises(InvalidRelease):verify_direct_bytes(i,hashlib.sha256(i).hexdigest(),'0000000001.idx',r,10000,p[:-1]+bytes([p[-1]^1]),s)
 def test_budgets_not_unlimited(self):
  for ds,es in [(True,52),(64,True),(16*1024**2+1,52),(64,4*1024**2+1)]:
   with self.assertRaises(InvalidRelease):ObjectSpec('1'*32,'2'*32,ds,es)
 def test_span_overflow(self):
  with self.assertRaises(InvalidRelease):LocalRef(bytes(9),0,0,1<<32,0)
class HistoryTests(unittest.TestCase):
 def setUp(self):
  b=Path(__file__).parent/'reports';self.receipt=json.loads((b/'LOCAL-OBJECT-PROOF-user.json').read_bytes());self.scope=json.loads((b/'ONE-OBJECT-SCOPE.json').read_bytes());self.target=TargetSnapshot.restore(json.loads((b/'CATALOGUE-VERIFIED-to-share.json').read_bytes())['target']);s=self.scope;self.spec=ObjectSpec(s['ckey'].lower(),s['ekey'].lower(),s['decoded_size'],s['encoded_size'])
 def run_import(self):return import_receipt(json.dumps(self.receipt).encode(),self.target,self.spec,self.scope)
 def test_success_stays_historical(self):
  x=self.run_import();self.assertFalse(x['reuse_authorized']);self.assertFalse(x['current_disk_state_proven']);self.assertFalse(x['additional_read_authorized']);self.assertFalse(x['installation_ready']);self.assertFalse(x['report_is_cryptographically_signed'])
 def test_future_target_not_silently_accepted(self):
  t=self.target.public();t.update(version='20.0.0.90000',build_id=90000);self.target=TargetSnapshot.restore(t)
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_failed_report_rejected(self):
  self.receipt['status']='stopped_safely'
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_overscope_read_rejected(self):
  self.receipt['archive_bytes_read']=53
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_bool_not_integer(self):
  self.receipt['network_requests']=False
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_modified_game_rejected(self):
  self.receipt['game_modified']=True
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_claimed_installation_ready_rejected(self):
  self.receipt['installation_ready']=True
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_verification_missing(self):
  self.receipt['full_ckey_verified']=False
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_wrong_identity_rejected(self):
  self.receipt['ckey']='0'*32
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_download_claim_rejected(self):
  self.receipt['required_download_bytes']=0
  with self.assertRaises(InvalidRelease):self.run_import()
 def test_duplicate_json_rejected(self):
  with self.assertRaises(InvalidRelease):import_receipt(b'{"x":1,"x":2}',self.target,self.spec,self.scope)
class ExtraTests(unittest.TestCase):
 def test_duplicate_prefixes_allowed(self):
  d,p,s,r,i=fixture();row=i[40:58];a,b=0,0
  for _ in range(2):a,b=hashlittle2(row,a,b)
  dup=i[:32]+struct.pack('<II',36,a)+row+row+bytes(4);refs,proof=parse_v7(dup,'0000000001.idx');self.assertEqual(len(refs),2)
 def test_large_future_descriptor(self):
  data=b'future-not-64-bytes'*5000;block=b'Z'+zlib.compress(data);head=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+struct.pack('>II',len(block),len(data))+hashlib.md5(block).digest();raw=head+block
  spec=ObjectSpec(hashlib.md5(data).hexdigest(),hashlib.md5(head).hexdigest(),len(data),len(raw))
  from local_blte import verify_blte
  self.assertEqual(verify_blte(raw,spec.public())['decoded_bytes'],len(data))
 def test_empty_primary_profile(self):
  d,p,s,r,i=fixture();refs,proof=parse_v7(i[:32]+bytes(8),'0000000001.idx');self.assertEqual(refs,());self.assertFalse(proof['content_verified'])
 def test_non_dict_receipt(self):
  b=Path(__file__).parent/'reports';scope=json.loads((b/'ONE-OBJECT-SCOPE.json').read_bytes());target=TargetSnapshot.restore(json.loads((b/'CATALOGUE-VERIFIED-to-share.json').read_bytes())['target']);spec=ObjectSpec(scope['ckey'].lower(),scope['ekey'].lower(),scope['decoded_size'],scope['encoded_size'])
  with self.assertRaises(InvalidRelease):import_receipt(b'[]',target,spec,scope)
if __name__=='__main__':unittest.main()
