import copy,hashlib,io,json,os,struct,tempfile,threading,unittest,zlib
from pathlib import Path
from unittest.mock import patch
import poststop_content as p
import lookup3
class Offline(unittest.TestCase):
 def setUp(self):
  self.data=b'synthetic content, never live evidence';self.encoded=b'BLTE'+bytes(4)+b'Z'+zlib.compress(self.data)
  self.spec=dict(ckey=hashlib.md5(self.data).hexdigest(),ekey=hashlib.md5(self.encoded).hexdigest(),decoded=len(self.data),encoded=len(self.encoded))
 def audit(self):
  r=p.blank('a'*40,'1');r.update(job_drained_verified=True,owned_empty_baseline_verified=True,build_reference_matched=True);return p.Audit(r)
 def test_exact_decoded_manifest(self):
  with tempfile.TemporaryDirectory()as t,patch.object(p,'MANIFESTS',{k:self.spec for k in p.MANIFESTS}),patch.object(p,'save',side_effect=p.validate):
   f=Path(t)/'untrusted-name';f.write_bytes(self.data);a=self.audit();a.scan(Path(t));self.assertTrue(a.r['objects']['encoding']);self.assertFalse(a.r['official_component_materialized']);self.assertFalse(a.r['same_file_socket_delivery_proven'])
 def test_encoded_requires_full_integrity(self):
  with tempfile.TemporaryDirectory()as t,patch.object(p,'MANIFESTS',{k:self.spec for k in p.MANIFESTS}),patch.object(p,'save',side_effect=p.validate):
   f=Path(t)/'cache';f.write_bytes(self.encoded);a=self.audit();a.encoded(f,0,'encoding');self.assertTrue(a.r['objects']['encoding']);self.assertEqual(a.r['bytes_read'],len(self.encoded))
 def test_tampered_encoded_no_proof(self):
  with tempfile.TemporaryDirectory()as t,patch.object(p,'MANIFESTS',{k:self.spec for k in p.MANIFESTS}),patch.object(p,'save',side_effect=p.validate):
   f=Path(t)/'cache';f.write_bytes(self.encoded[:-1]+bytes([self.encoded[-1]^1]));a=self.audit();a.encoded(f,0,'encoding');self.assertFalse(any(a.r['objects'].values()))
 def index(self,span,key=None,offset=50):
  key=bytes.fromhex(self.spec['ekey'])if key is None else key
  entry=key[:9]+offset.to_bytes(5,'big')+span.to_bytes(4,'little');h=struct.pack('<HBBBBBBQ',7,0,0,4,5,9,30,0x4000000000);hi,lo=lookup3.hashlittle2(entry)
  return struct.pack('<II',16,lookup3.hashlittle(h))+h+bytes(8)+struct.pack('<II',18,hi)+entry
 def test_index_archive_plus30_offset_verified(self):
  with tempfile.TemporaryDirectory()as t,patch.object(p,'MANIFESTS',{k:self.spec for k in p.MANIFESTS}),patch.object(p,'save',side_effect=p.validate):
   folder=Path(t)/'Data/data';folder.mkdir(parents=True);(folder/'0000000001.idx').write_bytes(self.index(len(self.encoded)+30));(folder/'data.000').write_bytes(bytes(80)+self.encoded+bytes(20));a=self.audit();a.scan(Path(t));self.assertTrue(a.r['objects']['encoding']);self.assertEqual(a.r['index_checksums_verified'],1);self.assertEqual(a.r['prefix_candidates'],3)
 def test_index_prefix_not_proof(self):
  with tempfile.TemporaryDirectory()as t,patch.object(p,'MANIFESTS',{k:self.spec for k in p.MANIFESTS}),patch.object(p,'save',side_effect=p.validate):
   folder=Path(t);(folder/'0000000001.idx').write_bytes(self.index(len(self.encoded)+30));(folder/'data.000').write_bytes(bytes(80)+self.encoded[:-1]+b'x'+bytes(20));a=self.audit();a.scan(folder);self.assertFalse(a.r['official_metadata_materialized']);self.assertEqual(a.r['index_checksums_verified'],1)
 def test_bad_index_checksum_rejected(self):
  with tempfile.TemporaryDirectory()as t,patch.object(p,'MANIFESTS',{k:self.spec for k in p.MANIFESTS}),patch.object(p,'save',side_effect=p.validate):
   folder=Path(t);raw=bytearray(self.index(len(self.encoded)+30));raw[36]^=1;(folder/'0000000001.idx').write_bytes(raw);(folder/'data.000').write_bytes(bytes(80)+self.encoded+bytes(20));a=self.audit();a.scan(folder);self.assertFalse(a.r['official_metadata_materialized']);self.assertEqual(a.r['index_checksums_verified'],0)
 def test_symlink_refused(self):
  with tempfile.TemporaryDirectory()as t:
   folder=Path(t);(folder/'link').symlink_to(folder,target_is_directory=True)
   with self.assertRaises(p.core.RepairError):self.audit().scan(folder)
 def test_hardlink_refused(self):
  with tempfile.TemporaryDirectory()as t:
   f=Path(t)/'a';f.write_bytes(b'x');os.link(f,Path(t)/'b')
   with self.assertRaises(p.core.RepairError):self.audit().scan(Path(t))
 def test_read_bound(self):
  a=self.audit();a.r['bytes_read']=p.MAX_READ
  with self.assertRaises(p.Bounded):p.Reader(io.BytesIO(b'x'),a).read(1)
  self.assertTrue(a.r['read_limit_reached'])
 def test_entry_bound(self):
  with tempfile.TemporaryDirectory()as t:
   (Path(t)/'a').write_bytes(b'x');a=self.audit();a.r['entries']=p.MAX_ENTRIES
   with self.assertRaises(p.Bounded):a.scan(Path(t))
   self.assertTrue(a.r['entry_limit_reached'])
 def test_time_bound(self):
  a=self.audit();a.deadline=0
  with self.assertRaises(p.Bounded):a.check()
 def test_public_schema_no_paths(self):
  r=p.blank('a'*40,'1');r['path']='private'
  with self.assertRaises(ValueError):p.validate(r)
 def test_proof_requires_job_drain(self):
  r=p.blank('a'*40,'1');r['objects']['encoding']=True;r['official_metadata_materialized']=True
  with self.assertRaises(ValueError):p.validate(r)
 def test_driver_invokes_after_drain(self):
  s=Path(p.__file__).with_name('guard_driver.py').read_text();self.assertLess(s.index("r['observation']=g.receipt"),s.index("str(HERE/'poststop_content.py')"));self.assertIn("if not o['job_drained'] or o['final_active_processes']!=0",s);self.assertIn('timeout=25',s)
 def test_ownership_bind_refuses_nonempty(self):
  with tempfile.TemporaryDirectory()as t,patch.dict(os.environ,{'RETAIL_POSTSTOP_CONTENT':'owned-offline-t11'}):
   (Path(t)/'a').write_bytes(b'x')
   with self.assertRaises(ValueError):p.bind(Path(t),p.cp.reference(),'a'*40,'1')
class Ownership(unittest.TestCase):
 def fixture(self,target):
  from test_t9_budget import Budget
  o=Budget().expanded();ref=p.cp.reference();s=target.stat()
  owner=dict(source_commit='a'*40,run_id='1',device=s.st_dev,inode=s.st_ino,empty=True,build_config=ref['build_config'],version=ref['version'])
  return o,owner
 def test_current_drained_owner_accepted(self):
  with tempfile.TemporaryDirectory()as t:
   target=Path(t);o,owner=self.fixture(target);self.assertEqual(p.prerequisites(o,owner,target,'a'*40,'1'),target)
 def test_alive_stale_wrong_owner_and_build_refused(self):
  changes=[('observation','job_drained',False),('observation','final_active_processes',1),('owner','run_id','2'),('owner','inode',-1),('owner','empty',False),('owner','version','wrong')]
  with tempfile.TemporaryDirectory()as t:
   for location,key,value in changes:
    target=Path(t);o,owner=self.fixture(target);(o if location=='observation'else owner)[key]=value
    with self.assertRaises((ValueError,p.core.RepairError)):p.prerequisites(o,owner,target,'a'*40,'1')
 def test_references_match_public_budget_audit(self):
  audit=json.loads((Path(p.__file__).resolve().parents[2]/'reports/prelogin-public-manifest-budget.json').read_text())
  for label,spec in p.MANIFESTS.items():
   m=audit['manifests'][label];self.assertEqual((spec['ckey'],spec['ekey'],spec['decoded'],spec['encoded']),(m['content_key'],m['encoding_key'],m['decoded_bytes'],m['encoded_bytes']))
class Markers(unittest.TestCase):
 def audit(self):
  r=p.blank('a'*40,'1');r.update(job_drained_verified=True,owned_empty_baseline_verified=True,build_reference_matched=True);return p.Audit(r)
 def prefix(self,host='synthetic-download-host',archive=0,seed=None):
  seed=hashlib.md5(host.encode()+b'data/data').digest()[2:9]if seed is None else seed
  records=[]
  for i in range(16):
   key=bytes([i,archive])+seed+bytes(7);head=key[::-1]+(30).to_bytes(4,'little')+b'\x01\x00';records.append(head+lookup3.hashlittle(head,0x3D6BE971).to_bytes(4,'little')+bytes(4))
  return b''.join(records)
 def check(self,raw,host='synthetic-download-host',seed=None):
  with tempfile.TemporaryDirectory()as t,patch.object(p.socket,'gethostname',return_value=host),patch.object(p,'save',side_effect=p.validate):
   f=Path(t)/'data.000';f.write_bytes(raw);a=self.audit();a.crosslinks([(f,len(raw))],seed or p.host_seed().hex());return a.r
 def test_all16_predicted_with_checksum_a(self):
  r=self.check(self.prefix());m=r['host_marker'];self.assertTrue(m['host_related_container_marker_observed']);self.assertEqual(m['prediction_matches'],16);self.assertEqual(m['negative_control_matches'],0);self.assertFalse(m['game_payload_watermark_proven']);self.assertFalse(r['official_component_materialized'])
 def test_different_hostname_is_not_a_match(self):
  r=self.check(self.prefix(host='other-host'));self.assertFalse(r['host_marker']['host_related_container_marker_observed']);self.assertEqual(r['host_marker']['prediction_matches'],0)
 def test_changed_header_checksums_rejected(self):
  raw=bytearray(self.prefix());raw[22]^=1;r=self.check(bytes(raw));self.assertFalse(r['host_marker']['host_related_container_marker_observed']);self.assertEqual(r['host_marker']['checksum_a_verified_records'],15)
 def test_duplicate_indices_not16proof(self):
  raw=self.prefix();r=self.check(raw[:30]*16);self.assertFalse(r['host_marker']['host_related_container_marker_observed'])
 def test_before_after_hostname_must_match(self):
  with self.assertRaises(ValueError):self.check(self.prefix(),seed='11'*7)
 def test_copy_of_prefix_preserves_marker(self):
  original=self.prefix();copy=bytes(bytearray(original));self.assertTrue(self.check(copy)['host_marker']['host_related_container_marker_observed'])
 def test_changing_hostname_seed_changes_expected_prefix(self):
  a=self.prefix('host-a');b=self.prefix('host-b');self.assertNotEqual(a,b);self.assertTrue(self.check(a,'host-a')['host_marker']['host_related_container_marker_observed']);self.assertFalse(self.check(a,'host-b')['host_marker']['host_related_container_marker_observed'])
 def test_legacy_t11_receipt_supported(self):
  r=p.blank('a'*40,'1');r['schema']='bnet-retail-poststop-content-1';del r['host_marker'];del r['index_layout_states'];del r['prefix_marker'];p.validate(r)
 def test_no_private_seed_or_hostname_fields(self):
  for key in ('hostname','seed','hash'):
   r=p.blank('a'*40,'1');r['host_marker'][key]='PRIVATE'
   with self.assertRaises(ValueError):p.validate(r)
if __name__=='__main__':unittest.main()
