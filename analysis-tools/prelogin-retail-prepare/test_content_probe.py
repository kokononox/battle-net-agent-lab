import unittest,hashlib,os,tempfile,struct,io,json
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack
import content_probe as c
import make_content_reference as m
class Content(unittest.TestCase):
 def setUp(self):
  self.ref=c.reference();self.data=b'known synthetic official fixture';self.ref['components']={k:[dict(ckey=hashlib.md5(self.data).hexdigest(),size=len(self.data))]for k in c.PATHS}
 def context(self,t):
  stack=ExitStack();stack.enter_context(patch.dict(os.environ,{'RETAIL_CONTENT_PROBE':'official-install-t9','RETAIL_BUDGET_PROFILE':'approved-2g-512m-t9'}));stack.enter_context(patch.object(c,'reference',return_value=self.ref));stack.enter_context(patch.object(c,'save',side_effect=c.validate));return stack
 def probe(self,t):return c.Probe(Path(t),{k:self.ref[k]for k in ('version','build_config')},'a'*40,'1')
 def test_empty_then_exact_full_ckey_match(self):
  with tempfile.TemporaryDirectory()as t,self.context(t):
   p=self.probe(t);p.scan();self.assertFalse(p.r['game_component_materialized'])
   path=Path(t)/'_retail_/Utils/WowVoiceProxy.exe';path.parent.mkdir(parents=True);path.write_bytes(self.data);p.scan()
   self.assertTrue(p.r['game_component_materialized']);self.assertFalse(p.r['network_delivery_of_same_file_proven']);c.validate(p.r)
 def test_same_size_wrong_content_not_proof(self):
  with tempfile.TemporaryDirectory()as t,self.context(t):
   p=self.probe(t);path=Path(t)/'Utils/WowVoiceProxy.exe';path.parent.mkdir();path.write_bytes(b'x'*len(self.data));p.scan();self.assertFalse(p.r['game_component_materialized']);self.assertEqual(p.r['components']['voice_proxy']['state'],'hash_mismatch')
 def test_existing_before_probe_refused(self):
  with tempfile.TemporaryDirectory()as t,self.context(t):
   path=Path(t)/'Utils/WowVoiceProxy.exe';path.parent.mkdir();path.write_bytes(self.data)
   with self.assertRaises(ValueError):self.probe(t)
 def test_symlink_ancestor_refused(self):
  with tempfile.TemporaryDirectory()as t,self.context(t):
   p=self.probe(t);outside=Path(t)/'other';outside.mkdir();(Path(t)/'Utils').symlink_to(outside,target_is_directory=True)
   with self.assertRaises(Exception):p.scan()
 def test_hard_link_refused(self):
  with tempfile.TemporaryDirectory()as t,self.context(t):
   p=self.probe(t);path=Path(t)/'Utils/WowVoiceProxy.exe';path.parent.mkdir();path.write_bytes(self.data);os.link(path,Path(t)/'alias')
   with self.assertRaises(Exception):p.scan()
 def test_wrong_build_refused(self):
  with tempfile.TemporaryDirectory()as t,self.context(t):
   with self.assertRaises(ValueError):c.Probe(Path(t),dict(version='0',build_config='a'*32),'a'*40,'1')
 def test_no_scope_no_probe(self):
  with patch.dict(os.environ,{},clear=True):
   with self.assertRaises(ValueError):c.Probe(Path('.'),None,'a'*40,'1')
 def test_refuses_extra_private_fields_and_overclaims(self):
  for k in ('network_delivery_of_same_file_proven','complete_installation_proven','hardware_upload_proven','raw_paths_exported','game_files_written_by_probe'):
   r=c.blank('a'*40,'1');r[k]=True
   with self.assertRaises(ValueError):c.validate(r)
  r=c.blank('a'*40,'1');r['raw_path']='x'
  with self.assertRaises(ValueError):c.validate(r)
 def test_positive_without_hash_fails(self):
  r=c.blank('a'*40,'1');r['game_component_materialized']=True
  with self.assertRaises(ValueError):c.validate(r)
 def test_size_mismatch_never_hashed(self):
  with tempfile.TemporaryDirectory()as t,self.context(t):
   p=self.probe(t);path=Path(t)/'Utils/WowVoiceProxy.exe';path.parent.mkdir();path.write_bytes(b'x');p.scan();self.assertEqual(p.r['hash_checks'],0)
 def test_changing_file_not_proof(self):
  with tempfile.TemporaryDirectory()as t,self.context(t):
   p=self.probe(t);path=Path(t)/'Utils/WowVoiceProxy.exe';path.parent.mkdir();path.write_bytes(self.data)
   with patch.object(c,'digest_exact',side_effect=c.core.RepairError('source_changed')):p.scan()
   self.assertFalse(p.r['game_component_materialized'])
class Manifest(unittest.TestCase):
 def decoded(self):
  rows=[('Utils\\WowVoiceProxy.exe',b'v'),('Utils\\WowWindowsExceptionHandler.dll',b'e')];data=b'IN\x01\x10'+struct.pack('>HI',1,len(rows))+b'Windows\0'+b'\0\1'+b'\xc0'
  for name,body in rows:data+=name.encode()+b'\0'+hashlib.md5(body).digest()+struct.pack('>I',len(body))
  return data
 def test_real_pinned_reference_is_bounded(self):
  r=c.reference();self.assertEqual(r['install_encoded_bytes'],23106);self.assertTrue(r['install_full_ekey_and_ckey_verified'])
 def test_parse_strict_bounds(self):
  d=self.decoded();self.assertEqual(set(m.parse(d)),set(c.PATHS))
  for bad in (d[:-1],d+b'x',b'IN\x01\x10'+b'\xff'*6):
   with self.assertRaises(ValueError):m.parse(bad)
 def test_complete_blte_and_ckey_proof(self):
  d=self.decoded();e=b'BLTE\0\0\0\0N'+d;ck=hashlib.md5(d).hexdigest();ek=hashlib.md5(e).hexdigest();config=f'build-uid = wow\nbuild-name = WOW-70575patch12.1.5_Retail\ninstall = {ck} {ek}\ninstall-size = {len(d)} {len(e)}\n'.encode();key=hashlib.md5(config).hexdigest();r=m.build(config,e,key);self.assertTrue(r['install_full_ekey_and_ckey_verified'])
  with self.assertRaises(Exception):m.build(config,e[:-1]+b'x',key)
if __name__=='__main__':unittest.main()
