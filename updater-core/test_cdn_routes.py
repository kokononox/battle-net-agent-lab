import dataclasses,hashlib,unittest
from release_core import InvalidRelease
from test_release_core import target
from test_cdn_index import make
from cdn_index import parse_cdn_index
from cdn_routes import archive_index_plan,locate_in_verified_archive
class Tests(unittest.TestCase):
 def setup(self,off=4,rows=None):
  raw,key=make(off=off,rows=rows);cfg=('archives = '+key+'\narchives-index-size = '+str(len(raw))+'\n').encode();t=dataclasses.replace(target(),cdn_config=hashlib.md5(cfg).hexdigest());plan=archive_index_plan(t,cfg);return parse_cdn_index(raw,key),plan[0],t,cfg
 def test_resolved_offset(self):
  x,r,_,_=self.setup();v=locate_in_verified_archive(x,r,'1'*32,52);self.assertEqual(v['archive_offset'],100);self.assertEqual(v['end_inclusive'],151);self.assertEqual(v['archive_url']+'.index',r.url);self.assertFalse(v['payload_identity_verified'])
 def test_absent(self):
  x,r,_,_=self.setup();self.assertIsNone(locate_in_verified_archive(x,r,'3'*32,52))
 def test_loose_not_archive(self):
  x,r,_,_=self.setup(off=0)
  with self.assertRaises(InvalidRelease):locate_in_verified_archive(x,r,'1'*32,52)
 def test_wrong_key(self):
  x,r,_,_=self.setup()
  with self.assertRaises(InvalidRelease):locate_in_verified_archive(x,dataclasses.replace(r,archive_key='f'*32),'1'*32,52)
 def test_duplicate_ambiguous(self):
  x,r,_,_=self.setup(rows=[(bytes.fromhex('1'*32),52,100),(bytes.fromhex('1'*32),52,200)])
  with self.assertRaises(InvalidRelease):locate_in_verified_archive(x,r,'1'*32,52)
 def test_wrong_config(self):
  _,_,t,cfg=self.setup()
  with self.assertRaises(InvalidRelease):archive_index_plan(t,cfg+b'\n')
 def test_list_length_conflict(self):
  _,_,t,cfg=self.setup();cfg=cfg.replace(b'archives-index-size = ',b'archives-index-size = 999 ');t=dataclasses.replace(t,cdn_config=hashlib.md5(cfg).hexdigest())
  with self.assertRaises(InvalidRelease):archive_index_plan(t,cfg)
 def test_span_overflow(self):
  x,r,_,_=self.setup(rows=[(bytes.fromhex('1'*32),52,2**32-30)])
  with self.assertRaises(InvalidRelease):locate_in_verified_archive(x,r,'1'*32,52)
if __name__=='__main__':unittest.main()
