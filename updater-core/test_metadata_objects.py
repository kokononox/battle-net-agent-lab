import tempfile,hashlib,zlib,struct,unittest
from pathlib import Path
from metadata_objects import decode_file,MetadataSession
from config_binding import ManifestDescriptor
from release_core import InvalidRelease
from test_release_core import target

def fixture(data=b'test-data'*100,mode=b'Z',header=True):
 chunk=mode+(zlib.compress(data) if mode==b'Z' else data)
 if header:
  h=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+struct.pack('>II',len(chunk),len(data))+hashlib.md5(chunk).digest();raw=h+chunk;ek=hashlib.md5(h).hexdigest()
 else:raw=b'BLTE'+bytes(4)+chunk;ek=hashlib.md5(raw).hexdigest()
 return raw,ManifestDescriptor('install',hashlib.md5(data).hexdigest(),ek,len(data),len(raw))
class MetadataTests(unittest.TestCase):
 def run_decode(self,raw,spec):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'input.blte';p.write_bytes(raw);d=Path(tmp)/'output.decoded';return decode_file(p,d,spec),d.read_bytes()
 def test_zlib(self):
  raw,s=fixture();r,data=self.run_decode(raw,s);self.assertEqual(data,b'test-data'*100);self.assertTrue(r['decoded_readback_verified'])
 def test_uncompressed(self):self.assertEqual(len(self.run_decode(*fixture(mode=b'N'))[1]),900)
 def test_headerless_z(self):self.assertEqual(len(self.run_decode(*fixture(header=False))[1]),900)
 def test_headerless_n(self):self.assertEqual(len(self.run_decode(*fixture(header=False,mode=b'N'))[1]),900)
 def test_bad_chunk_hash(self):
  raw,s=fixture();bad=bytearray(raw);bad[35]^=1;h=bytes(bad[:36]);s=ManifestDescriptor('install',s.ckey,hashlib.md5(h).hexdigest(),s.decoded_size,s.encoded_size)
  with self.assertRaises(InvalidRelease):self.run_decode(bytes(bad),s)
 def test_bad_ckey(self):
  raw,s=fixture();s=ManifestDescriptor('install','f'*32,s.ekey,s.decoded_size,s.encoded_size)
  with self.assertRaises(InvalidRelease):self.run_decode(raw,s)
 def test_bad_ekey(self):
  raw,s=fixture();s=ManifestDescriptor('install',s.ckey,'f'*32,s.decoded_size,s.encoded_size)
  with self.assertRaises(InvalidRelease):self.run_decode(raw,s)
 def test_unsupported_mode(self):
  raw,s=fixture(mode=b'E')
  with self.assertRaises(InvalidRelease):self.run_decode(raw,s)
 def test_declared_limit(self):
  raw,s=fixture();s=ManifestDescriptor('install',s.ckey,s.ekey,1,s.encoded_size)
  with self.assertRaises(InvalidRelease):self.run_decode(raw,s)
 def test_truncated(self):
  raw,s=fixture()
  with self.assertRaises(InvalidRelease):self.run_decode(raw[:-1],s)
 def test_output_never_overwritten(self):
  raw,s=fixture()
  with tempfile.TemporaryDirectory() as tmp:
   a=Path(tmp)/'in';a.write_bytes(raw);b=Path(tmp)/'out';b.write_bytes(b'keep')
   with self.assertRaises(InvalidRelease):decode_file(a,b,s)
   self.assertEqual(b.read_bytes(),b'keep')
 def test_only_metadata(self):
  _,s=fixture()
  with self.assertRaises(InvalidRelease):MetadataSession(target(),[s],s.encoded_size)
if __name__=='__main__':unittest.main()
