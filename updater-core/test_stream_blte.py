import dataclasses,hashlib,io,struct,tracemalloc,unittest,zlib
from stream_blte import StreamObjectSpec,verify_stream,BLOCK
from release_core import InvalidRelease
from local_blte import verify_blte

def fixture(data=b'abcde',modes=(b'N',),header=True):
 parts=[];sizes=[]
 for mode in modes:
  block=mode+(zlib.compress(data)if mode==b'Z'else data);parts.append(block);sizes.append(len(data))
 if header:
  h=b'BLTE'+(12+24*len(parts)).to_bytes(4,'big')+b'\x0f'+len(parts).to_bytes(3,'big')
  h+=b''.join(struct.pack('>II',len(p),n)+hashlib.md5(p).digest()for p,n in zip(parts,sizes));raw=h+b''.join(parts);ek=hashlib.md5(h).hexdigest()
 else:
  assert len(parts)==1;raw=b'BLTE'+bytes(4)+parts[0];ek=hashlib.md5(raw).hexdigest()
 decoded=data*len(parts);return raw,StreamObjectSpec(hashlib.md5(decoded).hexdigest(),ek,len(decoded),len(raw))
class CheckedReader:
 def __init__(self,raw,short=None):self.raw=raw;self.at=0;self.short=short;self.max_request=0
 def read(self,n):
  if not 0<n<=BLOCK:raise AssertionError('unbounded read')
  self.max_request=max(self.max_request,n);n=min(n,self.short)if self.short else n;v=self.raw[self.at:self.at+n];self.at+=len(v);return v
class Tests(unittest.TestCase):
 def bad(self,raw,spec):
  with self.assertRaises((InvalidRelease,zlib.error)):verify_stream(io.BytesIO(raw),spec)
 def test_headered_n(self):
  raw,s=fixture();p=verify_stream(CheckedReader(raw),s);self.assertTrue(p['blte_chunk_checksums_verified']);self.assertEqual(p['decoded_bytes'],5)
 def test_headered_z(self):
  raw,s=fixture(b'hello'*10000,(b'Z',));self.assertEqual(verify_stream(CheckedReader(raw),s)['decoded_bytes'],50000)
 def test_headerless_n(self):
  raw,s=fixture(header=False);self.assertEqual(verify_stream(io.BytesIO(raw),s)['chunk_checksum_scope'],'not_present_headerless')
 def test_headerless_z(self):
  raw,s=fixture(modes=(b'Z',),header=False);self.assertTrue(verify_stream(io.BytesIO(raw),s)['full_ckey_verified'])
 def test_mixed_chunks(self):
  raw,s=fixture(b'hello',(b'N',b'Z',b'N'));self.assertEqual(verify_stream(io.BytesIO(raw),s)['blte_chunks'],3)
 def test_matches_old_small_verifier(self):
  for mode in (b'N',b'Z'):
   for h in (True,False):
    raw,s=fixture(b'hello'*200,(mode,),h);a=verify_blte(raw,s.public());b=verify_stream(io.BytesIO(raw),s);self.assertEqual(a['decoded_sha256'],b['decoded_sha256'])
 def test_short_reads_one_byte(self):
  raw,s=fixture(b'abc'*50,(b'Z',));self.assertTrue(verify_stream(CheckedReader(raw,1),s)['full_ckey_verified'])
 def test_large_n_over_old_four_mib_limit(self):
  raw,s=fixture(b'abcdef'*(1024**2),(b'N',));reader=CheckedReader(raw);p=verify_stream(reader,s);self.assertGreater(s.encoded_size,4*1024**2);self.assertLessEqual(reader.max_request,BLOCK);self.assertFalse(p['decoded_content_exported'])
 def test_compressed_twenty_mib_bounded_peak(self):
  raw,s=fixture(b'a'*(20*1024**2),(b'Z',));tracemalloc.start()
  try:p=verify_stream(CheckedReader(raw),s);_,peak=tracemalloc.get_traced_memory()
  finally:tracemalloc.stop()
  self.assertEqual(p['decoded_bytes'],20*1024**2);self.assertLess(peak,2*1024**2)
 def test_wrong_ckey(self):
  raw,s=fixture();self.bad(raw,dataclasses.replace(s,ckey='1'*32))
 def test_wrong_ekey(self):
  raw,s=fixture();self.bad(raw,dataclasses.replace(s,ekey='1'*32))
 def test_wrong_headerless_ekey(self):
  raw,s=fixture(header=False);self.bad(raw,dataclasses.replace(s,ekey='1'*32))
 def test_checksum_failure(self):
  raw,s=fixture();self.bad(raw[:-1]+b'x',s)
 def test_truncated(self):
  raw,s=fixture();self.bad(raw[:-1],s)
 def test_trailing(self):
  raw,s=fixture();self.bad(raw+b'x',s)
 def test_wrong_decoded_total(self):
  raw,s=fixture();self.bad(raw,dataclasses.replace(s,decoded_size=4))
 def test_headerless_expansion_bomb_stopped(self):
  raw,s=fixture(b'a'*1000000,(b'Z',),False);self.bad(raw,dataclasses.replace(s,decoded_size=5))
 def test_zlib_trailing(self):
  block=b'Z'+zlib.compress(b'abc')+b'x';raw=b'BLTE'+bytes(4)+block;s=StreamObjectSpec(hashlib.md5(b'abc').hexdigest(),hashlib.md5(raw).hexdigest(),3,len(raw));self.bad(raw,s)
 def test_zlib_truncated(self):
  block=b'Z'+zlib.compress(b'abc')[:-1];raw=b'BLTE'+bytes(4)+block;s=StreamObjectSpec(hashlib.md5(b'abc').hexdigest(),hashlib.md5(raw).hexdigest(),3,len(raw));self.bad(raw,s)
 def test_unsupported_mode_no_fallback(self):
  raw,s=fixture(modes=(b'E',));self.bad(raw,s)
 def test_huge_header_refused_before_body(self):
  raw,s=fixture();self.bad(raw[:4]+(2**31).to_bytes(4,'big')+raw[8:],s)
 def test_wrong_flags(self):
  raw,s=fixture();self.bad(raw[:8]+b'\x10'+raw[9:],s)
 def test_boolean_size_refused(self):
  with self.assertRaises(InvalidRelease):StreamObjectSpec('1'*32,'2'*32,True,9)
 def test_read_over_return_refused(self):
  raw,s=fixture()
  class Wrong:
   def read(self,n):return b'x'*(n+1)
  with self.assertRaises(InvalidRelease):verify_stream(Wrong(),s)
if __name__=='__main__':unittest.main()
