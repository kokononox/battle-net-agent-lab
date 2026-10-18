import hashlib,unittest
from cdn_index import parse_cdn_index
from release_core import InvalidRelease

def make(rows=None,off=0,pages=None,count=None):
 rows=rows if rows is not None else [(bytes.fromhex('1'*32),52,100),(bytes.fromhex('2'*32),80,200)]
 if pages is None:pages=[rows]
 chunks=[];keys=[]
 for items in pages:
  data=b''.join(k+n.to_bytes(4,'big')+(o.to_bytes(off,'big')if off else b'')for k,n,o in items);chunks.append(data+bytes(4096-len(data)));keys.append(items[-1][0])
 toc=b''.join(keys)+b''.join(hashlib.md5(x).digest()[:8]for x in chunks);body=b''.join(chunks)+toc;count=sum(map(len,pages))if count is None else count
 fields=bytes([1,0,0,4,off,4,16,8])+count.to_bytes(4,'little');f=hashlib.md5(toc).digest()[:8]+fields+hashlib.md5(fields+bytes(8)).digest()[:8];return body+f,hashlib.md5(f).hexdigest()
class Tests(unittest.TestCase):
 def bad(self,raw,key,**kw):
  with self.assertRaises(InvalidRelease):parse_cdn_index(raw,key,**kw)
 def test_loose(self):
  b,k=make();x=parse_cdn_index(b,k,len(b));self.assertEqual(x.route_kind,'loose');self.assertIsNone(x.lookup('1'*32,52)[0].offset);self.assertEqual(x.summary()['records'],2);self.assertFalse(x.summary()['installation_ready'])
 def test_archive(self):
  b,k=make(off=4);x=parse_cdn_index(b,k);self.assertEqual(x.route_kind,'archive');self.assertEqual(x.lookup('1'*32,52)[0].offset,100)
 def test_absence_not_corruption(self):
  b,k=make();self.assertEqual(parse_cdn_index(b,k).lookup('3'*32),())
 def test_size_conflict(self):
  b,k=make()
  with self.assertRaises(InvalidRelease):parse_cdn_index(b,k).lookup('1'*32,53)
 def test_multipage(self):
  b,k=make(pages=[[(bytes.fromhex('1'*32),52,0)],[(bytes.fromhex('2'*32),80,0)]]);self.assertEqual(parse_cdn_index(b,k).page_count,2)
 def test_duplicate_not_silently_selected(self):
  b,k=make([(bytes.fromhex('1'*32),52,100),(bytes.fromhex('1'*32),52,200)],4);self.assertEqual(len(parse_cdn_index(b,k).lookup('1'*32)),2)
 def test_wrong_name(self):
  b,k=make();self.bad(b,'f'*32)
 def test_wrong_expected_size(self):
  b,k=make();self.bad(b,k,expected_size=len(b)+1)
 def test_footer_checksum(self):
  b,k=make();b=b[:-1]+bytes([b[-1]^1]);self.bad(b,hashlib.md5(b[-28:]).hexdigest())
 def test_unknown_profile(self):
  b,k=make(off=6);self.bad(b,k)
 def test_changed_page(self):
  b,k=make();self.bad(bytes([b[0]^1])+b[1:],k)
 def test_changed_toc(self):
  b,k=make();self.bad(b[:4096]+bytes([b[4096]^1])+b[4097:],k)
 def test_wrong_count(self):
  b,k=make(count=3);self.bad(b,k)
 def test_wrong_order(self):
  b,k=make([(bytes.fromhex('2'*32),80,0),(bytes.fromhex('1'*32),52,0)]);self.bad(b,k)
 def test_nonzero_padding_rehashed(self):
  b,k=make();p=bytearray(b[:4096]);p[-1]=1;toc=b[4096:-28];toc=toc[:16]+hashlib.md5(p).digest()[:8];fields=b[-20:-8];f=hashlib.md5(toc).digest()[:8]+fields+hashlib.md5(fields+bytes(8)).digest()[:8];self.bad(bytes(p)+toc+f,hashlib.md5(f).hexdigest())
 def test_wrong_last_key_rehashed(self):
  b,k=make();toc=bytes.fromhex('3'*32)+b[4112:-28];fields=b[-20:-8];f=hashlib.md5(toc).digest()[:8]+fields+hashlib.md5(fields+bytes(8)).digest()[:8];self.bad(b[:4096]+toc+f,hashlib.md5(f).hexdigest())
 def test_zero_size(self):
  b,k=make([(bytes.fromhex('1'*32),0,0)]);self.bad(b,k)
 def test_geometry(self):
  b,k=make();self.bad(b'0'+b,k)
 def test_empty(self):self.bad(b'', '1'*32)
 def test_bound(self):self.bad(b'x'*(4*1024**2+1),'1'*32)
 def test_bool_not_size(self):
  b,k=make();self.bad(b,k,expected_size=True)
if __name__=='__main__':unittest.main()
