import io,struct,hashlib,unittest
from catalogue_readers import parse_install,DownloadReader,EncodingReader
from release_core import InvalidRelease
CK=b'c'*16;EK=b'e'*16

def install():return struct.pack('>2sBBHI',b'IN',1,16,1,1)+b'Windows\0\0\1\x80'+b'metadata-label\0'+CK+struct.pack('>I',5)
def download():return b'DL\1\x10\0'+(1).to_bytes(4,'big')+(1).to_bytes(2,'big')+EK+(40).to_bytes(5,'big')+b'\0'+b'Windows\0\0\1\x80'
def encoding():
 spec=b'b:*=z\0';c=b'\1'+(5).to_bytes(5,'big')+CK+EK;c+=bytes(1024-len(c));e=EK+bytes(4)+(40).to_bytes(5,'big');e+=bytes(1024-len(e));h=b'EN\1\x10\x10'+(1).to_bytes(2,'big')*2+(1).to_bytes(4,'big')*2+b'\0'+len(spec).to_bytes(4,'big');return h+spec+CK+hashlib.md5(c).digest()+c+EK+hashlib.md5(e).digest()+e
class Readers(unittest.TestCase):
 def test_install(self):
  tags,rows=parse_install(install());self.assertEqual(tags[0][1],'Windows');self.assertEqual(rows[0][2],CK)
 def test_install_unknown(self):
  raw=bytearray(install());raw[2]=2
  with self.assertRaises(InvalidRelease):parse_install(bytes(raw))
 def test_install_trailing(self):
  with self.assertRaises(InvalidRelease):parse_install(install()+b'bad')
 def test_install_truncated(self):
  with self.assertRaises(InvalidRelease):parse_install(install()[:-1])
 def test_download(self):
  raw=download();r=DownloadReader(io.BytesIO(raw),len(raw));self.assertEqual(list(r.records()),[(0,EK,40,0)]);self.assertEqual(list(r.tags()),[(0,'Windows',1,b'\x80')])
 def test_download_unknown(self):
  raw=bytearray(download());raw[2]=2
  with self.assertRaises(InvalidRelease):DownloadReader(io.BytesIO(raw),len(raw))
 def test_download_geometry(self):
  raw=download()
  with self.assertRaises(InvalidRelease):list(DownloadReader(io.BytesIO(raw),len(raw)-1).tags())
 def test_encoding(self):
  raw=encoding();r=EncodingReader(io.BytesIO(raw),len(raw));self.assertEqual(list(r.content()),[(CK,5,(EK,))]);self.assertEqual(list(r.encoded()),[(EK,40,0)]);self.assertEqual(r.tail['bytes'],0)
 def test_encoding_hash_failure(self):
  raw=bytearray(encoding());raw[-1]=1;r=EncodingReader(io.BytesIO(raw),len(raw))
  with self.assertRaises(InvalidRelease):list(r.encoded())
 def test_encoding_truncated(self):
  raw=encoding()
  with self.assertRaises(InvalidRelease):EncodingReader(io.BytesIO(raw[:-1]),len(raw)-1)
 def test_encoding_tail_not_guessed(self):
  raw=encoding()+b'unparsed';r=EncodingReader(io.BytesIO(raw),len(raw));self.assertEqual(r.tail['bytes'],8);self.assertFalse(r.tail['semantically_parsed'])
 def test_encoding_unknown_layout(self):
  raw=bytearray(encoding());raw[2]=2
  with self.assertRaises(InvalidRelease):EncodingReader(io.BytesIO(raw),len(raw))
if __name__=='__main__':unittest.main()
