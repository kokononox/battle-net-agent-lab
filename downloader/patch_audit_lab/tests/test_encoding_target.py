import copy,hashlib,io,json,tempfile,unittest
from pathlib import Path
import encoding_target as e
import patch_audit as a
import source_binding as b
import refs_source_check as r

def fixture(data=b'hello',spec='b:*=z'):
    encoded=e.encode(data,spec);hs=int.from_bytes(encoded[4:8],'big');ek=hashlib.md5(encoded[:hs] if hs else encoded).digest();ck=hashlib.md5(data).digest()
    specs=(spec+'\0').encode();c=b'\1'+len(data).to_bytes(5,'big')+ck+ek;c+=bytes(1024-len(c))
    er=ek+bytes(4)+len(encoded).to_bytes(5,'big');er+=bytes(1024-len(er))
    header=b'EN\1\x10\x10'+(1).to_bytes(2,'big')*2+(1).to_bytes(4,'big')*2+b'\0'+len(specs).to_bytes(4,'big')
    raw=header+specs+ck+hashlib.md5(c).digest()+c+ek+hashlib.md5(er).digest()+er
    return raw,ck,ek,encoded

class LookupTests(unittest.TestCase):
    def test_content_and_encoding(self):
        raw,ck,ek,enc=fixture();t=e.EncodingLookup(io.BytesIO(raw),len(raw))
        self.assertEqual(t.content(ck),(5,[ek]));self.assertEqual(t.encoded(ek)['encoded_size'],len(enc))
        self.assertEqual(t.encoded(ek)['espec'],'b:*=z');self.assertLess(t.read_bytes,65536)
    def test_missing_key(self):
        raw,ck,ek,_=fixture();t=e.EncodingLookup(io.BytesIO(raw),len(raw));self.assertIsNone(t.content(bytes(16)))
    def test_bad_header(self):
        raw,*_=fixture()
        with self.assertRaises(b.BindingError):e.EncodingLookup(io.BytesIO(b'XX'+raw[2:]),len(raw))
    def test_truncated_geometry(self):
        raw,*_=fixture()
        with self.assertRaises(b.BindingError):e.EncodingLookup(io.BytesIO(raw[:-1]),len(raw)-1)
    def test_page_checksum(self):
        raw,ck,_,_=fixture();t=e.EncodingLookup(io.BytesIO(raw),len(raw));bad=bytearray(raw);bad[t.cp+40]^=1
        with self.assertRaises(b.BindingError):e.EncodingLookup(io.BytesIO(bad),len(bad)).content(ck)
    def test_ekey_page_checksum(self):
        raw,_,ek,_=fixture();t=e.EncodingLookup(io.BytesIO(raw),len(raw));bad=bytearray(raw);bad[t.ep+21]^=1
        with self.assertRaises(b.BindingError):e.EncodingLookup(io.BytesIO(bad),len(bad)).encoded(ek)
    def test_stream_hash_lookup(self):
        raw,ck,ek,_=fixture()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'encoding';p.write_bytes(raw)
            size,rows,proof=e.lookup_file(p,b.Watch(),a.md5(raw),len(raw),ck.hex())
            self.assertEqual(size,5);self.assertTrue(proof['whole_decoded_encoding_ckey_verified']);self.assertEqual(rows[0]['ekey'],ek.hex())
    def test_wrong_full_ckey(self):
        raw,ck,_,_=fixture()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'encoding';p.write_bytes(raw)
            with self.assertRaises(b.BindingError):e.lookup_file(p,b.Watch(),'0'*32,len(raw),ck.hex())
    def test_wrong_full_size(self):
        raw,ck,_,_=fixture()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'encoding';p.write_bytes(raw)
            with self.assertRaises(b.BindingError):e.lookup_file(p,b.Watch(),a.md5(raw),len(raw)+1,ck.hex())

class RealScaleSpecBoundsTests(unittest.TestCase):
    def replace_specs(self,spec):
        raw,ck,ek,enc=fixture()
        old=int.from_bytes(raw[18:22],'big')
        return raw[:18]+len(spec).to_bytes(4,'big')+spec+raw[22+old:],ck,ek
    def test_more_than_8MiB_and_250000_specs(self):
        # Regression for real Retail: 16,030,848 bytes / 317,554 recipes.
        spec=(b'z:'+b'9'*45+b'\0')*317554
        self.assertGreater(len(spec),8*1024**2)
        raw,ck,ek=self.replace_specs(spec)
        table=e.EncodingLookup(io.BytesIO(raw),len(raw))
        self.assertEqual(len(table.specs),317554)
        self.assertEqual(table.content(ck),(5,[ek]))
    def test_over_16MiB_rejected(self):
        raw,ck,ek=self.replace_specs(b'a'*(16*1024**2)+b'\0')
        with self.assertRaises(b.BindingError):e.EncodingLookup(io.BytesIO(raw),len(raw))
    def test_over_500000_specs_rejected(self):
        raw,ck,ek=self.replace_specs(b'z\0'*500001)
        with self.assertRaises(b.BindingError):e.EncodingLookup(io.BytesIO(raw),len(raw))
    def test_long_realistic_recipe_is_retained_not_guessed(self):
        raw,ck,ek=self.replace_specs(b'a'*3514+b'\0')
        table=e.EncodingLookup(io.BytesIO(raw),len(raw))
        self.assertEqual(len(table.encoded(ek)['espec']),3514)
        report,generated=e.assess(b'hello',table.encoded(ek))
        self.assertFalse(report['reencode_attempted']);self.assertIsNone(generated)

class EncoderTests(unittest.TestCase):
    def roundtrip(self,spec,data=b'abcd'*100):
        raw=e.encode(data,spec);hs=int.from_bytes(raw[4:8],'big');key=a.md5(raw[:hs] if hs else raw)
        self.assertEqual(r.decode_source(raw,key,len(data))[0],data)
        return raw
    def test_headerless_n(self):self.assertEqual(self.roundtrip('n')[:8],b'BLTE'+bytes(4))
    def test_headerless_z(self):self.roundtrip('z')
    def test_z_level(self):self.roundtrip('z:6')
    def test_explicit_window(self):self.roundtrip('z:{6,14}')
    def test_mpq_window(self):self.roundtrip('z:{6,mpq}')
    def test_one_chunk(self):self.assertEqual(self.roundtrip('b:*=z')[9:12],b'\0\0\1')
    def test_many_greedy_chunks(self):self.assertEqual(self.roundtrip('b:64*=z')[9:12],b'\0\0\7')
    def test_kilobyte_unit(self):self.roundtrip('b:1K*=z',b'X'*2049)
    def test_counted_chunks(self):self.roundtrip('b:{100*3=n,*=z}')
    def test_fixed_mixed(self):self.roundtrip('b:{100=n,300=z:{9,15}}')
    def test_nested_encryption_unsupported(self):
        with self.assertRaises(e.UnsupportedSpec):e.encode(b'abc','e:{AAAAAAAAAAAAAAAA,00000000,z}')
    def test_nested_blocks_unsupported(self):
        with self.assertRaises(e.UnsupportedSpec):e.encode(b'abc','b:*=b:*=z')
    def test_nonfinal_greedy_rejected(self):
        with self.assertRaises(e.UnsupportedSpec):e.encode(b'abc','b:{*=n,1=n}')
    def test_unconsumed_input_rejected(self):
        with self.assertRaises(e.UnsupportedSpec):e.encode(b'abc','b:1=n')
    def test_overrun_rejected(self):
        with self.assertRaises(e.UnsupportedSpec):e.encode(b'abc','b:4=n')
    def test_many_chunks_rejected(self):
        with self.assertRaises(e.UnsupportedSpec):e.encode(b'A'*1000,'b:1*=n')
    def test_bad_level(self):
        with self.assertRaises(e.UnsupportedSpec):e.encode(b'abc','z:99')
    def test_assess_success(self):
        raw,ck,ek,enc=fixture();report,generated=e.assess(b'hello',{'ekey':ek.hex(),'encoded_size':len(enc),'espec':'b:*=z','espec_index':0})
        self.assertTrue(report['exact_target_ekey_reproduced']);self.assertEqual(generated,enc)
    def test_assess_no_wrong_identity_written(self):
        raw,ck,ek,enc=fixture();report,generated=e.assess(b'hello',{'ekey':'0'*32,'encoded_size':len(enc),'espec':'b:*=z'})
        self.assertFalse(report['exact_target_ekey_reproduced']);self.assertIsNone(generated)
    def test_assess_unsupported_reported(self):
        report,generated=e.assess(b'hello',{'ekey':'0'*32,'encoded_size':100,'espec':'g:1'})
        self.assertFalse(report['reencode_attempted']);self.assertIsNone(generated)
