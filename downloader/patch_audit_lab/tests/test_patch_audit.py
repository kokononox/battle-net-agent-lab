import hashlib
import io
import struct
import unittest
import zlib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import patch_audit as a


def num(n):
    return (abs(n) | (1 << 63 if n < 0 else 0)).to_bytes(8, 'little')

def make_patch(triples=((3, 1, 0),), diff=b'\x01\xff\x01', extra=b'!', size=4):
    control = zlib.compress(b''.join(num(v) for t in triples for v in t))
    d = zlib.compress(diff)
    e = zlib.compress(extra)
    return b'ZBSDIFF1' + num(len(control)) + num(len(d)) + num(size) + control + d + e


def fake_manifest(*, count=1):
    rec = b'\x01' + b'\x20' * 16 + (4).to_bytes(5, 'big')
    rec += b'\x30' * 16 + (3).to_bytes(5, 'big') + b'\x40' * 16 + (100).to_bytes(4, 'big') + b'\x00'
    payload = rec + b'\0'
    block = payload + bytes(4096 - len(payload))
    header = b'PA\x02\x10\x10\x10\x0c' + count.to_bytes(2, 'big') + b'\x02'
    header += bytes(16 + 16) + struct.pack('>II', 100, 80) + b'\x00'
    entry = b'\x20' * 16 + hashlib.md5(payload).digest() + (len(header) + 36).to_bytes(4, 'big')
    raw_header = header + entry
    return raw_header + block, a.md5(raw_header)


def fake_blte(data=b'abcd'):
    chunks = [b'N' + data[:2], b'Z' + zlib.compress(data[2:])]
    header = b'BLTE' + (60).to_bytes(4, 'big') + b'\x0f\0\0\x02'
    for chunk, size in zip(chunks, (2, len(data) - 2)):
        header += struct.pack('>II', len(chunk), size) + hashlib.md5(chunk).digest()
    return header + b''.join(chunks), a.md5(header), a.md5(data), len(data)

class PatchTests(unittest.TestCase):
    def test_sign_magnitude_negative_seek(self):
        self.assertEqual(a.offtin(bytes.fromhex('a210000000000080')), -4258)
    def test_sign_magnitude_roundtrip(self):
        for n in [0, 1, 255, 1000000, (1 << 63)-1, -1, -4258, -((1 << 63)-1)]:
            self.assertEqual(a.offtin(num(n)), n)
    def test_integer_width(self):
        with self.assertRaises(a.AuditError): a.offtin(b'1')
    def test_modular_addition_not_xor(self):
        b=make_patch()
        out, _ = a.apply_patch(b'ABC', b, a.md5(b), 4, a.md5(b'BAD!'), source_sha256=a.sha256(b'ABC'))
        self.assertEqual(out, b'BAD!')
    def test_negative_seek_backwards(self):
        b=make_patch(((2,0,-2),(2,0,0)), bytes(4), b'', 4)
        out, _=a.apply_patch(b'ab',b,a.md5(b),4,a.md5(b'abab'),source_sha256=a.sha256(b'ab'))
        self.assertEqual(out,b'abab')
    def test_negative_and_past_end_source_positions_zero_fill(self):
        b=make_patch(((0,0,-1),(5,0,0)), bytes([1]*5), b'', 5)
        out,_=a.apply_patch(b'AB',b,a.md5(b),5,a.md5(b'\x01BC\x01\x01'),source_sha256=a.sha256(b'AB'))
        self.assertEqual(out,b'\x01BC\x01\x01')
    def test_zero_output(self):
        b=make_patch((), b'', b'', 0)
        out,_=a.apply_patch(b'',b,a.md5(b),0,a.md5(b''),source_sha256=a.sha256(b''))
        self.assertEqual(out,b'')
    def test_source_proof_rejected(self):
        b=make_patch()
        with self.assertRaisesRegex(a.AuditError,'source_proof'):
            a.apply_patch(b'ABD',b,a.md5(b),4,a.md5(b'BAD!'),source_sha256=a.sha256(b'ABC'))
    def test_wrong_target_ckey_rejected(self):
        b=make_patch()
        with self.assertRaisesRegex(a.AuditError,'output_ckey'):
            a.apply_patch(b'ABC',b,a.md5(b),4,'0'*32,source_sha256=a.sha256(b'ABC'))
    def test_wrong_patch_hash(self):
        with self.assertRaisesRegex(a.AuditError,'patch_checksum'): a.parse_patch(make_patch(),'0'*32,4)
    def test_wrong_magic(self):
        b=b'BSDIFF40'+make_patch()[8:]
        with self.assertRaisesRegex(a.AuditError,'patch_header'): a.parse_patch(b,a.md5(b),4)
    def test_truncated_header(self):
        with self.assertRaises(a.AuditError): a.parse_patch(b'ZBSDIFF1','0'*32,4)
    def test_every_patch_truncation(self):
        b=make_patch()
        for n in range(len(b)):
            with self.subTest(n=n), self.assertRaises(a.AuditError): a.parse_patch(b[:n],a.md5(b[:n]),4)
    def test_negative_copy_lengths(self):
        for triple in [(-1,1,0),(1,-1,0)]:
            b=make_patch((triple,))
            with self.subTest(triple=triple), self.assertRaises(a.AuditError): a.parse_patch(b,a.md5(b),4)
    def test_output_bound(self):
        b=make_patch()
        with self.assertRaises(a.AuditError): a.parse_patch(b,a.md5(b),4,output_limit=3)
    def test_output_size_mismatch(self):
        b=make_patch()
        with self.assertRaises(a.AuditError): a.parse_patch(b,a.md5(b),5)
    def test_output_overflow(self):
        b=make_patch(((5,0,0),))
        with self.assertRaises(a.AuditError): a.parse_patch(b,a.md5(b),4)
    def test_underflow_or_leftovers(self):
        for b in [make_patch(((1,0,0),)),make_patch(diff=b'1234'),make_patch(extra=b'12')]:
            with self.subTest(digest=a.md5(b)), self.assertRaises(a.AuditError): a.parse_patch(b,a.md5(b),4)
    def test_trailing_compressed_bytes(self):
        b=make_patch()+b'!'
        with self.assertRaisesRegex(a.AuditError,'zlib_truncated_or_trailing'): a.parse_patch(b,a.md5(b),4)
    def test_corrupt_zlib(self):
        b=bytearray(make_patch());b[-1]^=1;b=bytes(b)
        with self.assertRaises(a.AuditError): a.parse_patch(b,a.md5(b),4)
    def test_partial_control_record(self):
        c=zlib.compress(b'1');d=zlib.compress(b'');e=zlib.compress(b'')
        b=b'ZBSDIFF1'+num(len(c))+num(len(d))+num(0)+c+d+e
        with self.assertRaisesRegex(a.AuditError,'control_width'): a.parse_patch(b,a.md5(b),0)
    def test_inflate_bomb_capped(self):
        with self.assertRaisesRegex(a.AuditError,'decompression_limit'): a.inflate(zlib.compress(bytes(10000)),100)
    def test_inflate_concatenated_stream(self):
        with self.assertRaises(a.AuditError): a.inflate(zlib.compress(b'1')+zlib.compress(b'2'),2)

class ManifestTests(unittest.TestCase):
    def test_valid_manifest_and_zero_based_ordinal(self):
        raw,k=fake_manifest();options,report=a.manifest(raw,k)
        self.assertEqual(len(options),1);self.assertEqual(options[0].ordinal,0)
        self.assertEqual(report['blocks'],1)
    def test_hash_includes_terminator_not_padding(self):
        raw,k=fake_manifest();self.assertNotEqual(a.md5(raw[87:]),raw[67:83].hex())
        a.manifest(raw,k)
    def test_corrupted_record(self):
        raw,k=fake_manifest();raw=bytearray(raw);raw[100]^=1
        with self.assertRaises(a.AuditError): a.manifest(bytes(raw),k)
    def test_nonzero_padding(self):
        raw,k=fake_manifest();raw=raw[:-1]+b'!'
        with self.assertRaisesRegex(a.AuditError,'padding'): a.manifest(raw,k)
    def test_header_checksum(self):
        raw,k=fake_manifest()
        with self.assertRaisesRegex(a.AuditError,'header_checksum'): a.manifest(raw,'0'*32)
    def test_unknown_variant(self):
        raw,k=fake_manifest()
        for at in [0,2,3,4,5,9]:
            b=bytearray(raw);b[at]^=1
            with self.subTest(at=at),self.assertRaises(a.AuditError):a.manifest(bytes(b),k)
    def test_invalid_bits(self):
        raw,k=fake_manifest();raw=raw[:6]+b'\x01'+raw[7:]
        with self.assertRaisesRegex(a.AuditError,'block_bits'): a.manifest(raw,k)
    def test_record_bounds(self):
        raw,k=fake_manifest();raw=bytearray(raw);raw[87]=17
        with self.assertRaisesRegex(a.AuditError,'record_bounds'): a.manifest(raw,k)
    def test_truncated_manifest(self):
        raw,k=fake_manifest()
        for n in [0,10,50,86,87,120,150]:
            with self.subTest(n=n),self.assertRaises(a.AuditError):a.manifest(raw[:n],k)
    def test_block_offset_rejected_even_rehashed(self):
        raw,k=fake_manifest();raw=bytearray(raw);raw[86]+=1
        with self.assertRaisesRegex(a.AuditError,'geometry'):a.manifest(raw,a.md5(raw[:87]))

class MetadataTests(unittest.TestCase):
    def test_blte_identity(self):
        b,ek,ck,n=fake_blte();out,count=a.blte(b,ek,ck,n)
        self.assertEqual((out,count),(b'abcd',2))
    def test_blte_corrupt_chunk(self):
        b,ek,ck,n=fake_blte();b=b[:-1]+bytes([b[-1]^1])
        with self.assertRaisesRegex(a.AuditError,'chunk_checksum'):a.blte(b,ek,ck,n)
    def test_blte_wrong_ekey(self):
        b,ek,ck,n=fake_blte()
        with self.assertRaises(a.AuditError):a.blte(b,'0'*32,ck,n)
    def test_blte_wrong_ckey(self):
        b,ek,ck,n=fake_blte()
        with self.assertRaises(a.AuditError):a.blte(b,ek,'0'*32,n)
    def test_blte_trailing_data(self):
        b,ek,ck,n=fake_blte()
        with self.assertRaises(a.AuditError):a.blte(b+b'!',ek,ck,n)
    def test_blte_wrong_size(self):
        b,ek,ck,n=fake_blte()
        with self.assertRaises(a.AuditError):a.blte(b,ek,ck,n-1)
    def test_table_select_eu(self):
        self.assertEqual(a.one(a.table(b'Region!X|Value!Y\n#x\neu|12\n'),'Region','eu')['Value'],'12')
    def test_duplicate_region(self):
        with self.assertRaises(a.AuditError):a.one([{'Region':'eu'},{'Region':'eu'}],'Region','eu')
    def test_bad_table_width(self):
        with self.assertRaises(a.AuditError):a.table(b'A|B\nx\n')
    def test_config_checksum_and_duplicates(self):
        b=b'patch = '+'a'.encode()*32+b'\n'
        self.assertEqual(a.config(b,a.md5(b))['patch'],['a'*32])
        with self.assertRaises(a.AuditError):a.config(b,'0'*32)
        with self.assertRaises(a.AuditError):a.config(b+b,a.md5(b+b))
    def test_official_origin_hints(self):
        row={'Path':'tpr/wow','Servers':'http://a.example/ https://a.example/?maxhosts=8&fallback=1'}
        self.assertEqual(a.official_origin(row),'https://a.example')
    def test_invalid_origins(self):
        for server in ['http://a.example','https://u:p@a.example','https://a.example/foo','https://127.0.0.1','https://a.local','https://a.example/?x=1','https://a.example/?fallback=1&fallback=1','https://a.example/#x','https://a.example:444/']:
            with self.subTest(server=server),self.assertRaises(a.AuditError):a.official_origin({'Path':'tpr/wow','Servers':server})
    def test_path_injection_keys(self):
        for k in ['../file','a'*31,'a'*33,'A'*32]:
            with self.subTest(k=k),self.assertRaises(a.AuditError):a.object_url('https://a.example','patch',k)
    def test_http_rejections_before_body(self):
        class Response:
            status=200
            headers={}
            def geturl(self):return 'https://a.example/x'
        for headers in [{'Content-Length':'1000'},{'Content-Length':'-1'},{'Content-Length':'2'},{'Content-Encoding':'gzip'},{'Content-Range':'bytes 0-1/2'}]:
            r=Response();r.headers=headers
            with self.subTest(headers=headers),self.assertRaises(a.AuditError):a.validate_response(r,'https://a.example/x',100,3)
    def test_http_status_and_redirect(self):
        class Response:
            headers={}
            status=206
            def geturl(self):return 'https://a.example/x'
        with self.assertRaises(a.AuditError):a.validate_response(Response(),'https://a.example/x',100,None)
        r=Response();r.status=200
        with self.assertRaises(a.AuditError):a.validate_response(r,'https://other.example/x',100,None)
        with self.assertRaises(a.AuditError):a.NoRedirect().redirect_request(None,None,302,'',{},'https://other.example')


class IndexAndFilesystemTests(unittest.TestCase):
    @staticmethod
    def index():
        k=b'\x22'*16
        block=k+(100).to_bytes(4,'big')+bytes(4096-20)
        toc=k+hashlib.md5(block).digest()[:8]
        base=bytes([1,0,0,4,0,4,16,8])+(1).to_bytes(4,'little')
        footer=hashlib.md5(toc).digest()[:8]+base+hashlib.md5(base+bytes(8)).digest()[:8]
        return block+toc+footer,a.md5(footer),k
    def test_loose_index_full_validation(self):
        b,k,target=self.index()
        routes,report=a.cdn_catalog.matches(b,k,{target:100},kind='loose')
        self.assertEqual(routes,[(target,'advertised_direct','',-1,100)])
        self.assertTrue(report['all_block_checksums_verified'])
    def test_index_corrupt_block(self):
        b,k,t=self.index();b=bytes([b[0]^1])+b[1:]
        with self.assertRaises(a.cdn_catalog.CatalogError):a.cdn_catalog.matches(b,k,{t:100},kind='loose')
    def test_index_wrong_size_not_selected(self):
        b,k,t=self.index();routes,report=a.cdn_catalog.matches(b,k,{t:99},kind='loose')
        self.assertEqual(routes,[]);self.assertEqual(report['target_size_conflicts'],1)
    def test_index_name_hash(self):
        b,k,t=self.index()
        with self.assertRaises(a.cdn_catalog.CatalogError):a.cdn_catalog.matches(b,'0'*32,{t:100},kind='loose')
    def test_index_corrupt_toc(self):
        b,k,t=self.index();b=b[:4096]+bytes([b[4096]^1])+b[4097:]
        with self.assertRaises(a.cdn_catalog.CatalogError):a.cdn_catalog.matches(b,k,{t:100},kind='loose')
    def test_index_truncated(self):
        b,k,t=self.index()
        for n in [1,28,4096,len(b)-1]:
            with self.subTest(n=n),self.assertRaises(a.cdn_catalog.CatalogError):a.cdn_catalog.matches(b[:n],k,{t:100},kind='loose')
    def test_fetch_unsafe_origin_no_request(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f=a.Fetcher(d)
            with self.assertRaisesRegex(a.AuditError,'unbound_origin'):f.get('https://other.example/x','a',100)
            self.assertEqual(list(Path(d).iterdir()),[])
    def test_fetch_refuse_existing_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'a';p.write_bytes(b'preserve')
            f=a.Fetcher(d)
            with self.assertRaisesRegex(a.AuditError,'overwrite'):f.get(a.VERSIONS,'a',100)
            self.assertEqual(p.read_bytes(),b'preserve')
    def test_fetch_path_traversal_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f=a.Fetcher(d)
            with self.assertRaisesRegex(a.AuditError,'output_name'):f.get(a.VERSIONS,'../oops',100)
    def test_fetch_symlink_directory_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            real=Path(d)/'real';real.mkdir();link=Path(d)/'link';link.symlink_to(real,target_is_directory=True)
            with self.assertRaisesRegex(a.AuditError,'fresh_directory'):a.Fetcher(link)

if __name__=='__main__':unittest.main()
