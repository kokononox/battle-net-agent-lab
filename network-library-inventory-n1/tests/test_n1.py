import ast,copy,json,struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'level3-request-audit-t1/app'))
import n1_pe as pe
import n1_inventory as inv

def fixture(bits=64):
    b=bytearray(2048);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0'
    op=152;opsize=240 if bits==64 else 224
    struct.pack_into('<H',b,134,1);struct.pack_into('<H',b,148,opsize);struct.pack_into('<H',b,op,0x20b if bits==64 else 0x10b)
    struct.pack_into('<I',b,op+60,512);struct.pack_into('<I',b,op+(108 if bits==64 else 92),16)
    dirs=op+(112 if bits==64 else 96)
    struct.pack_into('<II',b,dirs,0x1000,80);struct.pack_into('<II',b,dirs+8,0x1100,40)
    s=op+opsize;struct.pack_into('<IIII',b,s+8,1536,0x1000,1536,512)
    # Export directory -> one exported SSL_write name.
    struct.pack_into('<I',b,512+24,1);struct.pack_into('<I',b,512+32,0x1050)
    struct.pack_into('<I',b,592,0x1060);b[608:618]=b'SSL_write\0'
    # Import descriptor and null terminator; WSASend from ws2_32.dll.
    struct.pack_into('<IIIII',b,768,0x1160,0,0,0x1140,0x1160)
    b[832:843]=b'ws2_32.dll\0'
    if bits==64:struct.pack_into('<QQ',b,864,0x1180,0)
    else:struct.pack_into('<II',b,864,0x1180,0)
    b[896:898]=b'\0\0';b[898:906]=b'WSASend\0'
    return b

class PETests(unittest.TestCase):
    def test_pe64_metadata(self):
        r=pe.PE(fixture()).result();self.assertEqual(r['exported_api_hints'],['SSL_write']);self.assertEqual(r['imported_api_hints'],['WSASend']);self.assertEqual(r['imported_library_categories'],['ws2_32.dll']);self.assertFalse(r['library_presence_proves_use'])
    def test_pe32_metadata(self):self.assertEqual(pe.PE(fixture(32)).result()['imported_api_hints'],['WSASend'])
    def test_unknown_export_not_returned(self):
        b=fixture();b[608:618]=b'PRIVATE_X\0';r=pe.PE(b).result();self.assertEqual(r['exported_api_hints'],[]);self.assertNotIn('PRIVATE',json.dumps(r))
    def test_bad_mz(self):
        with self.assertRaises(ValueError):pe.PE(b'X'*2048)
    def test_truncated_file(self):
        with self.assertRaises(ValueError):pe.PE(fixture()[:100])
    def test_export_name_unmapped(self):
        b=fixture();struct.pack_into('<I',b,592,0x70000000)
        with self.assertRaises(ValueError):pe.PE(b).result()
    def test_unterminated_name(self):
        b=fixture();b[608:1121]=b'A'*513
        with self.assertRaises(ValueError):pe.PE(b).result()
    def test_section_beyond_file(self):
        b=fixture();struct.pack_into('<I',b,152+240+20,100000)
        with self.assertRaises(ValueError):pe.PE(b).result()
    def test_ordinal_import_not_named(self):
        b=fixture();struct.pack_into('<Q',b,864,(1<<63)+42);self.assertEqual(pe.PE(b).result()['imported_api_hints'],[])
    def test_delay_import_caveat(self):
        b=fixture();struct.pack_into('<II',b,152+112+13*8,0x1200,32);r=pe.PE(b).result();self.assertTrue(r['delay_imports_present']);self.assertFalse(r['delay_imports_inspected'])
    def test_no_directories(self):
        b=fixture();struct.pack_into('<I',b,152+108,0);r=pe.PE(b).result();self.assertEqual(r['exported_api_hints'],[]);self.assertEqual(r['imported_api_hints'],[])
    def test_normalize_only_known_symbols(self):
        self.assertEqual(pe.canonical_symbol('_SSL_write@12'),'SSL_write');self.assertIsNone(pe.canonical_symbol('PRIVATE_CALL'))
    def test_safe_inspect_failure(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'bad.dll';p.write_bytes(b'bad');r=pe.inspect(p);self.assertEqual(r['status'],'unreadable_or_unrecognized_pe');self.assertNotIn(str(p),json.dumps(r))
    def test_inspect_uses_readonly_file(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'fixture.dll';data=fixture();p.write_bytes(data);r=pe.inspect(p);self.assertEqual(r['status'],'parsed');self.assertEqual(p.read_bytes(),data)
    def test_huge_export_count_bounded(self):
        b=fixture();struct.pack_into('<I',b,512+24,0xffffffff)
        with self.assertRaises(ValueError):pe.PE(b).result()

class InventoryTests(unittest.TestCase):
    def test_process_identity_guard(self):
        a={'path':'A','creation':1};self.assertTrue(inv.same_process(a,dict(path='a',creation=1)));self.assertFalse(inv.same_process(a,dict(path='a',creation=2)))
    def test_module_ignores_unknown_name(self):
        i=inv.Inventory();self.assertIsNone(i.module(Path('/nonexistent/private_name.dll'),Path('/image')))
    def test_module_cache_and_no_paths(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'libcef.dll';p.write_bytes(fixture());i=inv.Inventory();a=i.module(p,p);b=i.module(p,p)
            self.assertEqual(a,b);self.assertEqual(len(i.file_rows),1);text=json.dumps(i.report());self.assertNotIn(t,text);self.assertIn('libcef.dll',text)
    def test_size_limit(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'libcef.dll';p.write_bytes(fixture());i=inv.Inventory()
            with patch.object(inv,'MAX_FILE',128):self.assertIsNone(i.module(p,p))
            self.assertTrue(i.limits)
    def test_unsigned_image_not_inspected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'battle.net.exe';p.write_bytes(fixture());i=inv.Inventory();first=dict(path=str(p),creation=1,modules=[str(p)],module_status='ok')
            with patch.object(inv,'identity',return_value=first),patch.object(inv,'signature',return_value=dict(valid=False,blizzard=False)):
                k,info=i.image(dict(ProcessId=10,ParentProcessId=1,Name='battle.net.exe'))
            self.assertEqual(i.rows[k]['status'],'unconfirmed');self.assertEqual(i.file_rows,[])
    def test_pid_reuse_during_identity_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'battle.net.exe';p.write_bytes(fixture());i=inv.Inventory();first=dict(path=str(p),creation=1,modules=[],module_status='ok');second=dict(first,creation=2)
            with patch.object(inv,'identity',side_effect=[first,second]),patch.object(inv,'signature',return_value=dict(valid=True,blizzard=True)):
                k,info=i.image(dict(ProcessId=10,ParentProcessId=1,Name='battle.net.exe'))
            self.assertEqual(i.rows[k]['status'],'unconfirmed');self.assertEqual(i.rows[k]['error_code'],'pid_identity_changed')
    def test_sample_attributes_tcp_to_verified_process(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'battle.net.exe';p.write_bytes(fixture());lib=Path(t)/'libcef.dll';lib.write_bytes(fixture());i=inv.Inventory();live=dict(path=str(p),creation=1,modules=[str(p),str(lib)],module_status='ok')
            s=dict(processes=[dict(ProcessId=10,ParentProcessId=1,Name='battle.net.exe')],connections=[dict(OwningProcess=10,RemoteAddress='1.1.1.1',RemotePort=443,State='Established')])
            with patch.object(inv,'identity',return_value=live),patch.object(inv,'signature',return_value=dict(valid=True,blizzard=True)),patch.object(inv,'snapshot',return_value=s):i.sample()
            r=i.report();self.assertEqual(len(r['public_tcp_destinations']),1);self.assertEqual(len(r['module_files']),2);self.assertNotIn(t,json.dumps(r));self.assertFalse(r['limits']['hooks_attached'])
    def test_wow_causes_stop(self):
        i=inv.Inventory()
        with patch.object(inv,'snapshot',return_value=dict(processes=[dict(Name='wow.exe')],connections=[])):
            with self.assertRaises(ValueError):i.sample()
    def test_no_mutating_or_payload_apis(self):
        source=Path(inv.__file__).read_text()+Path(pe.__file__).read_text()
        for token in ('ReadProcessMemory','WriteProcessMemory','Interceptor','frida','HostsGuard(','.apply(','.restore(','.spawn(','.kill(','.resume(','.suspend(','Popen(','create_connection','urlopen','requests.'):
            self.assertNotIn(token,source)
    def test_required_base_manifest_is_current_receipt(self):
        receipt=json.loads((Path(__file__).resolve().parent/'fixtures/t11-build-receipt.json').read_text())
        self.assertEqual(inv.MANIFEST,receipt['build_manifest_sha256']);self.assertEqual(inv.SOURCE,receipt['source_commit'])
if __name__=='__main__':unittest.main()
