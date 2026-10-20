import importlib.util,json,struct,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from pml_read import analyze,PmlError,HEADER,EVENT
SELECT=r'D:\Games\_retail_\Wow.exe'

def fixture(op=2,ip6=False,result=0,root=True,extra_process=False,ptr=8,depth=1,version=9):
    b=bytearray(HEADER);b[:4]=b'PML_'
    struct.pack_into('<II',b,4,version,1 if ptr==8 else 0)
    # Privacy sentinel: private header should never reach minimized output.
    b[12:32]='PRIVATE_PC'.encode('utf-16le')
    strings=[SELECT if root else r'D:\Other\Other.exe',r'D:\SecretUser\private-library.dll','password-and-BIOS-PRIVATE-SENTINEL']
    if extra_process:strings.append(r'D:\Games\_retail_\helper.exe')
    ev=len(b)
    flags=(0 if ip6 else 3)|4
    import ipaddress
    src=ipaddress.ip_address('2001:db8::10' if ip6 else '192.0.2.10').packed.ljust(16,b'\0')
    dst=ipaddress.ip_address('2001:db8::20' if ip6 else '203.0.113.20').packed.ljust(16,b'\0')
    detail=struct.pack('<HHI',flags,0,123)+src+dst+struct.pack('<HH',50000,443)
    b+=EVENT.pack(1,25,5,op,0,0,10,1000,result,depth,0,len(detail),0)
    b+=struct.pack('<'+('Q' if ptr==8 else 'I')*depth,*([0x1001]*depth))+detail
    idx=len(b);b+=struct.pack('<IB',ev,0)
    pt=len(b);n=2 if extra_process else 1
    b+=struct.pack('<I',n)+struct.pack('<'+'I'*n,*range(1,n+1))+b'\0'*(4*n)
    for j in range(n):
        rel=len(b)-pt;struct.pack_into('<I',b,pt+4+4*n+4*j,rel)
        p=bytearray(100+ptr);struct.pack_into('<III',p,0,j+1,123+j,999 if j==0 else 123)
        struct.pack_into('<QQ',p,32,100+j,0)
        struct.pack_into('<I',p,68,0 if j==0 else 3)
        struct.pack_into('<I',p,72,2) # command line never read or exported
        struct.pack_into('<I',p,96+ptr,1)
        m=bytearray(48+2*ptr);struct.pack_into('<Q' if ptr==8 else '<I',m,ptr,0x1000)
        struct.pack_into('<II',m,2*ptr,0x100,1)
        b+=p+m
    st=len(b);b+=struct.pack('<I',len(strings))+b'\0'*(4*len(strings))
    for i,s in enumerate(strings):
        struct.pack_into('<I',b,st+4+4*i,len(b)-st);raw=(s+'\0').encode('utf-16le');b+=struct.pack('<I',len(raw))+raw
    icons=len(b);b+=b'\0'*4;hosts=len(b);b+=b'\0'*8
    struct.pack_into('<I',b,0x234,1);struct.pack_into('<QQQQQ',b,0x240,ev,idx,pt,st,icons)
    struct.pack_into('<QQ',b,0x398,HEADER,hosts)
    return b

class ReaderTests(unittest.TestCase):
    def run_bytes(self,b,**kw):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'trace.pml';p.write_bytes(b);return analyze(p,SELECT,**kw)
    def bad(self,b,code=None):
        with self.assertRaises(PmlError) as c:self.run_bytes(b)
        if code:self.assertIn(code,str(c.exception))
    def test_ipv4_send(self):
        r=self.run_bytes(fixture());n=r['outgoing_observations'][0]
        self.assertEqual((n['remote_ip'],n['remote_port'],n['successful_send_length_sum']),('203.0.113.20',443,123))
    def test_ipv6(self):self.assertEqual(self.run_bytes(fixture(ip6=True))['outgoing_observations'][0]['remote_ip'],'2001:db8::20')
    def test_x86(self):self.assertEqual(self.run_bytes(fixture(ptr=4))['selected_events'],1)
    def test_stack_hint(self):self.assertEqual(self.run_bytes(fixture())['outgoing_observations'][0]['stack_module_hints'],['private-library.dll'])
    def test_failed_send_not_counted(self):self.assertEqual(self.run_bytes(fixture(result=5))['outgoing_observations'][0]['successful_send_length_sum'],0)
    def test_connect_not_upload(self):self.assertEqual(self.run_bytes(fixture(op=5))['outgoing_observations'][0]['successful_send_length_sum'],0)
    def test_retransmit_not_upload(self):self.assertEqual(self.run_bytes(fixture(op=8))['outgoing_observations'][0]['successful_send_length_sum'],0)
    def test_receive_not_mislabeled_outgoing(self):
        r=self.run_bytes(fixture(op=3));self.assertEqual(r['outgoing_observations'],[]);self.assertEqual(r['receive_event_count_without_endpoint_attribution'],1)
    def test_unknown_network(self):self.assertEqual(self.run_bytes(fixture(op=999))['unknown_network_operations'],1)
    def test_no_root_is_error_not_empty(self):self.bad(fixture(root=False),'selected_image_not_observed')
    def test_descendant_labeled_candidate(self):self.assertEqual(self.run_bytes(fixture(extra_process=True))['processes'][1]['scope'],'pid_lifetime_descendant_candidate')
    def test_unhandled_pml_version(self):self.bad(fixture(version=10),'unsupported_pml_version_10')
    def test_magic(self):b=fixture();b[:4]=b'NOPE';self.bad(b,'not_pml')
    def test_truncated(self):self.bad(fixture()[:100],'too_short')
    def test_unfinalized(self):b=fixture();struct.pack_into('<Q',b,0x250,0);self.bad(b,'not_finalized')
    def test_event_limit(self):b=fixture();struct.pack_into('<I',b,0x234,1500001);self.bad(b,'event_limit')
    def test_string_table_count(self):
        b=fixture();st=struct.unpack_from('<Q',b,0x258)[0];struct.pack_into('<I',b,st,1000001);self.bad(b,'string_table_limit')
    def test_process_limit(self):
        b=fixture();pt=struct.unpack_from('<Q',b,0x250)[0];struct.pack_into('<I',b,pt,4097);self.bad(b,'process_limit')
    def test_bad_event_offset(self):
        b=fixture();idx=struct.unpack_from('<Q',b,0x248)[0];struct.pack_into('<I',b,idx,0xffffffff);self.bad(b,'event_offset_invalid')
    def test_bad_detail_size(self):b=fixture();struct.pack_into('<I',b,HEADER+44,0xffffffff);self.bad(b,'event_size_invalid')
    def test_bad_network_flags(self):b=fixture();struct.pack_into('<H',b,HEADER+EVENT.size+8,0x80);self.bad(b,'flags_unknown')
    def test_bad_module_count(self):
        b=fixture();pt=struct.unpack_from('<Q',b,0x250)[0];p=pt+struct.unpack_from('<I',b,pt+8)[0];struct.pack_into('<I',b,p+104,4097);self.bad(b,'module_limit')
    def test_budget_time(self):self.bad_time()
    def bad_time(self):
        with self.assertRaisesRegex(PmlError,'time_limit'):self.run_bytes(fixture(),seconds=-1)
    def test_does_not_modify_pml(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x';b=fixture();p.write_bytes(b);analyze(p,SELECT);self.assertEqual(p.read_bytes(),b)
    def test_privacy(self):
        s=json.dumps(self.run_bytes(fixture()));self.assertNotIn('PRIVATE',s);self.assertNotIn('SecretUser',s);self.assertNotIn('D:',s);self.assertNotIn('192.0.2.10',s)
    def test_no_stack(self):self.assertEqual(self.run_bytes(fixture(depth=0))['outgoing_observations'][0]['stack_module_hints'],[])
    def test_selected_case_insensitive(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x';p.write_bytes(fixture());self.assertEqual(analyze(p,SELECT.lower())['selected_events'],1)
    def test_scan_unknown_non_network(self):
        b=fixture();struct.pack_into('<I',b,HEADER+8,999)
        r=self.run_bytes(b);self.assertEqual(r['status'],'no_network_events_observed_in_this_window')
    def test_architecture_invalid(self):b=fixture();struct.pack_into('<I',b,8,64);self.bad(b,'architecture_unknown')
    def test_developer_did_not_add_xml_conversion(self):
        s=(Path(__file__).resolve().parents[1]/'app/observe.py').read_text()
        self.assertNotIn('/SaveAs',s);self.assertNotIn('/OpenLog',s);self.assertNotIn("os.environ['LOCALAPPDATA']",s)
        self.assertIn("'/Runtime','20'",s);self.assertIn('storage_preflight()',s);self.assertIn('stop_owned()',s)

class WrapperGuardTests(unittest.TestCase):
    def setUp(self):self.s=(Path(__file__).resolve().parents[1]/'app/observe.py').read_text()
    def test_refuses_c(self):self.assertIn("package.drive.lower()=='c:'",self.s)
    def test_checks_actual_system_volume(self):self.assertIn('guid==sysguid',self.s)
    def test_refuses_redirect_capture(self):self.assertIn('capture_folder_redirect_not_allowed',self.s)
    def test_checks_free_space(self):self.assertIn('need_2GiB_free_on_capture_drive',self.s);self.assertIn('need_1GiB_free_on_windows_drive',self.s)
    def test_stop_only_owned(self):self.assertIn('procmon_pids()!={ACTIVE.pid}',self.s)
    def test_analysis_child_timeout(self):self.assertIn('timeout=120',self.s)
    def test_signature_is_required(self):self.assertIn('verify_tool(tool)',self.s);self.assertIn('Get-AuthenticodeSignature',self.s)
    def test_no_sensitive_settings_mutation(self):
        self.assertNotIn('Set-ExecutionPolicy',self.s);self.assertNotIn('New-NetFirewallRule',self.s);self.assertNotIn('TerminateProcess',self.s)

if __name__=='__main__':unittest.main()
