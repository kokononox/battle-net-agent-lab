import json,socket,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from profile_gate import explicit_zero_sink_hosts,resolution_probe,check_profile,NO_DATA_WITH_EXPLICIT_SINK
from request_audit import BLOCKED,TARGET

class ProfileGateTests(unittest.TestCase):
    def probe(self,text,code=11004,platform='win32',target_error=False,blocked_public=False):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'hosts';p.write_text(text,encoding='utf-8');original=p.read_bytes()
            def resolver(h,*args):
                if h==TARGET and not target_error or h!=TARGET and blocked_public:return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',0))]
                raise socket.gaierror(code,'fixture')
            result=resolution_probe(BLOCKED,TARGET,p,resolver,platform)
            self.assertEqual(p.read_bytes(),original)
            return result
    def full(self):return '\n'.join('0.0.0.0 '+h for h in BLOCKED)+'\n'
    def test_24_explicit_zero_no_data_and_public_target_accepted(self):
        r=self.probe(self.full());self.assertTrue(check_profile(r,BLOCKED,TARGET));self.assertTrue(all(r[h]==NO_DATA_WITH_EXPLICIT_SINK for h in BLOCKED))
    def test_missing_entry_not_accepted(self):
        r=self.probe(self.full().replace('0.0.0.0 '+BLOCKED[0]+'\n',''));self.assertFalse(check_profile(r,BLOCKED,TARGET));self.assertEqual(r[BLOCKED[0]],'resolution_failed')
    def test_empty_hosts_not_accepted(self):self.assertFalse(check_profile(self.probe(''),BLOCKED,TARGET))
    def test_11001_not_accepted(self):self.assertFalse(check_profile(self.probe(self.full(),11001),BLOCKED,TARGET))
    def test_11002_not_accepted(self):self.assertFalse(check_profile(self.probe(self.full(),11002),BLOCKED,TARGET))
    def test_timeout_not_accepted(self):self.assertFalse(check_profile(self.probe(self.full(),10060),BLOCKED,TARGET))
    def test_other_platform_not_accepted(self):self.assertFalse(check_profile(self.probe(self.full(),platform='linux'),BLOCKED,TARGET))
    def test_public_conflict_not_accepted(self):self.assertFalse(check_profile(self.probe(self.full()+'1.1.1.1 '+BLOCKED[0]),BLOCKED,TARGET))
    def test_invalid_conflict_not_accepted(self):self.assertFalse(check_profile(self.probe(self.full()+'invalid '+BLOCKED[0]),BLOCKED,TARGET))
    def test_ipv6_public_conflict_not_accepted(self):self.assertFalse(check_profile(self.probe(self.full()+'2606:4700:4700::1111 '+BLOCKED[0]),BLOCKED,TARGET))
    def test_target_error_still_rejected(self):self.assertFalse(check_profile(self.probe(self.full(),target_error=True),BLOCKED,TARGET))
    def test_public_blocked_response_never_overridden_by_hosts(self):self.assertFalse(check_profile(self.probe(self.full(),blocked_public=True),BLOCKED,TARGET))
    def test_comment_not_entry(self):self.assertFalse(check_profile(self.probe('# '+self.full().replace('\n','\n# ')),BLOCKED,TARGET))
    def test_malformed_port_not_matching_hostname(self):self.assertFalse(check_profile(self.probe(self.full().replace(BLOCKED[0],BLOCKED[0]+':443')),BLOCKED,TARGET))
    def test_no_zero_mapping_not_exception(self):self.assertFalse(check_profile(self.probe(self.full().replace('0.0.0.0','127.0.0.1')),BLOCKED,TARGET))
    def test_aliases_case_and_comments(self):
        text='0.0.0.0 '+' '.join(h.upper() for h in BLOCKED)+' # comment\n';self.assertTrue(check_profile(self.probe(text),BLOCKED,TARGET))
    def test_normal_sink_resolution_remains_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'hosts';p.write_text('')
            def resolver(h,*args):return [(2,1,6,'',('1.1.1.1' if h==TARGET else '0.0.0.0',0))]
            self.assertTrue(check_profile(resolution_probe(BLOCKED,TARGET,p,resolver,'win32'),BLOCKED,TARGET))
    def test_oversized_and_null_hosts_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'hosts'
            for data in ((self.full()+'\0').encode(),self.full().encode()+b'#'*1048577):
                p.write_bytes(data);self.assertEqual(explicit_zero_sink_hosts(p,BLOCKED),set())
    def test_missing_file_refused(self):self.assertEqual(explicit_zero_sink_hosts(Path('/nonexistent-fixture-hosts'),BLOCKED),set())
    def test_ordinary_oserror_not_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'hosts';p.write_text(self.full())
            def resolver(h,*args):raise OSError(11004,'not_a_gaierror')
            self.assertFalse(check_profile(resolution_probe(BLOCKED,TARGET,p,resolver,'win32'),BLOCKED,TARGET))
if __name__=='__main__':unittest.main()
