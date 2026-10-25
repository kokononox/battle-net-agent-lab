import copy,hashlib,json,pathlib,struct,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'app'))
from policy import *
from state import Store,locked,inspect_file
from legacy import stage_blacklist,stage_whitelist
from cli import handle

class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
        self.identities={path_key(r'C:\Games\Wow.exe'):'a'*64,path_key(r'C:\Agent\Agent.exe'):'b'*64}
        def inspector(path):return dict(path=windows_path(path),sha256=self.identities[path_key(path)])
        self.inspector=inspector;self.store=Store(self.root/'state',inspector)
    def tearDown(self):self.temp.cleanup()
    def generation(self):return self.store.read()['config']['generation']
    def register(self):return self.store.register([r'C:\Games\Wow.exe',r'C:\Agent\Agent.exe'],self.generation())
    def test_register_multiple_exes_same_basename_not_required(self):
        s=self.register();self.assertEqual(len(s['config']['programs']),2)
    def test_duplicate_paths_case_insensitive(self):
        self.store.register([r'C:\Games\Wow.exe',r'c:\games\WOW.EXE'],0)
        self.assertEqual(len(self.store.read()['config']['programs']),1)
    def test_stale_edit_cannot_overwrite(self):
        self.register();before=self.store.file.read_bytes()
        with self.assertRaises(PolicyError):self.store.configure('blacklist_only',[],0)
        self.assertEqual(self.store.file.read_bytes(),before)
    def test_changed_binary_reselect_required(self):
        self.register();self.identities[path_key(r'C:\Games\Wow.exe')]='c'*64
        with self.assertRaisesRegex(PolicyError,'binary_changed'):self.store.preview()
        self.store.register([r'C:\Games\Wow.exe'],self.generation());self.assertFalse(self.store.preview()['activation_allowed'])
    def test_add_entry_to_two_programs_then_remove_one(self):
        s=self.register();a,b=[p['id'] for p in s['config']['programs']]
        self.store.add_blacklist([a,b],'8.8.8.8','TCP',443,self.generation())
        self.assertEqual(len(self.store.preview()['rules']),2)
        self.store.remove([a],self.generation());p=self.store.preview();self.assertEqual(len(p['rules']),1);self.assertEqual(p['rules'][0]['spec']['program_id'],b)
    def test_removing_program_keeps_whitelist(self):
        s=self.register();a=s['config']['programs'][0]['id'];self.store.configure('vpn_allowlist',['8.8.8.8'],self.generation())
        self.store.remove([a],self.generation());self.assertEqual(self.store.read()['config']['whitelist'],['8.8.8.8'])
    def test_remove_last_program_cleans_only_its_entries(self):
        s=self.store.register([r'C:\Games\Wow.exe'],0);a=s['config']['programs'][0]['id'];self.store.add_blacklist([a],'8.8.8.8','TCP',443,self.generation())
        self.store.remove([a],self.generation());self.assertEqual(self.store.read()['config']['blacklist'],[])
    def test_invalid_whitelist_not_partially_saved(self):
        self.register();before=self.store.file.read_bytes()
        with self.assertRaises(PolicyError):self.store.configure('vpn_allowlist',['8.8.8.8','8.8.8.9/24'],self.generation())
        self.assertEqual(self.store.file.read_bytes(),before)
    def test_whitelist_type_not_silently_skipped(self):
        self.register()
        with self.assertRaises(PolicyError):self.store.configure('vpn_allowlist',['8.8.8.8',7],self.generation())
    def test_exclusive_store_lock(self):
        with locked(self.store.lock):
            with self.assertRaises(PolicyError):self.store.read()
    def test_corrupt_config_is_not_reset(self):
        self.store.read();self.store.file.write_text('{bad');before=self.store.file.read_bytes()
        with self.assertRaises(PolicyError):self.store.read()
        self.assertEqual(self.store.file.read_bytes(),before)
    def test_legacy_blacklist_stages_no_deletion(self):
        old=self.root/'legacy.json';raw=dict(program=r'C:\Games\Wow.exe',program_sha256='a'*64,text='8.8.8.8:443 TCP\n[2606:4700:4700::1111]:53 UDP',phase='applied');old.write_text(json.dumps(raw))
        before=old.read_bytes();s=stage_blacklist(self.store,old,0)
        self.assertEqual(len(s['config']['blacklist']),2);self.assertEqual(old.read_bytes(),before);self.assertTrue(s['config']['legacy_imports'])
        self.assertFalse(self.store.preview()['activation_allowed'])
    def test_legacy_domains_reject_whole_import(self):
        self.register();old=self.root/'white.json';old.write_text(json.dumps(dict(schema='sstp-allowlist-config-1',domains=['example.com'],ip_addresses=['8.8.8.8'])))
        before=self.store.file.read_bytes()
        with self.assertRaisesRegex(PolicyError,'domains'):stage_whitelist(self.store,old,self.generation())
        self.assertEqual(self.store.file.read_bytes(),before)
    def test_legacy_bad_line_rejects_whole_import(self):
        old=self.root/'bad.json';old.write_text(json.dumps(dict(program=r'C:\Games\Wow.exe',text='8.8.8.8:443 TCP\nbad-line')))
        self.store.read();before=self.store.file.read_bytes()
        with self.assertRaises(PolicyError):stage_blacklist(self.store,old,self.generation())
        self.assertEqual(self.store.file.read_bytes(),before)
    def test_legacy_changed_program_not_adopted(self):
        old=self.root/'old.json';old.write_text(json.dumps(dict(program=r'C:\Games\Wow.exe',program_sha256='e'*64,text='8.8.8.8:443 TCP')))
        with self.assertRaisesRegex(PolicyError,'binary_changed'):stage_blacklist(self.store,old,0)
    def test_mutation_operations_are_gated(self):
        for action in ('apply','restore','hosts_apply'):
            with self.assertRaisesRegex(PolicyError,'disabled'):handle(self.store,action,{},self.root)
    def test_symlink_state_refused(self):
        self.store.read();other=self.root/'other.json';other.write_bytes(self.store.file.read_bytes());self.store.file.unlink()
        try:self.store.file.symlink_to(other)
        except OSError:self.skipTest('symlink not available')
        with self.assertRaises(PolicyError):self.store.read()
    def test_pe_header_hashing_and_text_file_rejected(self):
        exe=self.root/'fixture.exe';data=bytearray(128);data[:2]=b'MZ';struct.pack_into('<I',data,60,64);data[64:68]=b'PE\0\0';exe.write_bytes(data)
        self.assertEqual(inspect_file(exe),hashlib.sha256(data).hexdigest())
        exe.write_text('not a PE')
        with self.assertRaises(PolicyError):inspect_file(exe)
    def test_global_whitelist_preview_without_registered_program(self):
        self.store.configure('vpn_allowlist',['8.8.8.8'],0);plan=self.store.preview();self.assertEqual(len(plan['rules']),2)
if __name__=='__main__':unittest.main()
