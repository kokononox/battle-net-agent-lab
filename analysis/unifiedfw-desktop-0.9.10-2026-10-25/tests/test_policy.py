import copy,ipaddress,json,pathlib,random,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'app'))
from policy import *
OWNER='a'*32

def program(path):return dict(id=program_id(path),path=path,sha256='1'*64,enabled=True)
def config():
    c=new_config();c['programs']=[program(r'C:\Games\Wow.exe'),program(r'C:\Launcher\Agent.exe')];return c

class PolicyTests(unittest.TestCase):
    def test_accept_any_exe_name(self):
        for path in (r'C:\Games\Wow.exe',r'C:\Launcher\Agent.exe',r'D:\Apps\My Tool.EXE'):
            self.assertEqual(windows_path(path),path)
    def test_path_alias_case_and_slashes(self):
        self.assertEqual(program_id('c:/GAMES/Wow.exe'),program_id(r'C:\games\wow.EXE'))
    def test_reject_ambiguous_paths(self):
        for path in ('Wow.exe',r'C:Wow.exe',r'\\server\share\Wow.exe',r'C:\x\..\Wow.exe',r'C:\x\wow.exe:stream',r'C:\CON\wow.exe',r'C:\x\wow.exe ',r'C:\x\*.exe',r'C:\x\a.dll'):
            with self.subTest(path=path),self.assertRaises(PolicyError):windows_path(path)
    def test_interval_forms(self):
        self.assertEqual(interval('8.8.8.0/24'),interval('8.8.8.0-8.8.8.255'))
        self.assertEqual(interval('2606:4700::/32').version,6)
    def test_bad_ranges(self):
        for target in ('8.8.8.1/24','8.8.8.0/024','8.8.8.0/255.255.255.0','8.8.8.9-8.8.8.1','8.8.8.8-2606:4700::1','1.1.1.1-11.0.0.1','::/0','8.8.8.8%1','::ffff:8.8.8.8','192.0.2.0/24','2001:db8::/32'):
            with self.subTest(target=target),self.assertRaises(PolicyError):interval(target)
    def test_overlap_merge_and_complement_exact(self):
        allow=[interval('8.8.8.0/25'),interval('8.8.8.64-8.8.8.200')]
        merged=merge(allow);self.assertEqual(len(merged),1)
        deny=complement(allow,4)
        self.assertEqual(sum(i.high-i.low+1 for i in merged+deny),1<<32)
        self.assertFalse(any(a.overlaps(b) for a in merged for b in deny))
    def test_empty_full_and_ipv6_complement(self):
        for version,bits in ((4,32),(6,128)):
            full=Interval(version,0,(1<<bits)-1)
            self.assertEqual(complement([],version),[full]);self.assertEqual(complement([full],version),[])
            self.assertEqual(len(cidrs([full])),2)
    def test_multi_program_plan_does_not_replace_first(self):
        c=config();p1,p2=[p['id'] for p in c['programs']]
        c['blacklist']=[blacklist_entry([p1,p2],'8.8.8.8','TCP',443)]
        plan=compile_plan(c,OWNER)
        self.assertEqual({r['spec']['program_id'] for r in plan['rules']},{p1,p2});self.assertEqual(len(plan['rules']),2)
        self.assertFalse(plan['activation_allowed'])
    def test_shared_and_per_program_entries(self):
        c=config();a,b=[p['id'] for p in c['programs']]
        c['blacklist']=[blacklist_entry([a,b],'8.8.8.0/24','TCP',443),blacklist_entry([a],'8.8.8.8','UDP',53)]
        self.assertEqual(decision(c,a,'8.8.8.8',53,'UDP','outside')['outcome'],'block')
        self.assertEqual(decision(c,b,'8.8.8.8',53,'UDP','outside')['outcome'],'eligible_not_effectively_verified')
    def test_whitelist_exempts_only_owned_deny_inside_vpn(self):
        c=config();a,b=[p['id'] for p in c['programs']];c.update(mode='vpn_allowlist',whitelist=['8.8.8.0/24'])
        c['blacklist']=[blacklist_entry([a],'8.8.8.8','TCP',3724)]
        for pid,proto,port,expected in ((a,'TCP',3724,'eligible_not_effectively_verified'),(b,'TCP',3724,'eligible_not_effectively_verified'),(a,'UDP',3724,'eligible_not_effectively_verified'),(a,'TCP',443,'eligible_not_effectively_verified')):
            with self.subTest(pid=pid,proto=proto,port=port):self.assertEqual(decision(c,pid,'8.8.8.8',port,proto,'vpn')['outcome'],expected)
        self.assertEqual(len(compile_plan(c,OWNER)['overlaps']),1)
    def test_outside_whitelist_block(self):
        c=config();p=c['programs'][0]['id'];c.update(mode='vpn_allowlist',whitelist=['8.8.8.8'])
        self.assertIn('outside_vpn_whitelist',decision(c,p,'1.1.1.1',443,'TCP','vpn')['reasons'])
    def test_vpn_only_is_not_killswitch(self):
        c=config();p=c['programs'][0]['id'];c.update(mode='vpn_allowlist',whitelist=['8.8.8.8'])
        self.assertEqual(decision(c,p,'1.1.1.1',443,'TCP','outside')['outcome'],'eligible_not_effectively_verified')
    def test_unknown_route_full_isolation_block(self):
        c=config();p=c['programs'][0]['id'];c.update(mode='full_isolation',whitelist=['8.8.8.8'])
        for route in ('unknown','outside'):self.assertEqual(decision(c,p,'8.8.8.8',443,'TCP',route)['outcome'],'block')
        self.assertIn('sstp_transport_exceptions_unresolved',compile_plan(c,OWNER)['blockers'])
    def test_duplicate_program_rejected(self):
        c=config();c['programs'].append(copy.deepcopy(c['programs'][0]))
        with self.assertRaises(PolicyError):validate(c)
    def test_orphan_rule_rejected(self):
        c=config();c['blacklist']=[blacklist_entry(['0'*24],'8.8.8.8','TCP',443)]
        with self.assertRaises(PolicyError):validate(c)
    def test_duplicate_output_rules_are_deduplicated(self):
        c=config();a=c['programs'][0]['id'];e=blacklist_entry([a],'8.8.8.8','TCP',443);f=copy.deepcopy(e);f['id']='f'*24;c['blacklist']=[e,f]
        self.assertEqual(len(compile_plan(c,OWNER)['rules']),1)
    def test_partial_restore_plan_preserves_other_module(self):
        c=config();c.update(mode='vpn_allowlist',whitelist=['8.8.8.8']);c['blacklist']=[blacklist_entry([c['programs'][0]['id']],'1.1.1.1','TCP',443)]
        old=compile_plan(c,OWNER)['rules'];diff=reconcile_registry(old,[],OWNER,('blacklist',))
        self.assertTrue(all(r['component']=='blacklist' for r in diff['remove']))
        self.assertEqual(len(diff['preserved_other_components']),2);self.assertTrue(diff['dry_run_only'])
    def test_foreign_or_modified_rule_not_adopted(self):
        c=config();c['blacklist']=[blacklist_entry([c['programs'][0]['id']],'8.8.8.8','TCP',443)];rules=compile_plan(c,OWNER)['rules']
        bad=copy.deepcopy(rules);bad[0]['spec']['port']=80
        with self.assertRaises(PolicyError):reconcile_registry(bad,[],OWNER)
        with self.assertRaises(PolicyError):reconcile_registry(rules,[],'b'*32)
    def test_unchanged_snapshot_stable_names(self):
        c=config();c['blacklist']=[blacklist_entry([c['programs'][0]['id']],'8.8.8.8','TCP',443)]
        a=compile_plan(c,OWNER);c['generation']+=1;b=compile_plan(c,OWNER)
        self.assertEqual(a['rules'],b['rules']);self.assertNotEqual(a['config_digest'],b['config_digest'])
    def test_disabled_program_not_compiled(self):
        c=config();p=c['programs'][0];c['blacklist']=[blacklist_entry([p['id']],'8.8.8.8','TCP',443)];p['enabled']=False
        self.assertEqual(compile_plan(c,OWNER)['rules'],[])
    def test_bool_port_rejected(self):
        c=config();c['blacklist']=[blacklist_entry([c['programs'][0]['id']],'8.8.8.8','TCP',True)]
        with self.assertRaises(PolicyError):validate(c)
    def test_registry_duplicate_not_accepted(self):
        c=config();c['blacklist']=[blacklist_entry([c['programs'][0]['id']],'8.8.8.8','TCP',443)];r=compile_plan(c,OWNER)['rules']
        with self.assertRaises(PolicyError):reconcile_registry(r+r,[],OWNER)
    def test_legacy_migration_never_authorizes_apply(self):
        c=config();c['legacy_imports']=[dict(kind='blacklist',rules_may_still_be_active=True)]
        p=compile_plan(c,OWNER);self.assertFalse(p['activation_allowed']);self.assertTrue(any('legacy_rules_may' in s for s in p['blockers']))
    def test_differential_small_universe(self):
        c=config();a,b=[p['id'] for p in c['programs']];c.update(mode='vpn_allowlist',whitelist=['8.8.8.64/26'])
        c['blacklist']=[blacklist_entry([a],'8.8.8.80-8.8.8.95','TCP',443)]
        for offset in range(256):
            for pid in (a,b):
                got=decision(c,pid,f'8.8.8.{offset}',443,'TCP','vpn')['outcome']=='block'
                expected=not (64<=offset<=127)
                self.assertEqual(got,expected)
    def test_generated_complement_membership(self):
        c=config();c.update(mode='vpn_allowlist',whitelist=['8.8.8.64/26','2606:4700::/32'])
        plan=compile_plan(c,OWNER)
        networks=[ip.ip_network(n) for r in plan['rules'] if r['component']=='whitelist' for n in r['spec']['remote_addresses']]
        for address,blocked in [('8.8.8.63',True),('8.8.8.64',False),('8.8.8.127',False),('8.8.8.128',True),('2606:4700::1',False),('2001:4860::1',True)]:
            x=ip.ip_address(address);self.assertEqual(any(x in n for n in networks if n.version==x.version),blocked)
if __name__=='__main__':unittest.main()
