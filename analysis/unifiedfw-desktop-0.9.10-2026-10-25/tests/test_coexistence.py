from pathlib import Path
import copy,ipaddress,json,random,sys,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'lab'),str(ROOT/'app')]
from coexistence import build_coexistence_request,classify_coexistence,PHASES,EXPECTED,SCOPE
from policy import new_config,compile_plan,program_id,blacklist_entry,decision,reconcile_registry,digest

def request(address='9.9.9.9'):
    return build_coexistence_request(address,39443,root=Path('C:/Fixture'),inspector=lambda p:'a'*64)

def report():
    r=dict(scope=SCOPE,route_checks_ok=True,route_check_count=85,restore_verified=True,firewall_mutation_attempted=True,errors=[],phases=[]);counter=0
    for name,blocked in EXPECTED.items():
        p=dict(name=name,restored=True,baseline_strict_equal=True,during=[],after_restore=[])
        for stage in ('during','after_restore'):
            for role in ('A','B','REF'):
                for round in range(3):
                    counter+=1;good=not(stage=='during' and role in blocked)
                    p[stage].append(dict(role=role,round=round,probe_valid=True,connected=good,handshake_ok=good,request_id=f'{counter:032x}'))
        r['phases'].append(p)
    return r

class CoexistenceTests(unittest.TestCase):
    def test_fixed_phase_shapes(self):
        q=request();self.assertEqual([len(p['request']['plan']['rules']) for p in q['phases']],[0,2,1,1,2,3]);self.assertEqual([p['name'] for p in q['phases']],[p[0] for p in PHASES])
    def test_projection_is_only_two_images_one_endpoint_port(self):
        q=request()
        for phase in q['phases']:
            p=phase['request']['plan'];self.assertFalse(p['activation_allowed']);self.assertEqual(p['lab_scope'],SCOPE)
            for r in p['rules']:
                s=r['spec'];self.assertIn(s['program'],[p['path'] for p in q['programs']]);self.assertEqual(s['remote_addresses'],['9.9.9.9/32']);self.assertEqual((s['action'],s['protocol'],s['port']),('Block','TCP',39443));self.assertFalse(s['override_block_rules']);self.assertEqual(s['interface_type'],'RemoteAccess' if r['component']=='whitelist' else 'Any')
    def test_full_compiler_projection_agrees_with_independent_membership_oracle(self):
        for ip in ('1.1.1.1','8.8.8.8','9.9.9.9','1.0.0.1','93.184.216.34'):
            q=request(ip)
            for phase,(name,allowed,bl) in zip(q['phases'],PHASES):
                for program in q['programs']:
                    matches=[r for r in phase['request']['plan']['rules'] if r['spec']['program_id']==program['id'] and any(ipaddress.ip_address(ip) in ipaddress.ip_network(a) for a in r['spec']['remote_addresses'])]
                    self.assertEqual(bool(matches),(not allowed) or program['role'] in bl)
    def test_rule_names_are_owned_content_derived_and_component_separated(self):
        for phase in request()['phases']:
            plan=phase['request']['plan'];seen=set()
            for r in plan['rules']:
                self.assertEqual(r['name'],f"UnifiedFW-{plan['owner']}-{r['component']}-{digest(dict(component=r['component'],spec=r['spec']))[:24]}");self.assertNotIn(r['name'],seen);seen.add(r['name'])
    def test_allowed_phase_creates_no_allow_rule(self):
        q=request();self.assertEqual(q['phases'][0]['request']['plan']['rules'],[]);self.assertTrue(all(r['spec']['action']=='Block' for p in q['phases'] for r in p['request']['plan']['rules']))
    def test_no_external_probe_needed_for_sentinel(self):
        q=request('8.8.8.8');self.assertEqual(q['address'],'8.8.8.8');self.assertNotIn('8.8.4.4',json.dumps([r['spec']['remote_addresses'] for p in q['phases'] for r in p['request']['plan']['rules']]))
    def test_many_exe_blacklist_edits_preserve_whitelist(self):
        c=new_config();c.update(mode='vpn_allowlist',whitelist=['8.8.8.0/24','2606:4700:4700::/48'])
        c['programs']=[dict(id=program_id(f'C:/Fixture/App{i}.exe'),path=f'C:\\Fixture\\App{i}.exe',sha256='a'*64,enabled=True) for i in range(32)]
        old=compile_plan(c,'b'*32);wl=[r for r in old['rules'] if r['component']=='whitelist']
        c['blacklist']=[blacklist_entry([p['id'] for p in c['programs']],'8.8.8.8','TCP',443)]
        new=compile_plan(c,'b'*32);self.assertEqual([r for r in new['rules'] if r['component']=='whitelist'],wl)
        diff=reconcile_registry(old['rules'],new['rules'],'b'*32,components=('blacklist',));self.assertEqual(len(diff['create']),32);self.assertEqual(diff['remove'],[]);self.assertEqual(diff['preserved_other_components'],wl)
    def test_whitelist_edit_preserves_all_blacklist_specs(self):
        c=new_config();c.update(mode='vpn_allowlist',whitelist=['8.8.8.8']);pid=program_id('C:/Fixture/App.exe');c['programs']=[dict(id=pid,path='C:\\Fixture\\App.exe',sha256='a'*64,enabled=True)];c['blacklist']=[blacklist_entry([pid],'8.8.8.8','TCP',443)]
        old=compile_plan(c,'b'*32);c['whitelist']=['9.9.9.9'];new=compile_plan(c,'b'*32)
        self.assertEqual([r for r in old['rules'] if r['component']=='blacklist'],[r for r in new['rules'] if r['component']=='blacklist'])
        diff=reconcile_registry(old['rules'],new['rules'],'b'*32,components=('whitelist',));self.assertTrue(all(r['component']=='whitelist' for key in ('create','remove') for r in diff[key]));self.assertEqual(len(diff['preserved_other_components']),1)
    def test_randomized_shared_decisions_whitelist_exempts_owned_blacklist_inside_vpn(self):
        rng=random.Random(700);c=new_config();c.update(mode='vpn_allowlist',whitelist=['8.8.8.0/24']);pid=program_id('C:/Fixture/App.exe');c['programs']=[dict(id=pid,path='C:\\Fixture\\App.exe',sha256='a'*64,enabled=True)];c['blacklist']=[blacklist_entry([pid],'8.8.8.64-8.8.8.127','TCP',443)]
        for _ in range(200):
            octet=rng.randrange(256);port=rng.choice([443,444]);protocol=rng.choice(['TCP','UDP']);r=decision(c,pid,f'8.8.8.{octet}',port,protocol,'vpn');self.assertFalse(r['outcome']=='block')
    def test_narrow_good_report_only(self):
        r=classify_coexistence(report());self.assertEqual(r['outcome'],'passed');self.assertTrue(r['scoped_whitelist_projection_tested']);self.assertFalse(r['global_whitelist_tested']);self.assertFalse(r['vpn_route_verified']);self.assertFalse(r['no_leak_certified'])
    def test_missing_or_changed_route_guard_is_not_passed(self):
        for key,val in [('route_checks_ok',False),('route_check_count',0),('route_check_count',True),('scope','global'),('restore_verified',False),('firewall_mutation_attempted',False),('errors',['error'])]:
            r=report();r[key]=val;self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
    def test_each_blocked_image_connection_invalidates_pass(self):
        for p in report()['phases']:
            for role in EXPECTED[p['name']]:
                r=report();phase=next(x for x in r['phases'] if x['name']==p['name']);row=next(x for x in phase['during'] if x['role']==role);row.update(connected=True,handshake_ok=False);self.assertEqual(classify_coexistence(r)['outcome'],'failed')
    def test_controls_and_post_restore_must_work(self):
        for phaseIndex in range(len(EXPECTED)):
            for stage in ('during','after_restore'):
                r=report();row=next(x for x in r['phases'][phaseIndex][stage] if x['role']=='REF');row.update(connected=False,handshake_ok=False);self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
    def test_wrong_order_partial_invalid_process_replay_rejected(self):
        for kind in ('order','missing','invalid_process','replay'):
            r=report()
            if kind=='order':r['phases'][1],r['phases'][2]=r['phases'][2],r['phases'][1]
            if kind=='missing':r['phases'].pop()
            if kind=='invalid_process':r['phases'][2]['during'][0]['probe_valid']=False
            if kind=='replay':r['phases'][3]['during'][0]['request_id']=r['phases'][0]['during'][0]['request_id']
            self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
    def test_foreign_owner_reconcile_refused(self):
        q=request();rules=q['phases'][-1]['request']['plan']['rules'];wrong=copy.deepcopy(rules);wrong[0]['owner']='f'*32
        with self.assertRaisesRegex(ValueError,'ownership'):reconcile_registry(wrong,rules,q['phases'][-1]['request']['plan']['owner'])
    def test_test_endpoint_rejects_domains_loopback_private_low_port(self):
        for host,port in [('example.com',39443),('127.0.0.1',39443),('192.168.1.1',39443),('9.9.9.9',443)]:
            with self.assertRaises(ValueError):build_coexistence_request(host,port)
if __name__=='__main__':unittest.main()
