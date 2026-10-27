import ast
import copy
import importlib.util
import json
from pathlib import Path
import random
import unittest

ROOT = Path('/data/ufw-app-profile-plan-v01')
spec = importlib.util.spec_from_file_location('profile_plan', ROOT / 'source/app_profile_plan.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
compile_plan = module.compile_profile_plan


def fixture():
    return dict(schema='ufw-app-profiles-01', generation=1, active_profile_id='installer', profiles=[
        dict(id=kind, kind=kind, programs=[dict(id=kind, path=fr'C:\Fixture\{kind}.exe', sha256='a' * 64)],
             grants=[dict(program_id=kind, ip=ip, protocol='TCP', port=443)])
        for kind, ip in [('installer', '192.0.2.10'), ('browser', '192.0.2.20'), ('game', '2001:db8::30')]
    ])


def grant_match(plan, profile_id, path, pin, ip, protocol, port, verified_sstp):
    # Independent offline predicate over draft edges; NOT an implementation of native enforcement.
    return verified_sstp and any(t['profile_id'] == profile_id and t['program_path'].casefold() == path.casefold()
        and t['unverified_program_sha256'] == pin and t['remote_address'] == ip
        and t['protocol'] == protocol and t['remote_port'] == port for t in plan['application_templates'])


class PlanTests(unittest.TestCase):
    def rejected(self, config, code=None):
        p = compile_plan(config)
        self.assertFalse(p['input_valid'])
        self.assertEqual(p['application_templates'], [])
        self.assertIsNone(p['normalized_config'])
        self.assertIsNone(p['config_digest'])
        self.assertFalse(p['ready_for_apply'])
        self.assertFalse(p['plan_executable'])
        if code:
            self.assertEqual(p['code'], code)
        return p

    def test_three_modes_and_only_one_active(self):
        for selected in ('browser', 'game', 'installer'):
            c = fixture(); c['active_profile_id'] = selected
            p = compile_plan(c)
            self.assertTrue(p['input_valid'])
            self.assertEqual(len(p['application_templates']), 1)
            self.assertEqual(p['application_templates'][0]['program_id'], selected)
            self.assertFalse(p['inactive_profile_rules_included'])

    def test_active_program_cannot_use_other_profile_destinations(self):
        p = compile_plan(fixture())
        self.assertTrue(grant_match(p, 'installer', r'C:\Fixture\installer.exe', 'a'*64, '192.0.2.10', 'TCP', 443, True))
        for args in [('installer',r'C:\Fixture\browser.exe','a'*64,'192.0.2.10','TCP',443,True),
                     ('installer',r'C:\Fixture\installer.exe','a'*64,'192.0.2.20','TCP',443,True),
                     ('installer',r'C:\Fixture\installer.exe','a'*64,'192.0.2.10','TCP',443,False),
                     ('installer',r'C:\Fixture\installer.exe','b'*64,'192.0.2.10','TCP',443,True),
                     ('browser',r'C:\Fixture\browser.exe','a'*64,'192.0.2.20','TCP',443,True)]:
            self.assertFalse(grant_match(p, *args))

    def test_no_cartesian_product_between_dependencies(self):
        c=fixture();p=c['profiles'][0];p['programs'].append(dict(id='helper',path=r'C:\Fixture\helper.exe',sha256='b'*64));p['grants'].append(dict(program_id='helper',ip='192.0.2.11',protocol='UDP',port=5000))
        out=compile_plan(c);self.assertTrue(out['input_valid']);self.assertEqual(len(out['application_templates']),2)
        self.assertFalse(grant_match(out,'installer',r'C:\Fixture\installer.exe','a'*64,'192.0.2.11','UDP',5000,True))
        self.assertFalse(grant_match(out,'installer',r'C:\Fixture\helper.exe','b'*64,'192.0.2.10','TCP',443,True))
        self.assertFalse(grant_match(out,'installer',r'C:\Fixture\child.exe','a'*64,'192.0.2.10','TCP',443,True))

    def test_disabled_templates_require_fresh_binding_and_identity(self):
        p=compile_plan(fixture())
        for t in p['application_templates']:
            self.assertFalse(t['initial_enabled']);self.assertTrue(t['trusted_native_identity_required'])
            self.assertNotIn('interface_alias',t);self.assertNotIn('Any',t.values());self.assertEqual(t['sstp_binding_token'],'REQUIRES_FRESH_VERIFIED_SSTP_BINDING')
        for k in ['application_identity_verified','endpoint_approval_verified','baseline_verified_by_this_compiler','capture_is_approval','mode_switch_atomic','native_executor_implemented','journal_mutation_requested','firewall_mutation_requested','plan_executable','ready_for_apply','no_leak_certified','fingerprint_prevention_certified','automatic_child_process_permission','external_dns_exception_requested','physical_adapter_alias_or_index_used','firewall_disable_requested']:
            self.assertIs(p[k],False,k)
        self.assertEqual(len(p['blockers']),11)

    def test_generation_types(self):
        for value in [True,False,0,-1,1.5,'1',2147483648,None]:
            with self.subTest(value=value):
                c=fixture();c['generation']=value;self.rejected(c,'profile_plan_generation')

    def test_single_selection_shape(self):
        for value in [None,[],['installer','browser'],'Any','INSTALLER','missing','*',True]:
            with self.subTest(value=value):
                c=fixture();c['active_profile_id']=value;self.rejected(c)

    def test_unknown_fields_are_not_approval(self):
        for target in ['top','profile','program','grant']:
            c=fixture();obj={'top':c,'profile':c['profiles'][0],'program':c['profiles'][0]['programs'][0],'grant':c['profiles'][0]['grants'][0]}[target]
            for key in ['approved','execution_authorized','auto_allow_children','service','interface_alias']:
                bad=copy.deepcopy(c);dst={'top':bad,'profile':bad['profiles'][0],'program':bad['profiles'][0]['programs'][0],'grant':bad['profiles'][0]['grants'][0]}[target];dst[key]=True;self.rejected(bad,'profile_plan_shape')

    def test_missing_fields(self):
        for field in list(fixture()):
            c=fixture();del c[field];self.rejected(c,'profile_plan_shape')

    def test_profiles_and_programs_must_be_bounded_nonempty_arrays(self):
        for key in ['profiles','programs','grants']:
            for value in [None,{},'',[],True]:
                c=fixture();obj=c if key=='profiles' else c['profiles'][0];obj[key]=value;self.rejected(c)
        c=fixture();c['profiles']=[copy.deepcopy(c['profiles'][0]) for _ in range(9)];self.rejected(c,'profile_plan_profile_count')
        c=fixture();c['profiles'][0]['programs']*=17;self.rejected(c,'profile_plan_program_count')
        c=fixture();c['profiles'][0]['grants']*=257;self.rejected(c,'profile_plan_grant_count')

    def test_duplicate_profile_and_programs(self):
        c=fixture();c['profiles'][1]['id']='installer';self.rejected(c,'profile_plan_duplicate_profile')
        for by_path in [False,True]:
            c=fixture();p=c['profiles'][0];q=copy.deepcopy(p['programs'][0])
            if by_path:q.update(id='different',path=q['path'].upper())
            p['programs'].append(q);self.rejected(c,'profile_plan_duplicate_program')

    def test_unused_or_unknown_program(self):
        c=fixture();c['profiles'][0]['grants'][0]['program_id']='unknown';self.rejected(c,'profile_plan_unknown_program')
        c=fixture();c['profiles'][0]['programs'].append(dict(id='unused',path=r'C:\Fixture\unused.exe',sha256='c'*64));self.rejected(c,'profile_plan_program_without_grant')

    def test_duplicate_grant_normalizes_ipv6(self):
        c=fixture();c['profiles'][0]['grants']*=2;self.rejected(c,'profile_plan_duplicate_grant')
        c=fixture();g=c['profiles'][0]['grants'][0];g['ip']='2001:db8::1';c['profiles'][0]['grants'].append(dict(g,ip='2001:0DB8:0:0:0:0:0:1'));self.rejected(c,'profile_plan_duplicate_grant')

    def test_no_broad_destination_or_hostname(self):
        for value in ['Any','*','example.invalid','https://example.invalid','192.0.2.0/24','192.0.2.10/32','192.0.2.1-192.0.2.20','127.0.0.1','0.0.0.0','0.1.2.3','224.0.0.1','255.255.255.255','169.254.1.1','::','::1','ff02::1','fe80::1','fec0::1','fe80::1%11','::ffff:192.0.2.1','[2001:db8::1]','127.1','192.0.002.1','192.0.2.1 ',None,1]:
            with self.subTest(value=value):
                c=fixture();c['profiles'][0]['grants'][0]['ip']=value;self.rejected(c)

    def test_explicit_private_ip_is_not_broad_lan_exemption(self):
        c=fixture();c['profiles'][0]['grants'][0]['ip']='10.20.30.40';p=compile_plan(c);self.assertTrue(p['input_valid']);self.assertEqual(p['application_templates'][0]['remote_address'],'10.20.30.40')

    def test_protocol_and_port_are_exact(self):
        for proto in ['Any','tcp','ICMP','TCP,UDP',None,1,True]:
            c=fixture();c['profiles'][0]['grants'][0]['protocol']=proto;self.rejected(c,'profile_plan_exact_protocol')
        for port in ['443','Any','80-443',0,65536,True,False,None,443.0]:
            c=fixture();c['profiles'][0]['grants'][0]['port']=port;self.rejected(c,'profile_plan_exact_port')
        for proto,port in [('TCP',1),('UDP',65535)]:
            c=fixture();c['profiles'][0]['grants'][0].update(protocol=proto,port=port);self.assertTrue(compile_plan(c)['input_valid'])

    def test_path_shape_and_shared_host_rejected(self):
        for value in ['Any','*',r'browser.exe',r'.\browser.exe',r'c:\Fixture\browser.exe',r'\\server\share\browser.exe',r'\\?\C:\Fixture\browser.exe',r'%SystemRoot%\browser.exe','C:/Fixture/browser.exe',r'C:\Fixture\..\browser.exe',r'C:\Fixture\x.exe:stream',r'C:\Fixture\x.exe ',r'C:\Fixture.\x.exe',r'C:\Fixture\CON.exe',r'C:\Fixture\x.dll',r'C:\Fixture\*.exe',r'C:\Fixture\svchost.exe',r'C:\Fixture\rundll32.exe',r'C:\Fixture\dllhost.exe','C:\\Fixture\\\nx.exe',None,True]:
            with self.subTest(value=value):
                c=fixture();c['profiles'][0]['programs'][0]['path']=value;self.rejected(c)

    def test_hash_is_data_not_proof(self):
        for value in [None,True,'a'*63,'a'*65,'A'*64,'g'*64]:
            c=fixture();c['profiles'][0]['programs'][0]['sha256']=value;self.rejected(c,'profile_plan_program_sha256')
        p=compile_plan(fixture());self.assertFalse(p['application_identity_verified'])

    def test_input_not_modified_and_output_not_alias(self):
        c=fixture();before=copy.deepcopy(c);p=compile_plan(c);self.assertEqual(c,before);c['profiles'][0]['grants'][0]['ip']='192.0.2.99';self.assertNotEqual(p['normalized_config'],c)

    def test_order_independent_digest(self):
        c=fixture();p=compile_plan(c);c['profiles'].reverse();self.assertEqual(p['config_digest'],compile_plan(c)['config_digest'])

    def test_digest_changes_on_mode_and_content_and_generation(self):
        c=fixture();digest=compile_plan(c)['config_digest']
        for field in ['generation','active','path','hash','ip','protocol','port','inactive_grant']:
            changed=copy.deepcopy(c)
            if field=='generation':changed['generation']+=1
            elif field=='active':changed['active_profile_id']='browser'
            elif field=='path':changed['profiles'][0]['programs'][0]['path']=r'C:\Fixture\new-installer.exe'
            elif field=='hash':changed['profiles'][0]['programs'][0]['sha256']='b'*64
            elif field=='ip':changed['profiles'][0]['grants'][0]['ip']='192.0.2.11'
            elif field=='protocol':changed['profiles'][0]['grants'][0]['protocol']='UDP'
            elif field=='port':changed['profiles'][0]['grants'][0]['port']=80
            else:changed['profiles'][1]['grants'][0]['port']=80
            self.assertNotEqual(compile_plan(changed)['config_digest'],digest)

    def test_remove_and_switch_do_not_union_old_rules(self):
        c=fixture();old=compile_plan(c);c['generation']+=1;c['active_profile_id']='browser';new=compile_plan(c)
        self.assertFalse(any(t['program_id']=='installer' for t in new['application_templates']))
        self.assertEqual(old['application_templates'][0]['program_id'],'installer')
        c=fixture();c['profiles'][0]['grants'].append(dict(program_id='installer',ip='192.0.2.11',protocol='TCP',port=80));self.assertEqual(len(compile_plan(c)['application_templates']),2)
        del c['profiles'][0]['grants'][0];self.assertEqual(compile_plan(c)['application_templates'][0]['remote_address'],'192.0.2.11')
        c['profiles'][0]['grants']=[];self.rejected(c,'profile_plan_grant_count')

    def test_offline_predicate_randomized_edges(self):
        randomizer=random.Random(3924);checks=0
        c=fixture();active=c['profiles'][0]
        for i in range(1,5):
            active['programs'].append(dict(id=f'helper{i}',path=fr'C:\Fixture\helper{i}.exe',sha256=str(i)*64))
            active['grants'].append(dict(program_id=f'helper{i}',ip=f'192.0.2.{10+i}',protocol='UDP',port=5000+i))
        p=compile_plan(c)
        for _ in range(1000):
            i,j=randomizer.randrange(5),randomizer.randrange(5);bound=randomizer.choice([True,False]);program=active['programs'][i];g=active['grants'][j]
            actual=grant_match(p,'installer',program['path'],program['sha256'],g['ip'],g['protocol'],g['port'],bound)
            self.assertEqual(actual,bound and i==j);checks+=1
        self.assertEqual(checks,1000)

    def test_unknown_raw_capture_not_accepted(self):
        self.rejected(dict(schema='capture',events=[dict(program='browser',approved=True)]),'profile_plan_shape')

    def test_raw_plan_private_summary_is_sanitized(self):
        p=compile_plan(fixture());s=module.summarize_profile_plan(p);text=json.dumps(s)
        for token in [r'C:\\Fixture','192.0.2.','2001:db8','a'*64,'config_digest','program_path']:
            self.assertNotIn(token,text)
        self.assertFalse(s['ready_for_apply']);self.assertEqual(s['active_template_count'],1)

    def test_source_has_no_native_network_file_calls(self):
        tree=ast.parse((ROOT/'source/app_profile_plan.py').read_text())
        imports={n.name for node in ast.walk(tree) if isinstance(node,ast.Import) for n in node.names}
        self.assertEqual(imports,{'hashlib','ipaddress','json','ntpath','re'})
        forbidden={'open','eval','exec','__import__','compile','getattr','setattr','print'}
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in forbidden for n in ast.walk(tree)))


if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(PlanTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    summary=dict(suite='app-profile-non-executable-plan-01',passed=result.wasSuccessful(),test_methods=result.testsRun,
                 randomized_offline_predicate_cases=1000,native_Windows_API_executed=False,real_program_identity_verified=False,
                 real_SSTP_binding_verified=False,real_profile_switch_executed=False,firewall_mutation_requested=False,
                 journal_mutation_requested=False,ready_for_apply=False,no_leak_certified=False)
    (ROOT/'evidence/model-tests.json').write_text(json.dumps(summary,indent=2))
    raise SystemExit(not result.wasSuccessful())
