import ast
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import recon
from recon_profiles import PROFILES,BAT3_FIXED,EXTRAS,ProfileGuard,domains_for,probe_domains

def fixture_report():
    return dict(schema='retail-destination-recon-1',profile_id='02',
        profile_label=PROFILES['02']['label'],blocked_domains=list(BAT3_FIXED),
        started_utc='2026-10-18T23:00:00+00:00',ready_utc=None,
        observation_ended_utc='2026-10-18T23:02:00+00:00',ended_utc='2026-10-18T23:02:01+00:00',
        window_seconds=120,end_reason='stopped',ready=False,user_preconditions_confirmed=True,
        status='stopped',error_code='no_live_verified_agent_do_not_resume',
        initial_versions={'status':'read','retail_versions':['12.1.0.69933']},
        final_versions=None,hosts={'changed':False,'restored':False,'restore_status':'not_needed',
            'resolution_after_apply':{},'resolution_before_restore':{}},
        user_final_state='unknown',user_download_behavior='unknown',
        observation={'processes':[],'public_tcp_samples':[],'sampler_errors':0,
            'process_limit_hit':False,'flow_limit_hit':False},limits=recon.LIMITS)

class ProfileTests(unittest.TestCase):
    def test_corrected_bat_three_exact_twenty(self):
        self.assertEqual(len(BAT3_FIXED),20);self.assertEqual(len(set(BAT3_FIXED)),20)
        self.assertIn('breaking-news.support.blizzard.com',BAT3_FIXED)
        self.assertNotIn('www.google.com',BAT3_FIXED)
        self.assertTrue(all(':' not in d and '/' not in d for d in BAT3_FIXED))
    def test_single_extra_not_accumulated(self):
        for index,extra in enumerate(EXTRAS,3):
            self.assertEqual(domains_for(f'{index:02}'),BAT3_FIXED+(extra,))
    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):domains_for('foo.battle.net')
    def test_each_profile_roundtrip_bytes_and_two_entries_each(self):
        for profile in PROFILES:
            with self.subTest(profile=profile),tempfile.TemporaryDirectory() as x:
                root=Path(x);p=root/'hosts';original=b'# original\r\n127.0.0.1 localhost\r\n';p.write_bytes(original)
                g=ProfileGuard(p,root/'journal',profile,flush_fn=lambda:True,
                    probe_fn=lambda ds:{d:'loopback_only' for d in ds})
                g.apply();lines=p.read_text().splitlines()
                for domain in domains_for(profile):
                    self.assertIn('127.0.0.1 '+domain,lines);self.assertIn('::1 '+domain,lines)
                self.assertEqual(g.restore(),'restored_exactly');self.assertEqual(p.read_bytes(),original)
    def test_old_bad_port_entry_refused_without_cleanup(self):
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);p=root/'hosts';b=b'0.0.0.0 breaking-news.support.blizzard.com:443\r\n';p.write_bytes(b)
            g=ProfileGuard(p,root/'journal','02',flush_fn=lambda:True)
            with self.assertRaisesRegex(ValueError,'existing_profile_entry'):g.apply()
            self.assertEqual(p.read_bytes(),b);self.assertFalse(g.journal.exists())
    def test_existing_nonselected_profile_entry_refused(self):
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);p=root/'hosts';b=b'0.0.0.0 www.youtube.com\r\n';p.write_bytes(b)
            g=ProfileGuard(p,root/'journal','01',flush_fn=lambda:True)
            with self.assertRaises(ValueError):g.apply()
            self.assertEqual(p.read_bytes(),b)
    def test_profile_failure_preserves_recovery(self):
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);p=root/'hosts';original=b'# keep\n';p.write_bytes(original)
            g=ProfileGuard(p,root/'journal','02',flush_fn=lambda:True,
                probe_fn=lambda ds:{d:('public_only' if d=='rum.battle.net' else 'loopback_only') for d in ds})
            with self.assertRaisesRegex(ValueError,'block_resolution_failed'):g.apply()
            self.assertEqual(g.restore(),'restored_exactly');self.assertEqual(p.read_bytes(),original)
    def test_external_edit_not_overwritten(self):
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);p=root/'hosts';p.write_bytes(b'# keep\n')
            g=ProfileGuard(p,root/'journal','02',flush_fn=lambda:True,
                probe_fn=lambda ds:{d:'loopback_only' for d in ds})
            g.apply();edited=p.read_bytes()+b'# external edit\n';p.write_bytes(edited)
            self.assertEqual(g.restore(),'needs_manual_attention_journal_kept')
            self.assertEqual(p.read_bytes(),edited);self.assertTrue(g.journal.exists())
    def test_existing_backup_not_overwritten(self):
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);p=root/'hosts';p.write_bytes(b'# keep\n');j=root/'journal';j.write_bytes(b'old journal')
            g=ProfileGuard(p,j,'02',flush_fn=lambda:True)
            with self.assertRaises(ValueError):g.apply()
            self.assertEqual(j.read_bytes(),b'old journal');self.assertEqual(p.read_bytes(),b'# keep\n')

class ReconTests(unittest.TestCase):
    def test_no_injection_process_control_or_payload_network_client(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'recon.py').read_text()
        tree=ast.parse(s)
        for n in ast.walk(tree):
            if isinstance(n,(ast.Import,ast.ImportFrom)):
                names=[a.name for a in n.names]+([n.module] if isinstance(n,ast.ImportFrom) else [])
                self.assertNotIn('frida',names)
            if isinstance(n,ast.Call):
                name=n.func.attr if isinstance(n.func,ast.Attribute) else n.func.id if isinstance(n.func,ast.Name) else ''
                self.assertNotIn(name,{'attach','kill','terminate','spawn','suspend','resume','urlopen','Popen','system'})
    def test_report_strict_whitelist_and_negative_claims(self):
        r=recon.validate_report(fixture_report())
        self.assertFalse(r['limits']['injection_used']);self.assertFalse(r['limits']['zero_telemetry_proven'])
        r['raw_payload']='NO'
        with self.assertRaises(ValueError):recon.validate_report(r)
    def test_raw_fields_in_process_refused(self):
        r=fixture_report();r['observation']['processes']=[{'path':'private'}]
        with self.assertRaises(ValueError):recon.validate_report(r)
    def test_ready_not_allowed_if_resolution_failed(self):
        r=fixture_report();r['ready']=True
        with self.assertRaisesRegex(ValueError,'recon_unblocked_ready'):recon.validate_report(r)
    def test_other_profile_blocked_domains_refused(self):
        r=fixture_report();r['blocked_domains'].append('unknown.example')
        with self.assertRaises(ValueError):recon.validate_report(r)
    def test_unknown_payload_limit_not_silently_accepted(self):
        r=fixture_report();r['limits']=dict(recon.LIMITS,injection_used=True)
        with self.assertRaises(ValueError):recon.validate_report(r)
    def test_fake_full_run_exact_restore_and_report(self):
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);hosts=root/'System32'/'drivers'/'etc'/'hosts';hosts.parent.mkdir(parents=True)
            original=b'# original\r\n';hosts.write_bytes(original)
            def guard(h,j,p):
                return ProfileGuard(h,j,p,flush_fn=lambda:True,probe_fn=lambda ds:{d:'loopback_only' for d in ds})
            scanner=SimpleNamespace(poll=lambda phase:None,live_agent_seen=lambda:True,
                report=lambda:fixture_report()['observation'])
            with patch.object(recon.sys,'platform','win32'),\
                patch.object(recon.ctypes,'windll',SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda:True)),create=True),\
                patch.dict(os.environ,{'SystemRoot':str(root)}),\
                patch.dict(sys.modules,{'msvcrt':SimpleNamespace(kbhit=lambda:False)}),\
                patch.object(recon,'BASE',root),patch.object(recon,'integrity'),\
                patch.object(recon,'ProfileGuard',side_effect=guard),\
                patch.object(recon,'snapshot',return_value={'processes':[]}),\
                patch.object(recon,'versions',return_value=fixture_report()['initial_versions']),\
                patch.object(recon,'Scanner',return_value=scanner),\
                patch.object(recon.time,'monotonic',side_effect=[0,1,2,123]),\
                patch('builtins.input',side_effect=['','CONFIRM','BLOCK','2','1']):
                result=recon.main(SimpleNamespace(selftest_network=False,profile='02'))
            recon.validate_report(result)
            self.assertEqual(result['end_reason'],'time_limit')
            self.assertTrue(result['ready']);self.assertEqual(result['user_final_state'],'reported_paused')
            self.assertEqual(hosts.read_bytes(),original)
            self.assertEqual(len(list((root/'output').glob('recon-02-*.json'))),1)

if __name__=='__main__':unittest.main()