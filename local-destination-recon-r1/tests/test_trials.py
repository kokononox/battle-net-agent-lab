import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import hosts_guard
from hosts_guard import HostsGuard,TARGET,EXTRA_TARGETS,trial_targets,checked_targets
import monitor
from validate import validate

def report():
    return {
        'schema':'local-retail-privacy-observer-2','version':'U2',
        'started_utc':'2026-10-18T23:00:00+00:00','mode':'block_one_extra',
        'experiment':{'baseline_target':TARGET,'selected_extra_target':EXTRA_TARGETS[0],
            'blocked_targets':[TARGET,EXTRA_TARGETS[0]],'resolution_after_apply':{},
            'resolution_before_restore':{},'dependency_result_user_reported':'not_recorded',
            'control_caveat':'progress_and_cache_differ_between_runs',
            'schedule_index':2,'window_seconds':120,'window_end_reason':'not_started'},
        'selftest':dict(passed=True,loopback_only=True,send_observed=True,wsasend_observed=True,
            sspi_negative_input_observed=True,fixture_excluded_from_real_report=True,
            worker_exited=True,script_errors=0,error_code=None),
        'initial_versions':{'status':'read','retail_versions':['12.1.0.69933']},
        'final_versions':None,'user_preconditions_confirmed':True,
        'ready_was_announced':False,'user_final_state':'not_recorded','status':'stopped',
        'error_code':'agent_hooks_not_ready_do_not_resume_update',
        'hosts':{'changed_by_tool':True,'restored':True,'restore_status':'restored_exactly',
            'resolution_after_apply':'loopback_only','resolution_at_end':'loopback_only'},
        'observation':None,'limits':monitor.LIMITS,'cpu_reference_available':True,
    }

class TrialGuardTests(unittest.TestCase):
    def make(self,root,extra=EXTRA_TARGETS[0],**kw):
        path=root/'hosts';path.write_bytes(b'# untouched\r\n127.0.0.1 localhost\r\n')
        return HostsGuard(path,root/'recovery.json',targets=trial_targets(extra),
            flush_fn=lambda:True,**kw)
    def test_each_trial_exact_two_domains_and_restore(self):
        for extra in EXTRA_TARGETS:
            with self.subTest(extra=extra),tempfile.TemporaryDirectory() as x:
                g=self.make(Path(x),extra,resolve_fn=lambda:'loopback_only')
                original=g.hosts.read_bytes();g.apply()
                entries=[l.split() for l in g.hosts.read_text().splitlines() if l and not l.startswith('#')]
                added=entries[1:]
                self.assertEqual(len(added),4)
                self.assertEqual({l[1] for l in added},{TARGET,extra})
                self.assertEqual(set(g.resolutions),{TARGET,extra})
                self.assertEqual(g.restore(),'restored_exactly')
                self.assertEqual(g.hosts.read_bytes(),original)
    def test_refuses_arbitrary_ip_or_hostname(self):
        for target in ('127.0.0.1','example.com','*.battle.net','level3.blizzard.com\n0.0.0.0 other'):
            with self.assertRaises(ValueError):trial_targets(target)
    def test_refuses_cumulative_or_missing_baseline(self):
        for targets in ((EXTRA_TARGETS[0],),(TARGET,EXTRA_TARGETS[0],EXTRA_TARGETS[1]),(TARGET,TARGET)):
            with self.assertRaises(ValueError):checked_targets(targets)
    def test_refuses_stale_other_menu_block_without_writes(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.make(Path(x),resolve_fn=lambda:'loopback_only')
            g.hosts.write_bytes(b'0.0.0.0 '+EXTRA_TARGETS[-1].encode()+b'\r\n')
            before=g.hosts.read_bytes()
            with self.assertRaises(ValueError):g.apply()
            self.assertEqual(before,g.hosts.read_bytes());self.assertFalse(g.journal.exists())
    def test_one_failed_target_cannot_announce_all_blocked(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.make(Path(x));original=g.hosts.read_bytes()
            with patch.object(hosts_guard,'resolve',side_effect=lambda t:'loopback_only' if t==TARGET else 'public_only'):
                with self.assertRaisesRegex(ValueError,'block_resolution_failed'):g.apply()
            self.assertEqual(g.resolutions[EXTRA_TARGETS[0]],'public_only')
            self.assertEqual(g.restore(),'restored_exactly');self.assertEqual(original,g.hosts.read_bytes())
    def test_crash_recovery_does_not_need_target_selection(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.make(Path(x),resolve_fn=lambda:'loopback_only');original=g.hosts.read_bytes();g.apply()
            recovery=HostsGuard(g.hosts,g.journal,flush_fn=lambda:True)
            self.assertEqual(recovery.restore(),'restored_exactly');self.assertEqual(original,g.hosts.read_bytes())
    def test_external_edit_not_overwritten_in_multi_target_mode(self):
        with tempfile.TemporaryDirectory() as x:
            g=self.make(Path(x),resolve_fn=lambda:'loopback_only');g.apply()
            edited=g.hosts.read_bytes()+b'# other edit\n';g.hosts.write_bytes(edited)
            self.assertEqual(g.restore(),'needs_manual_attention_journal_kept')
            self.assertEqual(g.hosts.read_bytes(),edited);self.assertTrue(g.journal.exists())

class TrialSchemaTests(unittest.TestCase):
    def test_valid_stopped_trial_is_not_completion(self):
        r=validate(report())
        self.assertFalse(r['limits']['whole_update_completion_proven'])
    def test_cumulative_blocks_refused(self):
        r=report();r['experiment']['blocked_targets'].append(EXTRA_TARGETS[1])
        with self.assertRaises(ValueError):validate(r)
    def test_schedule_index_target_mismatch_refused(self):
        r=report();r['experiment']['schedule_index']=3
        with self.assertRaises(ValueError):validate(r)
    def test_schedule_window_not_unbounded(self):
        r=report();r['experiment']['window_seconds']=9999999
        with self.assertRaises(ValueError):validate(r)
    def test_manual_mode_schema(self):
        r=report();r['experiment'].update(schedule_index=None,window_seconds=None)
        validate(r)
    def test_raw_log_cannot_be_added(self):
        r=report();r['experiment']['raw_payload']='not_exportable'
        with self.assertRaises(ValueError):validate(r)
    def test_ready_refused_when_one_target_unverified(self):
        r=report();r['ready_was_announced']=True
        r['experiment']['resolution_after_apply']={TARGET:'loopback_only',EXTRA_TARGETS[0]:'public_only'}
        with self.assertRaisesRegex(ValueError,'unblocked_trial_ready'):validate(r)

class ScheduleTests(unittest.TestCase):
    def stage(self,extra,index,finished=False,progress=True):
        r=report();r.update(status='observation_ended',ready_was_announced=True,user_final_state='reported_finished' if finished else 'reported_paused')
        r['experiment'].update(selected_extra_target=extra,schedule_index=index,
            dependency_result_user_reported='reported_progress' if progress else 'reported_stall',
            window_end_reason='time_limit')
        return r
    def test_plan_is_baseline_then_unique_single_extras(self):
        self.assertEqual(monitor.schedule_plan(),(None,)+EXTRA_TARGETS)
        self.assertEqual(len(set(EXTRA_TARGETS)),6)
        for extra in monitor.schedule_plan():
            self.assertLessEqual(len(trial_targets(extra)),2)
    def test_finishing_update_stops_before_more_trials(self):
        with patch('builtins.input',return_value='SCHEDULE'),patch.object(monitor,'main',return_value=self.stage(None,1,finished=True)) as main:
            monitor.run_schedule(object());self.assertEqual(main.call_count,1)
    def test_failed_baseline_stops_schedule(self):
        with patch('builtins.input',return_value='SCHEDULE'),patch.object(monitor,'snapshot',return_value={'processes':[]}),patch.object(monitor,'main',return_value=self.stage(None,1,progress=False)) as main:
            monitor.run_schedule(object());self.assertEqual(main.call_count,1)
    def test_live_process_prevents_next_trial(self):
        with patch('builtins.input',return_value='SCHEDULE'),patch.object(monitor,'snapshot',return_value={'processes':[{}]}),patch.object(monitor,'main',return_value=self.stage(None,1)) as main:
            monitor.run_schedule(object());self.assertEqual(main.call_count,1)
    def test_all_stages_are_fixed_120_seconds_and_require_next(self):
        results=[self.stage(extra,i) for i,extra in enumerate(monitor.schedule_plan(),1)]
        with patch('builtins.input',side_effect=['SCHEDULE']+['NEXT']*6),patch.object(monitor,'snapshot',return_value={'processes':[]}),patch.object(monitor,'main',side_effect=results) as main:
            monitor.run_schedule(object())
            self.assertEqual(main.call_count,7)
            for i,call in enumerate(main.call_args_list,1):
                self.assertEqual(call.kwargs['scheduled_trial'],{'index':i,'extra':monitor.schedule_plan()[i-1],'seconds':120})
    def test_mutex_is_shared_with_previous_package(self):
        s=(Path(__file__).resolve().parents[1]/'app'/'monitor.py').read_text()
        self.assertIn('Global\\\\LocalRetailPrivacyObserverU1',s)
    def test_timed_window_never_issues_update_pause_or_process_exit(self):
        import ast
        tree=ast.parse((Path(__file__).resolve().parents[1]/'app'/'monitor.py').read_text())
        for n in ast.walk(tree):
            if isinstance(n,ast.Call):
                name=n.func.attr if isinstance(n.func,ast.Attribute) else n.func.id if isinstance(n.func,ast.Name) else ''
                self.assertNotIn(name,{'kill','terminate','suspend','resume','spawn','Popen','system'})
                if name=='run':
                    # The only direct run() is the owned loopback self-test;
                    # subprocess.run (or another object's run) is forbidden.
                    self.assertIsInstance(n.func,ast.Name)
                    self.assertEqual([a.id for a in n.args if isinstance(a,ast.Name)],['frida'])
    def test_timed_main_roundtrip_writes_valid_report_without_real_hosts_or_frida(self):
        import os
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as x:
            root=Path(x);hostpath=root/'System32'/'drivers'/'etc'/'hosts'
            hostpath.parent.mkdir(parents=True);original=b'# original\r\n'
            hostpath.write_bytes(original)
            fake_collector=SimpleNamespace(
                start=lambda:None,ready=lambda:True,close=lambda:None,phase='before_user_update',
                report=lambda:dict(processes=[],events=[],aggregate_inputs=[],
                    public_tcp_destinations=[],sampler_errors=0,
                    limits_hit=dict(event_detail=False,flows=False,processes=False,hooks=False),
                    sampling_thread_stopped=True))
            def factory(hosts,journal,**kw):
                return HostsGuard(hosts,journal,flush_fn=lambda:True,resolve_fn=lambda:'loopback_only',**kw)
            modules={'frida':SimpleNamespace(__version__='17.24.2'),
                'selftest':SimpleNamespace(run=lambda _:report()['selftest']),
                'msvcrt':SimpleNamespace(kbhit=lambda:False)}
            with patch.dict(sys.modules,modules),patch.dict(os.environ,{'SystemRoot':str(root)}),\
                patch.object(monitor.sys,'platform','win32'),\
                patch.object(monitor.ctypes,'windll',SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda:True)),create=True),\
                patch.object(monitor,'BASE',root),patch.object(monitor,'integrity'),\
                patch.object(monitor,'HostsGuard',side_effect=factory),\
                patch.object(monitor,'snapshot',return_value={'processes':[]}),\
                patch.object(monitor,'versions',return_value={'status':'read','retail_versions':['12.1.0.69933']}),\
                patch.object(monitor,'cpu_reference',return_value=b'FIXTURE'),\
                patch.object(monitor,'Collector',return_value=fake_collector),\
                patch.object(monitor.time,'monotonic',side_effect=[0,1,2,123]),\
                patch.object(monitor.time,'sleep'),\
                patch('builtins.input',side_effect=['','CONFIRM','BLOCK','2','1']):
                result=monitor.main(SimpleNamespace(restore_only=False,selftest_only=False),
                    scheduled_trial={'index':2,'extra':EXTRA_TARGETS[0],'seconds':120})
            validate(result)
            self.assertEqual(result['experiment']['window_end_reason'],'time_limit')
            self.assertEqual(result['experiment']['dependency_result_user_reported'],'reported_progress')
            self.assertEqual(result['hosts']['restore_status'],'restored_exactly')
            self.assertEqual(hostpath.read_bytes(),original)
            self.assertEqual(len(list((root/'output').glob('report-*.json'))),1)

if __name__=='__main__':unittest.main()