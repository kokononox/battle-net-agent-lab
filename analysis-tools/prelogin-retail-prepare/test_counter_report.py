import copy
import unittest
from pathlib import Path
import counter_driver as driver
import counter_report as c
from test_network_diagnostics import blank


class CounterReport(unittest.TestCase):
    def native(self):
        d=blank()
        d.update(samples=33,phase_boundary_observed=True)
        return dict(schema='bnet-counter-native-1',source_commit='a'*40,run_id='1',
                    status='observed',network_scope='hostwide_adapter_counters',
                    boundary_kind='synthetic_observation_marker',target_launched=False,
                    transfer_requested=False,diagnostics=d)

    def test_valid_native(self):c.native(self.native())
    def test_blank_run(self):c.validate(c.blank('a'*40,'1'))
    def test_target_cannot_be_claimed(self):
        for k in ('target_launched','transfer_requested'):
            d=self.native();d[k]=True
            with self.assertRaises(ValueError):c.native(d)
    def test_no_unbounded_sampling(self):
        d=self.native();d['diagnostics']['samples']=34
        with self.assertRaises(ValueError):c.native(d)
    def test_incomplete_cannot_pass(self):
        d=self.native();d['diagnostics']['samples']=32
        with self.assertRaises(ValueError):c.native(d)
    def test_no_endpoint_identifiers(self):
        for k in ('ip','interface_id','pid'):
            d=self.native();d[k]='PRIVATE'
            with self.assertRaises(ValueError):c.native(d)
    def test_boundary_is_not_a_game_transfer(self):
        d=self.native();d['boundary_kind']='game_transfer'
        with self.assertRaises(ValueError):c.native(d)
    def test_success_needs_real_run_receipt(self):
        d=c.blank('a'*40,'1');d['status']='observed'
        with self.assertRaises(ValueError):c.validate(d)
    def test_success_gate(self):
        d=c.blank('a'*40,'1');d.update(status='observed',portable_assertions_passed=True,native=self.native())
        d['guard_build'].update(stage='compiled',installation_found=True,devcmd_found=True,compiler_exit_code=0)
        c.validate(d)
        d['native']['run_id']='2'
        with self.assertRaises(ValueError):c.validate(d)
    def test_report_cannot_relax_limits(self):
        d=c.blank('a'*40,'1');d['production_limits_changed']=True
        with self.assertRaises(ValueError):c.validate(d)
    def test_approval_is_separate_from_target(self):
        e=dict(GITHUB_ACTIONS='true',RUNNER_OS='Windows',RUNNER_ENVIRONMENT='github-hosted',
               GITHUB_EVENT_NAME='push',GITHUB_RUN_ATTEMPT='1',GITHUB_REF=driver.BRANCH,
               COUNTER_DIAGNOSTIC='approved-counter-diagnostics-d1')
        self.assertTrue(driver.allowed(e,'win32'))
        self.assertFalse(driver.allowed(e,'linux'))
        e['COUNTER_DIAGNOSTIC']='approved-retail-prepare-c10'
        self.assertFalse(driver.allowed(e,'win32'))
    def test_driver_does_not_execute_production_guard(self):
        text=Path(driver.__file__).read_text()
        self.assertIn("guard_driver.build(r['guard_build'])",text)
        self.assertNotIn("'observe'",text)
        self.assertNotIn('run_prepare.py',text)
    def test_probe_has_no_target_launch_or_http_calls(self):
        text=Path(driver.__file__).with_name('counter_probe_win.cpp').read_text()
        for word in ('CreateProcess','ShellExecute','WinHttp','WinInet','WSAConnect','send('):
            self.assertNotIn(word,text)
    def test_workflow_uploads_only_typed_receipt(self):
        path=Path(driver.__file__).resolve().parents[2]/'.github/workflows/prelogin-counter-diagnostics.yml'
        text=path.read_text()
        self.assertIn('path: sanitized/counter-diagnostic-run.json',text)
        self.assertNotIn('RETAIL_PREPARE:',text)
        self.assertNotIn('RETAIL_SUPERVISED:',text)
        self.assertIn("github.event.head_commit.message == 'lab: approved counter diagnostics d1'",text)


if __name__=='__main__':unittest.main()
