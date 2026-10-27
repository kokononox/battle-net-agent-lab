import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import attempt_report as a
import ci_status
import guard_report as g
import report
import transfer_probe as t

SOURCE = 'a' * 40
RUN = '123'


class Attempt(unittest.TestCase):
    def ci(self):
        return ci_status.status(SOURCE, RUN, 'completed', 'success', 'success',
                                'failure', 'failure')

    def summary(self, **kw):
        return a.summarize(SOURCE, RUN, self.ci(), **kw)

    def test_absent_is_not_success(self):
        r = self.summary()
        self.assertEqual(r['status'], 'evidence_incomplete')
        for k in ('complete_installation_proven', 'hardware_upload_proven',
                  'request_delivery_proven', 'download_progress_observed'):
            self.assertIs(r[k], False)

    def test_stale_form_payload_is_not_consumed(self):
        r = self.summary(form=dict(source_commit='b'*40, run_id='99',
                                   schema='old-version', token='PRIVATE'))
        self.assertEqual(r['form_receipt'], 'stale_ignored')
        self.assertNotIn('PRIVATE', json.dumps(r))

    def test_other_run_same_commit_is_stale(self):
        r = self.summary(transfer=t.blank(SOURCE, '124'))
        self.assertEqual(r['transfer_receipt'], 'stale_ignored')
        self.assertIsNone(r['transfer_status'])

    def test_current_blank_transfer_is_explicit(self):
        r = self.summary(transfer=t.blank(SOURCE, RUN))
        self.assertEqual(r['transfer_receipt'], 'current')
        self.assertEqual(r['transfer_status'], 'not_started')
        self.assertFalse(r['finalization_intent_recorded'])

    def test_current_schema_cannot_be_bypassed(self):
        for name, value in [('transfer', t.blank(SOURCE, RUN)),
                            ('form', report.blank(SOURCE, RUN)),
                            ('guard', g.blank(SOURCE, RUN))]:
            value['private'] = 'SECRET'
            with self.assertRaises(ValueError):
                self.summary(**{name: value})

    def test_source_bound_ci(self):
        ci = self.ci()
        ci['run_id'] = '999'
        with self.assertRaises(ValueError):
            a.summarize(SOURCE, RUN, ci)

    def test_unknown_ci_field(self):
        ci = self.ci()
        ci['token'] = 'SECRET'
        with self.assertRaises(ValueError):
            a.summarize(SOURCE, RUN, ci)

    def test_bad_stale_identity_refused(self):
        with self.assertRaises(ValueError):
            self.summary(form=dict(source_commit='PRIVATE', run_id=RUN))

    def test_current_form_does_not_invent_transfer(self):
        r = self.summary(form=report.blank(SOURCE, RUN))
        self.assertEqual(r['form_receipt'], 'current')
        self.assertEqual(r['transfer_receipt'], 'absent')

    def test_real_interrupted_receipts(self):
        fixture = g.read(Path(__file__).with_name('testdata')/'c10-interrupted.json')
        guard, transfer = fixture['guard'], fixture['transfer']
        # Stable historical fixture: normalize identities, not observed fields.
        guard = copy.deepcopy(guard)
        guard.update(source_commit=SOURCE, run_id=RUN)
        for v in [*guard['fixtures'].values(), guard['observation']]:
            v.update(source_commit=SOURCE, run_id=RUN)
        transfer = copy.deepcopy(transfer)
        transfer.update(source_commit=SOURCE, run_id=RUN)
        r = self.summary(guard=guard, transfer=transfer)
        self.assertEqual(r['status'], 'supervisor_stopped')
        self.assertTrue(r['finalization_intent_recorded'])
        self.assertFalse(r['start_intent_recorded'])
        self.assertIsNone(r['finalization_http_status'])
        self.assertTrue(r['job_drained'])
        self.assertEqual(r['final_active_processes'], 0)
        self.assertFalse(r['request_delivery_proven'])

    def test_fresh_cli_missing_form(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/'ci.json').write_text(json.dumps(self.ci()))
            env = os.environ.copy()
            env.pop('PYTHONPATH', None)
            result = subprocess.run([sys.executable, str(Path(a.__file__).resolve()),
                SOURCE, RUN, str(p/'ci.json'), str(p/'no-guard'),
                str(p/'no-transfer'), str(p/'no-form'), str(p/'out.json')],
                cwd=d, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads((p/'out.json').read_text())['form_receipt'], 'absent')


class WorkflowPublication(unittest.TestCase):
    def test_publish_without_worker_final_report_uses_current_run_only(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root/'.github/workflows/prelogin-retail-prepare.yml').read_text()
        script = workflow.split("python3 - <<'PY'", 1)[1].split('          PY', 1)[0]
        import textwrap
        import shutil
        script = textwrap.dedent(script.lstrip('\n'))
        fixture = g.read(Path(__file__).with_name('testdata')/'c10-interrupted.json')
        source = fixture['guard']['source_commit']
        run = fixture['guard']['run_id']
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            shutil.copytree(root/'agent-interface-lab', work/'agent-interface-lab')
            shutil.copytree(Path(__file__).parent,
                            work/'analysis-tools/prelogin-retail-prepare')
            incoming = work/'incoming'
            incoming.mkdir()
            (work/'reports').mkdir()
            inputs = {'retail-supervision.json': fixture['guard'],
                      'retail-transfer.json': fixture['transfer'],
                      'prelogin-retail-prepare-ci.json': ci_status.status(
                          source, run, 'completed', 'success', 'success', 'failure', 'failure')}
            for name, value in inputs.items():
                (incoming/name).write_text(json.dumps(value))
            stale = work/'reports/prelogin-retail-prepare-runtime.json'
            stale.write_text('old run must not be read or rewritten')
            env = dict(os.environ, SOURCE=source, RUN=run)
            env.pop('PYTHONPATH', None)
            p = subprocess.run([sys.executable, '-c', script], cwd=d, env=env,
                               capture_output=True, timeout=10)
            self.assertEqual(p.returncode, 0)
            r = json.loads((work/'reports/prelogin-retail-attempt-latest.json').read_text())
            self.assertEqual(r['run_id'], run)
            self.assertEqual(r['form_receipt'], 'absent')
            self.assertEqual(r['status'], 'supervisor_stopped')
            self.assertEqual(stale.read_text(), 'old run must not be read or rewritten')
            inputs['retail-transfer.json']['run_id'] = '999'
            (incoming/'retail-transfer.json').write_text(json.dumps(inputs['retail-transfer.json']))
            p = subprocess.run([sys.executable, '-c', script], cwd=d, env=env,
                               capture_output=True, timeout=10)
            self.assertNotEqual(p.returncode, 0)


if __name__ == '__main__':
    unittest.main()
