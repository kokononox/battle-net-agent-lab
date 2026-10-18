import base64
import json
from pathlib import Path
import sys
import unittest
sys.path.append(str(Path(__file__).resolve().parents[1] / "privacy-http"))
from birth_manager import Manager, reconstruct
from validate_observation import validate

RAW = b"POST /owned HTTP/1.1\r\nHost: nydus.battle.net\r\nContent-Length: 4\r\n\r\ntest"

def item(raw=RAW, sequence=1, accepted=None, socket="s1", **kw):
    return {
        "pid": 7, "process_sha256": "a"*64, "socket": socket, "api": "send",
        "sequence": sequence, "declared_bytes": len(raw),
        "accepted_bytes": len(raw) if accepted is None else accepted,
        "return_code": len(raw), "truncated": False, "raw": raw, **kw,
    }

class DecodeTests(unittest.TestCase):
    def test_complete(self):
        rows, streams = reconstruct([item()])
        self.assertEqual(base64.b64decode(rows[0]["body_sample_base64"]), b"test")
        self.assertFalse(streams[0]["api_input_gap"])
    def test_split(self):
        rows, _ = reconstruct([item(RAW[:11]), item(RAW[11:], sequence=2)])
        self.assertTrue(rows[0]["body_complete"])
    def test_partial_send(self):
        rows, _ = reconstruct([item(RAW, accepted=11), item(RAW[11:], sequence=2)])
        self.assertTrue(rows[0]["body_complete"])
    def test_zero_acceptance_is_gap(self):
        rows, streams = reconstruct([item(accepted=0), item(sequence=2)])
        self.assertFalse(rows)
        self.assertTrue(streams[0]["api_input_gap"])
    def test_pending_completion_is_not_success(self):
        first = item()
        first["accepted_bytes"] = None
        rows, streams = reconstruct([first])
        self.assertFalse(rows)
        self.assertTrue(streams[0]["api_input_gap"])
    def test_different_sockets_not_concatenated(self):
        rows, _ = reconstruct([item(RAW[:11]), item(RAW[11:], socket="s2")])
        self.assertFalse(rows)
    def test_credential_redacted_after_parse(self):
        raw = RAW.replace(b"Content-Length:", b"Authorization: secret\r\nContent-Length:")
        rows, _ = reconstruct([item(raw)])
        self.assertNotIn("secret", str(rows))
    def test_alternate_host_exported(self):
        rows, _ = reconstruct([item(RAW.replace(b"nydus.battle.net", b"other.example"))])
        self.assertEqual(rows[0]["host"], "other.example")
    def test_input_order_is_sequence_not_callback_order(self):
        rows, _ = reconstruct([item(RAW[11:], sequence=2), item(RAW[:11])])
        self.assertEqual(len(rows), 1)

class TLSAndHostsTests(unittest.TestCase):
    def test_tls_context_kept_separate(self):
        rows,_=reconstruct([item(RAW[:11]),item(RAW[11:],socket='ctx1',api='EncryptMessage',return_code=0)])
        self.assertFalse(rows)
    def test_tls_success_input_is_decodable(self):
        rows,_=reconstruct([item(socket='ctx1',api='EncryptMessage',return_code=0)])
        self.assertEqual(rows[0]['socket'],'ctx1')
    def test_tls_failed_call_never_complete_request(self):
        first=item(socket='ctx1',api='EncryptMessage',return_code=-1);first['accepted_bytes']=None
        rows,streams=reconstruct([first]);self.assertFalse(rows);self.assertTrue(streams[0]['api_input_gap'])
    def test_invalid_host_omitted(self):
        rows,_=reconstruct([item(RAW.replace(b'nydus.battle.net',b'bad/host'))]);self.assertFalse(rows)
    def test_tls_host_port_normalization(self):
        rows,_=reconstruct([item(RAW.replace(b'nydus.battle.net',b'telemetry-in.battle.net:443'))])
        self.assertEqual(rows[0]['host'],'telemetry-in.battle.net')
    def test_intervention_classifier(self):
        from run import classify,contains_target
        self.assertEqual(classify(['127.0.0.1','::1'])[0],'loopback_only')
        self.assertEqual(classify(['127.0.0.1','8.8.8.8'])[0],'mixed_or_other')
        self.assertTrue(contains_target(b'127.0.0.1 telemetry-in.battle.net'))
        self.assertFalse(contains_target(b'# 127.0.0.1 telemetry-in.battle.net'))
    def test_main_guards_refuse_local_host(self):
        from run import main
        with self.assertRaises(SystemExit):main()
    def test_negative_sspi_cannot_pass_alone(self):
        text=Path(__file__).with_name('birth_selftest.py').read_text()
        self.assertIn("and x['return_code']!=0",text)
        self.assertIn('"sspi_negative_input_observed",',text)

class ReportValidationTests(unittest.TestCase):
    def fixture(self):
        import ast
        tree=ast.parse(Path(__file__).with_name('validate_observation.py').read_text())
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate')
        node=next(n for n in fn.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='expected' for t in n.targets))
        limits=ast.literal_eval(node.value)
        return dict(schema='bnet-process-birth-http-tls-1',source_commit='a'*40,run_id='123',
            scope='fresh_vm_root_child_gate_no_login_game_install_action',tool_version='17.24.2',
            reference=dict(cpu_model=None,windows_build=26100,total_physical_memory_bytes=8000000000,logical_processors=2),
            selftest=None,bootstrap_pin_match=None,processes=[],streams=[],requests=[],tls_inputs=[],
            input_events=0,dropped_events=0,fatal=False,status='stopped',error_code=None,limits=limits)
    def test_stopped_report_valid(self):validate(self.fixture())
    def test_wrong_hardware_privacy_claim_refused(self):
        r=self.fixture();r['limits']['server_receipt_proven']=True
        with self.assertRaises(ValueError):validate(r)
    def test_unattributed_tls_rejected(self):
        r=self.fixture();r['tls_inputs']=[{}]
        with self.assertRaises(ValueError):validate(r)
    def test_extra_field_rejected(self):
        r=self.fixture();r['credentials']='not_a_real_secret'
        with self.assertRaises(ValueError):validate(r)
    def test_summary_only_literal_hit_not_delivery(self):
        from birth_manager import tls_summary
        x=item(raw=b'CPU EXAMPLE',socket='ctx1',api='EncryptMessage',return_code=0)
        rows=tls_summary([x],'CPU EXAMPLE')
        self.assertTrue(rows[0]['reference_cpu_literal_present'])
        self.assertNotIn('raw',rows[0]);self.assertNotIn('server_receipt',rows[0])

class Cancel:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def cancel(self): pass

class FakeScript:
    def on(self, event, callback): self.callback = callback
    def load(self): self.callback({"type": "send", "payload": {"kind": "ready"}}, None)

class FakeSession:
    def __init__(self, fail): self.fail = fail
    def enable_child_gating(self):
        if self.fail: raise NotImplementedError("not_supported")
    def create_script(self, source): return FakeScript()
    def detach(self): pass

class FakeDevice:
    def __init__(self, fail): self.fail, self.resumed, self.killed = fail, [], []
    def on(self, *args): pass
    def off(self, *args): pass
    def attach(self, pid): return FakeSession(self.fail)
    def resume(self, pid): self.resumed.append(pid)
    def kill(self, pid): self.killed.append(pid)

class FakeFrida:
    Cancellable = Cancel
    def __init__(self, fail): self.device = FakeDevice(fail)
    def get_local_device(self): return self.device

class GateTests(unittest.TestCase):
    def verifier(self, pid, recheck=False):
        return {} if recheck else {
            "process_name": "agent.exe", "sha256": "a"*64, "image_bytes": 100,
            "authenticode_valid": True, "expected_blizzard_publisher": True,
        }
    def test_no_resume_when_child_gating_fails(self):
        frida = FakeFrida(True)
        manager = Manager(frida, self.verifier)
        try:
            row = manager.prepare(7, None)
            self.assertEqual(row["phase"], "child_gating")
            self.assertEqual(frida.device.resumed, [])
            self.assertEqual(frida.device.killed, [7])
            self.assertTrue(manager.fatal)
        finally: manager.close()
    def test_hook_is_ready_before_resume(self):
        frida = FakeFrida(False)
        manager = Manager(frida, self.verifier)
        try:
            row = manager.prepare(7, None)
            self.assertTrue(row["hook_ready"] and row["instrumented_before_resume"])
            self.assertEqual(frida.device.resumed, [7])
        finally: manager.close()
    def test_identity_failure_cannot_resume(self):
        frida = FakeFrida(False)
        def bad(*args, **kwargs): raise OSError("owned_fixture")
        manager = Manager(frida, bad)
        try:
            manager.prepare(7, None)
            self.assertFalse(frida.device.resumed)
        finally: manager.close()
    def test_local_selftest_module_selected(self):
        text = Path(__file__).with_name("observation.py").read_text()
        self.assertIn('sys.path.insert(0, str(Path(__file__).resolve().parent))', text)
    def test_no_reserved_frida_context_assignment(self):
        text = Path(__file__).with_name("birth_hook.js").read_text()
        self.assertNotIn("this.context=", text.replace(" ", ""))

if __name__ == "__main__":
    unittest.main()