import base64
import json
from pathlib import Path
import sys
import unittest
sys.path.append(str(Path(__file__).resolve().parents[1] / "privacy-http"))
from manager import Manager, reconstruct
from validate_api import validate

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
    def test_foreign_host_not_exported(self):
        rows, _ = reconstruct([item(RAW.replace(b"nydus.battle.net", b"other.example"))])
        self.assertFalse(rows)
    def test_input_order_is_sequence_not_callback_order(self):
        rows, _ = reconstruct([item(RAW[11:], sequence=2), item(RAW[:11])])
        self.assertEqual(len(rows), 1)

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
        text = Path(__file__).with_name("run.py").read_text()
        self.assertIn('sys.path.insert(0, str(Path(__file__).resolve().parent))', text)
    def test_no_reserved_frida_context_assignment(self):
        text = Path(__file__).with_name("hook.js").read_text()
        self.assertNotIn("this.context=", text.replace(" ", ""))

if __name__ == "__main__":
    unittest.main()