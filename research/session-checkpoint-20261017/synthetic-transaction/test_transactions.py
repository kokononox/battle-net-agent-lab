"""Real disposable-file/process tests. No archive, game or network input."""
from pathlib import Path
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import transaction_fixture as t

HERE = Path(__file__).resolve().parent
EVIDENCE = {"advance_crashes": [], "rollback_crashes": [], "injected_io_failures": [], "reader_snapshots": 0}


def snapshot(root):
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*") if p.is_file() and not p.is_symlink()
    }


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="case-", dir=os.environ["SYNTHETIC_OUT_NEW"])
        self.base = Path(self.temp.name).resolve()
        self.root, self.cap = t.create_fixture(self.base)
        self.old = {name: (self.root / "generations/g0" / name).read_bytes() for name in (*t.NAMES, "MANIFEST.json")}

    def tearDown(self):
        self.temp.cleanup()

    def assert_old_retained(self):
        self.assertEqual(self.old, {name: (self.root / "generations/g0" / name).read_bytes() for name in self.old})

    def cli(self, mode, phase="never"):
        return subprocess.run(
            [sys.executable, "-B", str(HERE / "worker.py"), mode, str(self.root), self.cap, phase],
            capture_output=True, text=True, timeout=15,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
        )

    def crash_advance(self, phase):
        child = self.cli("advance", phase)
        self.assertEqual(child.returncode, 91, child.stdout + child.stderr)
        before_resume = t.visible(self.root, self.cap)
        expected = "g1" if phase in ("pointer_replaced", "root_synced") else "g0"
        self.assertEqual(before_resume, expected)
        resumed = self.cli("advance")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(t.visible(self.root, self.cap), "g1")
        before = snapshot(self.root)
        self.assertTrue(t.advance(self.root, self.cap)["idempotent"])
        self.assertEqual(before, snapshot(self.root))
        self.assert_old_retained()
        EVIDENCE["advance_crashes"].append({
            "phase": phase, "exit_code": 91, "visible_after_exit": before_resume,
            "resumed": "g1", "repeat_nonmutating": True, "old_retained": True,
        })

    def crash_rollback(self, phase):
        t.advance(self.root, self.cap)
        child = self.cli("rollback", phase)
        self.assertEqual(child.returncode, 91, child.stdout + child.stderr)
        expected = "g0" if phase in ("pointer_replaced", "root_synced") else "g1"
        self.assertEqual(t.visible(self.root, self.cap), expected)
        resumed = self.cli("rollback")
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertEqual(t.visible(self.root, self.cap), "g0")
        self.assert_old_retained()
        EVIDENCE["rollback_crashes"].append({
            "phase": phase, "exit_code": 91, "visible_after_exit": expected, "resumed": "g0",
        })

    def io_failure(self, failure):
        with self.assertRaises((OSError, t.Stopped)):
            t.advance(self.root, self.cap, fail=failure)
        expected = "g1" if failure == "sync_root" else "g0"
        self.assertEqual(t.visible(self.root, self.cap), expected)
        t.advance(self.root, self.cap)
        self.assertEqual(t.visible(self.root, self.cap), "g1")
        self.assert_old_retained()
        EVIDENCE["injected_io_failures"].append({
            "injection": failure, "visible_on_error": expected, "resume": "g1",
            "physical_disk_full_test": False,
        })

    def test_complete_three_file_generation(self):
        self.assertEqual(t.visible(self.root, self.cap), "g0")
        result = t.advance(self.root, self.cap)
        self.assertEqual(result["state"], "g1")
        self.assertFalse(result["installation_ready"])
        self.assert_old_retained()

    def test_wrong_capability_rejected_without_writes(self):
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, "wrong")
        self.assertEqual(before, snapshot(self.root))

    def test_unmarked_directory_rejected_without_writes(self):
        root = self.base / "synthetic-txn-unmarked"
        root.mkdir()
        (root / "keep.fixture").write_bytes(b"untouched")
        before = snapshot(root)
        with self.assertRaises((t.Stopped, OSError)):
            t.advance(root, self.cap)
        self.assertEqual(before, snapshot(root))

    def test_unexpected_file_preserved_and_rejected(self):
        (self.root / "do-not-delete.fixture").write_bytes(b"KEEP")
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, self.cap)
        self.assertEqual(before, snapshot(self.root))

    def test_corrupt_old_generation_stops_before_writes(self):
        (self.root / "generations/g0" / t.NAMES[0]).write_bytes(b"broken")
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, self.cap)
        self.assertEqual(before, snapshot(self.root))

    def test_corrupt_complete_new_generation_not_activated(self):
        self.assertEqual(self.cli("advance", "generation_ready").returncode, 91)
        (self.root / "generations/g1" / t.NAMES[1]).write_bytes(b"broken")
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, self.cap)
        self.assertEqual(before, snapshot(self.root))
        self.assertEqual(t.visible(self.root, self.cap), "g0")

    def test_corrupt_stage_not_silently_deleted(self):
        self.assertEqual(self.cli("advance", "alpha_half").returncode, 91)
        (self.root / "generations/.stage-g1" / t.NAMES[0]).write_bytes(b"not-generated")
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, self.cap)
        self.assertEqual(before, snapshot(self.root))
        self.assertEqual(t.visible(self.root, self.cap), "g0")

    def test_symlink_payload_rejected_target_untouched(self):
        outside = self.base / "outside.fixture"
        outside.write_bytes(b"KEEP")
        target = self.root / "generations/g0" / t.NAMES[0]
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, self.cap)
        self.assertEqual(outside.read_bytes(), b"KEEP")

    def test_hardlink_payload_rejected(self):
        target = self.root / "generations/g0" / t.NAMES[0]
        os.link(target, self.base / "second-link.fixture")
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, self.cap)
        self.assertEqual(before, snapshot(self.root))

    def test_symlink_root_rejected(self):
        link = self.base / "synthetic-txn-link"
        link.symlink_to(self.root, target_is_directory=True)
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(link, self.cap)
        self.assertEqual(before, snapshot(self.root))

    def test_corrupt_pointer_rejected_without_guess(self):
        (self.root / "ACTIVE.json").write_bytes(b'{"generation":"g2"}')
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, self.cap)
        self.assertEqual(before, snapshot(self.root))

    def test_corrupt_temporary_pointer_preserved(self):
        (self.root / "ACTIVE.next").write_bytes(b"FOREIGN")
        before = snapshot(self.root)
        with self.assertRaises(t.Stopped):
            t.advance(self.root, self.cap)
        self.assertEqual(before, snapshot(self.root))

    def test_competing_writer_rejected(self):
        with (self.root / "LOCK").open("r+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = snapshot(self.root)
            result = self.cli("advance")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(before, snapshot(self.root))

    def test_rollback_retains_both_complete_generations(self):
        t.advance(self.root, self.cap)
        self.assertEqual(t.rollback(self.root, self.cap)["state"], "g0")
        self.assertEqual(t.visible(self.root, self.cap), "g0")
        t.validate_generation(self.root / "generations/g1", "g1")
        self.assert_old_retained()

    def test_reader_retains_old_pointer_descriptor_across_replace(self):
        t.advance(self.root, self.cap)
        t.rollback(self.root, self.cap)
        t.write_new(self.root / "ACTIVE.next", t.pointer("g1"))
        real_open = os.open
        switched = []
        def replace_after_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if Path(path) == self.root / "ACTIVE.json" and not switched:
                os.replace(self.root / "ACTIVE.next", self.root / "ACTIVE.json")
                self.assertEqual(os.fstat(fd).st_nlink, 0)
                switched.append(True)
            return fd
        with patch.object(os, "open", side_effect=replace_after_open):
            self.assertEqual(t.visible(self.root, self.cap), "g0")
        self.assertTrue(switched)
        self.assertEqual(t.visible(self.root, self.cap), "g1")

    def test_retry_after_post_commit_sync_error_reissues_directory_sync(self):
        with self.assertRaises(OSError):
            t.advance(self.root, self.cap, fail="sync_root")
        self.assertEqual(t.visible(self.root, self.cap), "g1")
        with patch.object(t, "sync_dir", wraps=t.sync_dir) as synced:
            result = t.advance(self.root, self.cap)
        self.assertTrue(result["idempotent"])
        self.assertEqual([call.args[0] for call in synced.call_args_list], [
            self.root / "generations/g1", self.root / "generations", self.root,
        ])

    def test_retry_generation_directory_sync_before_pointer_publication(self):
        with self.assertRaises(OSError):
            t.advance(self.root, self.cap, fail="sync_generation")
        self.assertEqual(t.visible(self.root, self.cap), "g0")
        with patch.object(t, "sync_dir", wraps=t.sync_dir) as synced:
            t.advance(self.root, self.cap)
        self.assertEqual([call.args[0] for call in synced.call_args_list], [
            self.root / "generations/g1", self.root / "generations", self.root,
        ])
        self.assertEqual(t.visible(self.root, self.cap), "g1")

    def test_reader_sees_complete_generation_during_pointer_switches(self):
        proc = subprocess.Popen(
            [sys.executable, "-B", str(HERE / "worker.py"), "reader_experiment",
             str(self.root), self.cap, "never"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        count = 0
        seen = set()
        deadline = time.monotonic() + 15
        try:
            while proc.poll() is None:
                self.assertLess(time.monotonic(), deadline)
                seen.add(t.visible(self.root, self.cap))
                count += 1
            out, err = proc.communicate(timeout=1)
            self.assertEqual(proc.returncode, 0, out + err)
            self.assertGreater(count, 0)
            self.assertEqual(seen, {"g0", "g1"})
            self.assertEqual(t.visible(self.root, self.cap), "g0")
            self.assert_old_retained()
            EVIDENCE["reader_snapshots"] = count
            EVIDENCE["reader_generations_seen"] = sorted(seen)
            EVIDENCE["pointer_switch_cycles"] = 40
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()


for phase in t.PHASES:
    setattr(TransactionTests, "test_process_exit_advance_" + phase,
            lambda self, phase=phase: self.crash_advance(phase))
for phase in t.ROLLBACK_PHASES:
    setattr(TransactionTests, "test_process_exit_rollback_" + phase,
            lambda self, phase=phase: self.crash_rollback(phase))
for fault in (
    "enospc", "short_write", "fsync", "enospc_manifest", "sync_stage",
    "rename_generation", "sync_generation", "enospc_pointer", "short_pointer",
    "fsync_pointer", "replace", "sync_root",
):
    setattr(TransactionTests, "test_injected_io_" + fault,
            lambda self, fault=fault: self.io_failure(fault))