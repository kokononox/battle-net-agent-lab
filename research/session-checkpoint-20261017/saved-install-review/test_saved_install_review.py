"""Synthetic Lab/game/cache tests; NO real user Install or native Windows."""
from pathlib import Path
from unittest.mock import patch
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
import contextlib
import sys
import types
import saved_install_review as review
import source_binding as b
import installed_profile_probe as p
from fixtures import Fixture
from profile_probe_tests.test_installed_profile_probe import game

RAW = b"IN\x01\x10" + bytes.fromhex("000100000002") + b"SYNTHETIC_PUBLIC_TEST_ONLY"
DESC = {"ckey": hashlib.md5(RAW).hexdigest(), "ekey": "1" * 32,
        "decoded_bytes": len(RAW), "encoded_bytes": len(RAW)}
AUDIT = Path("/data/retail-release-extracted/Portable-Retail-Sample/pinned_metadata")


class CountingStream:
    def __init__(self, wrapped, reads):
        self.wrapped, self.reads = wrapped, reads
    def __enter__(self):
        self.wrapped.__enter__()
        return self
    def __exit__(self, *args):
        return self.wrapped.__exit__(*args)
    def fileno(self):
        return self.wrapped.fileno()
    def read(self, amount):
        self.reads.append(amount)
        return self.wrapped.read(amount)


class ExactReader(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ["INSTALL_TEST_OUT"])
        self.root = Path(self.temp.name).resolve()
        self.lab = self.root / "lab"
        (self.lab / "objects").mkdir(parents=True)
        self.path = self.lab / "objects" / (DESC["ckey"] + "-" + str(len(RAW)) + ".decoded")
        self.watch = b.Watch()
    def tearDown(self):
        self.temp.cleanup()
    def observe(self, descriptor=DESC, **kwargs):
        return review.observe_exact(self.lab, descriptor, self.watch, **kwargs)
    def test_absent_no_search_or_open(self):
        with patch.object(Path, "open", side_effect=AssertionError("no file open")), \
                patch.object(os, "listdir", side_effect=AssertionError("no search")):
            result, absent = self.observe()
        self.assertFalse(result["content_identity_revalidated"])
        self.assertEqual(result["metadata_bytes_read"], 0)
        self.assertEqual(absent, str(self.path))
    def test_exact_one_read_and_safe_header_only(self):
        self.path.write_bytes(RAW)
        original, reads = Path.open, []
        def spy(path, *args, **kwargs):
            stream = original(path, *args, **kwargs)
            return CountingStream(stream, reads) if path == self.path else stream
        with patch.object(Path, "open", spy), patch.object(os, "listdir", side_effect=AssertionError("no search")):
            result, absent = self.observe()
        self.assertEqual(reads, [len(RAW)])
        self.assertIsNone(absent)
        self.assertTrue(result["content_identity_revalidated"])
        self.assertEqual(result["sha256"], hashlib.sha256(RAW).hexdigest())
        self.assertEqual(result["header_observation"]["first_10_bytes_hex"], RAW[:10].hex())
        self.assertNotIn("SYNTHETIC_PUBLIC_TEST_ONLY", json.dumps(result))
        self.assertFalse(result["schema_semantics_validated"])
    def test_wrong_size_rejected_before_open(self):
        self.path.write_bytes(RAW + b"x")
        with patch.object(Path, "open", side_effect=AssertionError("must not read")), self.assertRaisesRegex(b.BindingError, "size_conflict"):
            self.observe()
    def test_same_size_wrong_content_no_export(self):
        self.path.write_bytes(b"?" * len(RAW))
        with self.assertRaisesRegex(b.BindingError, "ckey_mismatch"):
            self.observe()
    def test_symlink_rejected_before_open(self):
        other = self.root / "elsewhere"
        other.write_bytes(RAW)
        self.path.symlink_to(other)
        with patch.object(Path, "open", side_effect=AssertionError("must not read")), self.assertRaises(b.BindingError):
            self.observe()
    def test_hardlink_rejected(self):
        self.path.write_bytes(RAW)
        os.link(self.path, self.root / "second-link")
        with self.assertRaises(b.BindingError):
            self.observe()
    def test_oversize_descriptor_before_io(self):
        with patch.object(Path, "lstat", side_effect=AssertionError("must reject before IO")), self.assertRaises(b.BindingError):
            self.observe(dict(DESC, decoded_bytes=review.MAX_INSTALL_READ + 1))
    def test_traversal_ckey_before_io(self):
        with self.assertRaises(b.BindingError):
            self.observe(dict(DESC, ckey="../private"))
    def test_cancel_before_read(self):
        self.path.write_bytes(RAW)
        def cancel():
            raise b.BindingError("install_cancelled")
        with patch.object(Path, "open", side_effect=AssertionError("must not read")), self.assertRaises(b.BindingError):
            self.observe(checked=cancel)
    def test_no_alternate_cache_fallback(self):
        (self.lab / "objects/alternative.decoded").write_bytes(RAW)
        result, _ = self.observe()
        self.assertEqual(result["metadata_bytes_read"], 0)
    def test_encoded_key_cache_not_used_as_decoded_install(self):
        (self.lab / "objects" / (review.INSTALL_EKEY + "-23106.decoded")).write_bytes(b"x" * 23106)
        result, _ = self.observe()
        self.assertEqual(result["metadata_bytes_read"], 0)
    def test_real_pinned_descriptor_rejects_synthetic_bytes(self):
        real = {"ckey": review.INSTALL_CKEY, "decoded_bytes": review.INSTALL_SIZE}
        exact = self.lab / "objects" / (review.INSTALL_CKEY + "-24078.decoded")
        exact.write_bytes(b"x" * 24078)
        with self.assertRaisesRegex(b.BindingError, "ckey_mismatch"):
            self.observe(real)
    def test_maximum_budget_is_exact_not_plus_one(self):
        raw = b"IN" + b"x" * (24078 - 2)
        descriptor = dict(DESC, ckey=hashlib.md5(raw).hexdigest(), decoded_bytes=24078)
        path = self.lab / "objects" / (descriptor["ckey"] + "-24078.decoded")
        path.write_bytes(raw)
        original, reads = Path.open, []
        def spy(current, *args, **kwargs):
            stream = original(current, *args, **kwargs)
            return CountingStream(stream, reads) if current == path else stream
        with patch.object(Path, "open", spy):
            result, _ = self.observe(descriptor)
        self.assertEqual(reads, [24078])
        self.assertEqual(result["metadata_bytes_read"], 24078)
    def test_unknown_header_observed_not_guessed(self):
        raw = b"XX" + RAW[2:]
        descriptor = dict(DESC, ckey=hashlib.md5(raw).hexdigest())
        path = self.lab / "objects" / (descriptor["ckey"] + "-" + str(len(raw)) + ".decoded")
        path.write_bytes(raw)
        result, _ = self.observe(descriptor)
        self.assertFalse(result["header_observation"]["first_two_bytes_equal_IN"])
        self.assertFalse(result["install_policy_proven"])


def source_snapshot(root):
    # Never read data.NNN; its metadata fingerprint suffices for write detection.
    return {
        str(path.relative_to(root)): (b.fp(path.stat()),
            None if path.name.startswith("data.") else hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.rglob("*") if path.is_file()
    }


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata = b.load_metadata(AUDIT, b.Watch())
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ["INSTALL_TEST_OUT"])
        self.root = Path(self.temp.name).resolve()
        self.game, self.config = game(self.root / "game")
        self.f = Fixture(self.root, self.metadata[2], b"\0" * 1024)
        self.f.storage.rename(self.game / "Data/data")
        self.f.storage = self.game / "Data/data"
        self.f.archive = self.f.storage / "data.000"
        self.f.edit(self.f.ev, "UPDATE evidence SET source_path=?", (str(self.f.archive),))
        self.f.refresh_snapshot()
        self.out = self.root / "new-report"
    def tearDown(self):
        self.temp.cleanup()
    def invoke(self, **kwargs):
        # Guard all archive opens and raw Download/Encoding cache access.
        original = Path.open
        def guard(path, *args, **kw):
            if path.name.startswith("data."):
                raise AssertionError("archive payload open forbidden")
            if path.suffix == ".decoded" and path.name not in {
                review.INSTALL_CKEY + "-24078.decoded",
                DESC["ckey"] + "-" + str(len(RAW)) + ".decoded",
            }:
                raise AssertionError("other metadata cache read forbidden")
            return original(path, *args, **kw)
        with patch.object(Path, "open", guard):
            return review.run(self.f.lab, AUDIT, self.game, self.out, **kwargs)
    def synthetic_success(self, **kwargs):
        path = self.f.objects / (DESC["ckey"] + "-" + str(len(RAW)) + ".decoded")
        path.write_bytes(RAW)
        before = source_snapshot(self.f.lab), source_snapshot(self.game)
        # Explicit test-only substitution; no CLI or runtime model override exists.
        with patch.object(review, "pinned_descriptor", return_value=DESC):
            result = self.invoke(**kwargs)
        self.assertEqual(before, (source_snapshot(self.f.lab), source_snapshot(self.game)))
        return result
    def test_production_missing_cache_bound_report(self):
        before = source_snapshot(self.f.lab), source_snapshot(self.game)
        result, final = self.invoke()
        self.assertEqual(result["status"], "bound_install_metadata_unavailable")
        self.assertEqual(result["scope"]["saved_install_metadata_bytes_read"], 0)
        self.assertEqual(json.loads(final.read_text()), result)
        self.assertEqual(before, (source_snapshot(self.f.lab), source_snapshot(self.game)))
        self.assertEqual(result["scope"]["saved_download_metadata_bytes_read"], 0)
    def test_synthetic_full_success_no_archive_reads_or_writes(self):
        result, final = self.synthetic_success()
        self.assertEqual(result["status"], "bound_install_identity_observed_policy_unresolved")
        self.assertEqual(result["scope"]["saved_install_metadata_bytes_read"], len(RAW))
        self.assertEqual(result["scope"]["archive_payload_bytes_read"], 0)
        self.assertEqual(result["scope"]["game_metadata_files_read"], 2)
        self.assertFalse(result["installation_ready"])
        self.assertIsNone(result["required_network_download_bytes"])
        self.assertTrue(final.is_file())
    def test_same_size_wrong_real_pin_stops_no_report(self):
        (self.f.objects / (review.INSTALL_CKEY + "-24078.decoded")).write_bytes(b"X" * 24078)
        with self.assertRaisesRegex(b.BindingError, "ckey_mismatch"):
            self.invoke()
        self.assertFalse(self.out.exists())
    def test_other_game_root_not_silently_used(self):
        other, _ = game(self.root / "other-game")
        with self.assertRaises(OSError):
            review.review(self.f.lab, AUDIT, other)
    def test_existing_output_not_overwritten(self):
        self.out.mkdir()
        keep = self.out / "INSTALL-REVIEW-to-share.json"
        keep.write_bytes(b"KEEP")
        with self.assertRaises(b.BindingError):
            self.invoke()
        self.assertEqual(keep.read_bytes(), b"KEEP")
    def test_publication_race_preserves_other_winner(self):
        original = p.publish_noreplace
        def race(source, destination):
            Path(destination).write_bytes(b"RACE-WINNER")
            return original(source, destination)
        with patch.object(p, "publish_noreplace", side_effect=race), self.assertRaises(OSError):
            self.invoke()
        self.assertEqual((self.out / "INSTALL-REVIEW-to-share.json").read_bytes(), b"RACE-WINNER")
        self.assertEqual(list(self.out.glob("*.pending")), [])
    def test_output_symlink_ancestor_rejected(self):
        parent = self.root / "output-link"
        real = self.root / "real-output"
        real.mkdir()
        parent.symlink_to(real, target_is_directory=True)
        self.out = parent / "new"
        with self.assertRaises(b.BindingError):
            self.invoke()
        self.assertFalse((real / "new").exists())
    def test_output_inside_Lab_rejected(self):
        self.out = self.f.lab / "forbidden-new"
        with self.assertRaises(b.BindingError):
            self.invoke()
        self.assertFalse(self.out.exists())
    def test_output_inside_game_rejected(self):
        self.out = self.game / "forbidden-new"
        with self.assertRaises(b.BindingError):
            self.invoke()
        self.assertFalse(self.out.exists())
    def test_absent_cache_appearing_during_publication_stops(self):
        def progress(stage):
            if stage == "write_pending_report":
                (self.f.objects / (review.INSTALL_CKEY + "-24078.decoded")).write_bytes(b"x" * 24078)
        with self.assertRaisesRegex(b.BindingError, "appeared"):
            self.invoke(progress=progress)
        self.assertFalse((self.out / "INSTALL-REVIEW-to-share.json").exists())
    def test_input_change_before_publication_stops(self):
        def progress(stage):
            if stage == "write_pending_report":
                self.config.write_bytes(self.config.read_bytes() + b"\n")
        with self.assertRaises(b.BindingError):
            self.invoke(progress=progress)
        self.assertFalse((self.out / "INSTALL-REVIEW-to-share.json").exists())
    def test_postpublication_change_removes_own_report(self):
        def progress(stage):
            if stage == "postpublication_recheck":
                self.config.write_bytes(self.config.read_bytes() + b"\n")
        with self.assertRaises(b.BindingError):
            self.invoke(progress=progress)
        self.assertFalse((self.out / "INSTALL-REVIEW-to-share.json").exists())
    def test_report_never_exports_private_data(self):
        result, _ = self.invoke()
        text = json.dumps(result)
        for secret in (str(self.root), "PRIVATE", "PRIVATE123", "PRIVATE456", "source_path", "KeyRing"):
            self.assertNotIn(secret, text)
    def test_cancel_stops_without_output(self):
        with self.assertRaises(b.BindingError):
            self.invoke(cancel=lambda: True)
        self.assertFalse(self.out.exists())
    def test_missing_snapshot_archive_is_not_rebuilt(self):
        self.f.archive.unlink()
        with self.assertRaises(b.BindingError):
            self.invoke()
        self.assertFalse(self.f.archive.exists())
    def test_pin_descriptor_matches_existing_config(self):
        descriptor = review.pinned_descriptor((AUDIT / "build.config").read_bytes())
        self.assertEqual(descriptor["ckey"], "d7c8cd9845e2b5d39821678f481324da")
        self.assertEqual(descriptor["decoded_bytes"], 24078)
    def test_no_pinned_config_mutation_accepted(self):
        with self.assertRaises(audit_exception_types()):
            review.pinned_descriptor((AUDIT / "build.config").read_bytes() + b"\n")
    def test_public_error_redacts_paths_and_free_text(self):
        result = review.public_error(OSError("PRIVATE/path/password"), "read_exact_install")
        self.assertNotIn("PRIVATE", json.dumps(result))
    def test_network_hook_blocks_socket_operations(self):
        with self.assertRaisesRegex(b.BindingError, "network_forbidden"):
            review.block_network("socket.connect", ())
    def test_windows_publication_contract_modeled(self):
        pending = self.root / "pending"
        pending.write_bytes(b"MODEL")
        final = self.root / "final"
        # Patch only the branch selector, not a claim of native Windows execution.
        with patch.object(p.sys, "platform", "win32"), patch.object(p.os, "rename") as mocked:
            p.publish_noreplace(pending, final)
            mocked.assert_called_once_with(pending, final)

class Launcher(unittest.TestCase):
    def cancelled(self, choices):
        import saved_install_launcher as launcher
        root = types.SimpleNamespace(withdraw=lambda: None, destroy=lambda: None)
        tk = types.ModuleType("tkinter")
        tk.Tk = lambda: root
        dialog = types.ModuleType("tkinter.filedialog")
        values = iter(choices)
        dialog.askdirectory = lambda **kwargs: next(values)
        tk.filedialog = dialog
        with patch.dict(sys.modules, {"tkinter": tk, "tkinter.filedialog": dialog}), \
                patch.object(review, "run", side_effect=AssertionError("cancel must not review inputs")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(launcher.main(), 0)
    def test_cancel_first_picker_no_read(self):
        self.cancelled([""])
    def test_cancel_second_picker_no_read(self):
        self.cancelled(["SYNTHETIC_LAB", ""])


def audit_exception_types():
    import patch_audit
    return (b.BindingError, patch_audit.AuditError)