import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repair_core as core


class SimulatedCrash(BaseException):
    pass


def encoded(data, mode=b"Z", table=False):
    chunk = mode + (zlib.compress(data) if mode == b"Z" else data)
    if table:
        header = b"BLTE" + (36).to_bytes(4, "big") + b"\x0f\0\0\1"
        header += struct.pack(">II", len(chunk), len(data)) + hashlib.md5(chunk).digest()
        b = header + chunk
        key = hashlib.md5(header).hexdigest()
    else:
        b = b"BLTE\0\0\0\0" + chunk
        key = hashlib.md5(b).hexdigest()
    return b, key


def make_spec(name, data, table=False, archive_offset=None):
    b, key = encoded(data, table=table)
    route_key = "a" * 32 if archive_offset is not None else key
    return core.Spec(name, hashlib.md5(data).hexdigest(), len(data), key, len(b),
                     "https://fixtures.invalid/tpr/wow/data/" +
                     route_key[:2] + "/" + route_key[2:4] + "/" + route_key,
                     archive_offset), b


class Response(io.BytesIO):
    def __init__(self, body, url, headers, status):
        super().__init__(body)
        self.url, self.headers, self.status = url, headers, status

    def geturl(self):
        return self.url


class Transport:
    def __init__(self, spec, blob, cut=None, mutate=None):
        self.spec, self.blob, self.cut = spec, blob, cut
        self.requests = []
        self.mutate = mutate
        self.edit = lambda r: r

    def open(self, url, headers):
        self.requests.append((url, dict(headers)))
        start, end = 0, len(self.blob) - 1
        offset = self.spec.archive_offset or 0
        ranged = "Range" in headers
        if ranged:
            a, b = headers["Range"][6:].split("-")
            start, end = int(a) - offset, int(b) - offset
        body = self.blob[start:end + 1]
        h = {"Content-Length": str(len(body))}
        if ranged:
            h["Content-Range"] = "bytes %d-%d/%d" % (
                start + offset, end + offset, offset + len(self.blob))
        if self.cut is not None:
            body = body[:self.cut]
        if self.mutate:
            self.mutate()
        return self.edit(Response(body, url, h, 206 if ranged else 200))


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.lab = core.Lab.create(self.base / "owned")
        self.good = b"synthetic desired standalone data" * 5000
        self.spec, self.blob = make_spec("_retail_/Bin/Test.dll", self.good)
        self.net = Transport(self.spec, self.blob)
        self.cancel = threading.Event()

    def put(self, name, data):
        p = self.lab.target(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def target(self):
        return self.lab.target(self.spec.path)

    def runrepair(self, **kw):
        return core.repair(self.lab, [self.spec], self.net, self.cancel, **kw)

    def tx(self):
        return next((self.lab.root / "transactions").glob("tx-*"))

    def crash(self, at):
        def fail(stage):
            if at == stage:
                raise SimulatedCrash(stage)
        return fail

    def test_missing_download_decode_apply_and_readback(self):
        r = self.runrepair()
        self.assertEqual(r["status"], "committed")
        self.assertEqual(r["files_repaired"], 1)
        self.assertEqual(self.target().read_bytes(), self.good)
        self.assertEqual(core.scan(self.lab, [self.spec])[0]["status"], "healthy")
        self.assertFalse((self.tx() / "0.backup").exists())

    def test_damaged_is_backed_up_then_repaired(self):
        old = b"broken content"
        self.put(self.spec.path, old)
        self.runrepair()
        self.assertEqual((self.tx() / "0.backup").read_bytes(), old)
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_same_size_bad_hash_is_damaged(self):
        self.put(self.spec.path, b"x" * len(self.good))
        self.assertEqual(core.scan(self.lab, [self.spec])[0]["status"], "damaged")

    def test_healthy_no_network_no_transaction(self):
        self.put(self.spec.path, self.good)
        r = self.runrepair()
        self.assertEqual(r["status"], "already_healthy")
        self.assertEqual(self.net.requests, [])
        self.assertEqual(list((self.lab.root / "transactions").iterdir()), [])

    def test_repeat_idempotent(self):
        self.runrepair()
        n = len(self.net.requests)
        self.assertEqual(self.runrepair()["status"], "already_healthy")
        self.assertEqual(len(self.net.requests), n)

    def test_resume_after_truncated_download(self):
        self.net.cut = 17
        with self.assertRaisesRegex(core.RepairError, "interrupted"):
            self.runrepair()
        part = next((self.lab.root / "objects").glob("*.part"))
        self.assertEqual(part.read_bytes(), self.blob[:17])
        self.assertFalse(self.target().exists())
        self.net.cut = None
        self.runrepair()
        self.assertEqual(self.net.requests[1][1]["Range"],
                         "bytes=17-" + str(len(self.blob) - 1))
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_resume_archive_offset(self):
        self.spec, self.blob = make_spec(self.spec.path, self.good, archive_offset=1234)
        self.net = Transport(self.spec, self.blob, cut=11)
        with self.assertRaises(core.RepairError):
            self.runrepair()
        self.net.cut = None
        self.runrepair()
        self.assertEqual(self.net.requests[1][1]["Range"],
                         "bytes=1245-" + str(1234 + len(self.blob) - 1))

    def test_complete_retained_encoded_no_redownload(self):
        core.fetch_decoded(self.lab, self.spec, self.net)
        next((self.lab.root / "objects").glob("*.decoded")).unlink()
        self.net.open = lambda *a: self.fail("unexpected redownload")
        self.runrepair()
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_decoded_cache_reused_without_network(self):
        core.fetch_decoded(self.lab, self.spec, self.net)
        for p in (self.lab.root / "objects").glob("*.part"):
            p.unlink()
        self.net.open = lambda *a: self.fail("unexpected request")
        self.runrepair()
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_bad_cached_decoded_quarantined_and_refetched(self):
        cached = core.fetch_decoded(self.lab, self.spec, self.net)
        cached.write_bytes(b"bad")
        self.runrepair()
        self.assertTrue(list((self.lab.root / "objects").glob("*.decoded.rejected-*")))
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_corrupt_encoded_prefix_never_applied(self):
        self.net.cut = 17
        with self.assertRaises(core.RepairError):
            self.runrepair()
        part = next((self.lab.root / "objects").glob("*.part"))
        part.write_bytes(b"!" + part.read_bytes()[1:])
        self.net.cut = None
        with self.assertRaisesRegex(core.RepairError, "payload_"):
            self.runrepair()
        self.assertFalse(self.target().exists())
        self.assertTrue(list((self.lab.root / "objects").glob("*.part.rejected-*")))
        self.runrepair()
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_oversized_partial_rejected_and_retained(self):
        self.net.cut = 5
        with self.assertRaises(core.RepairError):
            self.runrepair()
        next((self.lab.root / "objects").glob("*.part")).write_bytes(
            self.blob + b"extra")
        with self.assertRaisesRegex(core.RepairError, "partial_oversized"):
            self.runrepair()
        self.assertFalse(self.target().exists())

    def test_chunk_table_proofs(self):
        self.spec, self.blob = make_spec(self.spec.path, self.good, table=True)
        self.net = Transport(self.spec, self.blob)
        self.runrepair()
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_bad_ckey_does_not_write_target(self):
        self.spec = replace(self.spec, ckey="0" * 32)
        with self.assertRaisesRegex(core.RepairError, "payload_"):
            self.runrepair()
        self.assertFalse(self.target().exists())

    def test_wrong_ekey_no_apply(self):
        self.spec, self.blob = make_spec(self.spec.path, self.good, table=True,
                                        archive_offset=500)
        self.spec = replace(self.spec, ekey="0" * 32)
        self.net = Transport(self.spec, self.blob)
        with self.assertRaisesRegex(core.RepairError, "payload_"):
            self.runrepair()
        self.assertFalse(self.target().exists())

    def test_unknown_mode_fail_closed(self):
        self.blob, key = encoded(self.good, mode=b"E")
        self.spec = replace(self.spec, ekey=key, encoded_size=len(self.blob),
                            url="https://fixtures.invalid/tpr/wow/data/" +
                            key[:2] + "/" + key[2:4] + "/" + key)
        self.net = Transport(self.spec, self.blob)
        with self.assertRaisesRegex(core.RepairError, "unsupported_or_encrypted"):
            self.runrepair()
        self.assertFalse(self.target().exists())

    def response_failure(self, edit):
        self.net.edit = edit
        with self.assertRaises(core.RepairError):
            self.runrepair()
        self.assertFalse(self.target().exists())

    def test_ignored_resume_range_rejected(self):
        self.net.cut = 11
        with self.assertRaises(core.RepairError):
            self.runrepair()
        self.net.cut = None
        def edit(r):
            r.status = 200
            return r
        self.response_failure(edit)

    def test_bad_content_range_rejected(self):
        self.spec, self.blob = make_spec(self.spec.path, self.good, archive_offset=1)
        self.net = Transport(self.spec, self.blob)
        def edit(r):
            r.headers["Content-Range"] = "bytes 0-1/2"
            return r
        self.response_failure(edit)

    def test_bad_content_length_rejected(self):
        def edit(r):
            r.headers["Content-Length"] = "999999999"
            return r
        self.response_failure(edit)

    def test_changed_url_rejected(self):
        def edit(r):
            r.url = "https://evil.invalid/"
            return r
        self.response_failure(edit)

    def test_http_content_encoding_rejected(self):
        def edit(r):
            r.headers["Content-Encoding"] = "gzip"
            return r
        self.response_failure(edit)

    def test_extra_response_bytes_rejected(self):
        def edit(r):
            return Response(r.getvalue() + b"extra", r.url, r.headers, r.status)
        self.response_failure(edit)

    def test_transfer_encoding_rejected(self):
        def edit(r):
            r.headers["Transfer-Encoding"] = "chunked"
            return r
        self.response_failure(edit)

    def test_cancel_before_download(self):
        self.cancel.set()
        with self.assertRaises(core.Cancelled):
            self.runrepair()
        self.assertEqual(self.net.requests, [])

    def test_cancel_during_download_retains_partial_no_apply(self):
        original = self.net.open
        def opening(*a):
            r = original(*a)
            read = r.read
            def cancel_read(n):
                b = read(min(n, 10))
                self.cancel.set()
                return b
            r.read = cancel_read
            return r
        self.net.open = opening
        with self.assertRaises(core.Cancelled):
            self.runrepair()
        self.assertFalse(self.target().exists())
        self.assertEqual(next((self.lab.root / "objects").glob("*.part")).stat().st_size, 10)

    def test_failure_after_replace_restores_damaged_original(self):
        self.put(self.spec.path, b"original")
        def fail(stage):
            if stage == "replaced:0":
                raise OSError("injected ordinary failure")
        with self.assertRaises(OSError):
            self.runrepair(failpoint=fail)
        self.assertEqual(self.target().read_bytes(), b"original")
        self.assertEqual(core.load_json(self.tx() / "journal.json")["status"], "rolled_back")

    def test_failure_after_new_file_replace_removes_only_new_file(self):
        def fail(stage):
            if stage == "replaced:0":
                raise OSError("injected")
        with self.assertRaises(OSError):
            self.runrepair(failpoint=fail)
        self.assertFalse(self.target().exists())

    def test_crash_after_replace_before_journal_recover_original(self):
        self.put(self.spec.path, b"old")
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("replaced:0"))
        self.assertEqual(self.target().read_bytes(), self.good)
        reopened = core.Lab(self.lab.root)
        self.assertEqual(core.recover(reopened)[0]["status"], "rolled_back")
        self.assertEqual(self.target().read_bytes(), b"old")
        self.assertEqual(core.recover(reopened)[0]["status"], "rolled_back")

    def test_crash_prepared_no_target_change(self):
        self.put(self.spec.path, b"old")
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("prepared"))
        core.recover(self.lab)
        self.assertEqual(self.target().read_bytes(), b"old")

    def test_crash_after_row_recorded_recover_missing_state(self):
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("recorded:0"))
        core.recover(self.lab)
        self.assertFalse(self.target().exists())

    def test_committed_crash_does_not_rollback(self):
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("committed"))
        self.assertEqual(core.recover(self.lab)[0]["status"], "committed")
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_recovery_preserves_external_edit(self):
        self.put(self.spec.path, b"old")
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("replaced:0"))
        self.target().write_bytes(b"external edit")
        with self.assertRaisesRegex(core.RepairError, "conflict"):
            core.recover(self.lab)
        self.assertEqual(self.target().read_bytes(), b"external edit")
        self.assertEqual((self.tx() / "0.backup").read_bytes(), b"old")

    def test_corrupt_backup_blocks_recovery_without_overwrite(self):
        self.put(self.spec.path, b"old")
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("replaced:0"))
        (self.tx() / "0.backup").write_bytes(b"damaged backup")
        with self.assertRaisesRegex(core.RepairError, "backup_invalid"):
            core.recover(self.lab)
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_changed_during_download_not_overwritten(self):
        self.put(self.spec.path, b"old")
        self.net.mutate = lambda: self.target().write_bytes(b"other writer")
        with self.assertRaisesRegex(core.RepairError, "changed_since_scan"):
            self.runrepair()
        self.assertEqual(self.target().read_bytes(), b"other writer")

    def test_changed_after_prepare_preserved(self):
        self.put(self.spec.path, b"old")
        def fail(stage):
            if stage == "prepared":
                self.target().write_bytes(b"other writer")
        with self.assertRaisesRegex(core.RepairError, "conflict"):
            self.runrepair(failpoint=fail)
        self.assertEqual(self.target().read_bytes(), b"other writer")

    def test_corrupt_stage_not_installed(self):
        self.put(self.spec.path, b"old")
        def fail(stage):
            if stage == "prepared":
                (self.tx() / "0.stage").write_bytes(b"bad")
        with self.assertRaisesRegex(core.RepairError, "readback"):
            self.runrepair(failpoint=fail)
        self.assertEqual(self.target().read_bytes(), b"old")

    def test_cancel_after_first_replace_rolls_back(self):
        self.put(self.spec.path, b"old")
        def fail(stage):
            if stage == "replaced:0":
                self.cancel.set()
        with self.assertRaises(core.Cancelled):
            self.runrepair(failpoint=fail)
        self.assertEqual(self.target().read_bytes(), b"old")

    def test_user_files_untouched(self):
        personal = {}
        for name in ("WTF/config.wtf", "Interface/AddOns/Foo/main.lua",
                     "Screenshots/test.jpg", "Cache/random"):
            p = self.lab.root / "target" / "_retail_" / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"personal data")
            personal[p] = p.read_bytes()
        self.runrepair()
        self.assertTrue(all(p.read_bytes() == b for p, b in personal.items()))

    def test_protected_path_candidates_rejected(self):
        for name in ("_retail_/WTF/config.wtf", "_retail_/Interface/x",
                     "_retail_/Screenshots/x", "_retail_/Data/x",
                     "_retail_/.build.info", "../Wow.exe",
                     "_retail_/../Wow.exe", "_retail_/foo:bar",
                     "_retail_/CON.txt", "_retail_/a.", "_retail_/a\\b",
                     "_retail_//a", "/tmp/a", "_retail_/Logs/x"):
            with self.subTest(name=name), self.assertRaises(core.RepairError):
                replace(self.spec, path=name).validate()

    def test_duplicate_casefold_path_rejected(self):
        with self.assertRaisesRegex(core.RepairError, "duplicate_target"):
            core.specs_guard([self.spec, replace(self.spec, path="_retail_/bin/test.DLL")])

    def test_file_directory_conflict_rejected_in_both_orders(self):
        parent = replace(self.spec, path="_retail_/Bin")
        for items in ([self.spec, parent], [parent, self.spec]):
            with self.assertRaisesRegex(core.RepairError, "file_directory"):
                core.specs_guard(items)

    def test_bool_size_and_offset_rejected(self):
        for kw in ({"encoded_size": True}, {"decoded_size": False},
                   {"archive_offset": True}):
            with self.assertRaises(core.RepairError):
                replace(self.spec, **kw).validate()

    def test_invalid_route_rejected(self):
        for url in ("http://fixtures.invalid/x", "https://u:p@fixtures.invalid/x",
                    self.spec.url + "?secret=1", self.spec.url + "#x",
                    "https://fixtures.invalid/invalid", self.spec.url.replace(":443", ":9")):
            if url == self.spec.url:
                continue
            with self.subTest(url=url), self.assertRaises(core.RepairError):
                replace(self.spec, url=url).validate()

    def test_refuse_existing_directory_as_workspace(self):
        game = self.base / "existing-game"
        game.mkdir()
        (game / ".build.info").write_bytes(b"untouched")
        with self.assertRaisesRegex(core.RepairError, "new_workspace"):
            core.Lab.create(game)
        self.assertEqual((game / ".build.info").read_bytes(), b"untouched")

    def test_refuse_arbitrary_directory_without_marker(self):
        with self.assertRaises((core.RepairError, FileNotFoundError)):
            core.Lab(self.base)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_symlink_target_rejected_external_unchanged(self):
        outside = self.base / "outside"
        outside.write_bytes(b"untouched")
        self.target().parent.mkdir(parents=True)
        self.target().symlink_to(outside)
        with self.assertRaisesRegex(core.RepairError, "link_or_reparse"):
            self.runrepair()
        self.assertEqual(outside.read_bytes(), b"untouched")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_symlink_parent_rejected(self):
        outside = self.base / "outside-dir"
        outside.mkdir()
        p = self.lab.root / "target" / "_retail_"
        p.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(core.RepairError):
            self.runrepair()
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(hasattr(os, "link"), "hardlink unavailable")
    def test_shared_hardlink_rejected(self):
        outside = self.base / "outside"
        outside.write_bytes(b"old")
        self.target().parent.mkdir(parents=True)
        os.link(outside, self.target())
        with self.assertRaisesRegex(core.RepairError, "unshared"):
            self.runrepair()
        self.assertEqual(outside.read_bytes(), b"old")

    def test_lock_blocks_second_engine(self):
        with self.lab.lock():
            with self.assertRaisesRegex(core.RepairError, "workspace_busy"):
                self.runrepair()

    def test_low_space_download_no_request(self):
        with patch("repair_core.shutil.disk_usage") as usage:
            usage.return_value.free = 0
            with self.assertRaisesRegex(core.RepairError, "insufficient_space"):
                self.runrepair()
        self.assertEqual(self.net.requests, [])

    def test_low_space_transaction_preserves_original(self):
        self.put(self.spec.path, b"old")
        core.fetch_decoded(self.lab, self.spec, self.net)
        with patch("repair_core.shutil.disk_usage") as usage:
            usage.return_value.free = 0
            with self.assertRaisesRegex(core.RepairError, "insufficient_transaction"):
                self.runrepair()
        self.assertEqual(self.target().read_bytes(), b"old")

    def test_space_budget_reserves_larger_original_for_rollback(self):
        original = b"x" * (1024 * 1024)
        self.put(self.spec.path, original)
        core.fetch_decoded(self.lab, self.spec, self.net)
        # Enough for backups + new stage + new-file temporary, but NOT the
        # larger old-file temporary needed during rollback.
        incomplete_budget = 64 * 1024**2 + len(original) + 2 * len(self.good) + 1
        with patch("repair_core.shutil.disk_usage") as usage:
            usage.return_value.free = incomplete_budget
            with self.assertRaisesRegex(core.RepairError, "insufficient_transaction"):
                self.runrepair()
        self.assertEqual(self.target().read_bytes(), original)

    def test_invalid_port_is_safe_validation_error(self):
        url = self.spec.url.replace("fixtures.invalid", "fixtures.invalid:invalid")
        with self.assertRaisesRegex(core.RepairError, "invalid_https_route"):
            replace(self.spec, url=url).validate()

    def test_tampered_journal_path_cannot_escape(self):
        self.put(self.spec.path, b"old")
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("prepared"))
        jp = self.tx() / "journal.json"
        j = core.load_json(jp)
        j["rows"][0]["path"] = "../outside"
        core.atomic_json(jp, j)
        with self.assertRaises(core.RepairError):
            core.recover(self.lab)
        self.assertEqual(self.target().read_bytes(), b"old")

    def test_wrong_workspace_journal_rejected(self):
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("prepared"))
        jp = self.tx() / "journal.json"
        j = core.load_json(jp)
        j["workspace"] = "0" * 32
        core.atomic_json(jp, j)
        with self.assertRaisesRegex(core.RepairError, "invalid_transaction"):
            core.recover(self.lab)

    def test_duplicate_json_key_rejected(self):
        p = self.lab.root / "duplicate.json"
        p.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(core.RepairError, "duplicate_json"):
            core.load_json(p)

    def test_preparation_crash_without_journal_never_replayed(self):
        tx = self.lab.root / "transactions" / ("tx-" + "b" * 32)
        tx.mkdir()
        (tx / "0.stage").write_bytes(b"unused")
        self.assertEqual(core.recover(self.lab)[0]["status"],
                         "preparation_incomplete_retained")

    def test_multi_file_failure_restores_entire_preflighted_set(self):
        second, blob2 = make_spec("_retail_/Second.dll", b"second replacement")
        self.put(self.spec.path, b"old first")
        second_target = self.lab.target(second.path)
        second_target.parent.mkdir(parents=True, exist_ok=True)
        second_target.write_bytes(b"old second")
        a, b = self.net, Transport(second, blob2)
        class Routing:
            def open(self, url, headers):
                return (a if url == a.spec.url else b).open(url, headers)
        def fail(stage):
            if stage == "replaced:1":
                raise OSError("injected second file failure")
        with self.assertRaises(OSError):
            core.repair(self.lab, [self.spec, second], Routing(), failpoint=fail)
        self.assertEqual(self.target().read_bytes(), b"old first")
        self.assertEqual(second_target.read_bytes(), b"old second")

    def test_recovery_preflight_conflict_does_not_partially_restore(self):
        second, blob2 = make_spec("_retail_/Second.dll", b"second")
        self.put(self.spec.path, b"old first")
        self.put(second.path, b"old second")
        a, b = self.net, Transport(second, blob2)
        class Routing:
            def open(self, url, headers):
                return (a if url == a.spec.url else b).open(url, headers)
        with self.assertRaises(SimulatedCrash):
            core.repair(self.lab, [self.spec, second], Routing(),
                        failpoint=self.crash("replaced:1"))
        self.target().write_bytes(b"external edit")
        with self.assertRaisesRegex(core.RepairError, "conflict"):
            core.recover(self.lab)
        self.assertEqual(self.lab.target(second.path).read_bytes(), b"second")
        self.assertEqual(self.target().read_bytes(), b"external edit")

    def test_old_committed_journal_not_replayed_over_new_version(self):
        self.runrepair()
        new = b"newer content"
        second, blob = make_spec(self.spec.path, new)
        core.repair(self.lab, [second], Transport(second, blob))
        core.recover(self.lab)
        self.assertEqual(self.target().read_bytes(), new)

    def test_automatic_recovery_before_next_attempt(self):
        self.put(self.spec.path, b"old")
        with self.assertRaises(SimulatedCrash):
            self.runrepair(failpoint=self.crash("replaced:0"))
        self.runrepair()
        self.assertEqual(self.target().read_bytes(), self.good)

    def child_crash(self, point):
        code = r'''
import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
sys.path.insert(0,str(Path(sys.argv[1])/"tests"))
import repair_core as c
from test_repair_core import make_spec,Transport
lab=c.Lab(sys.argv[2])
spec,blob=make_spec("_retail_/Bin/Test.dll",b"child-process-synthetic-target")
def fail(stage):
    if stage==sys.argv[3]:
        os._exit(73)
c.repair(lab,[spec],Transport(spec,blob),failpoint=fail)
raise SystemExit(99)
'''
        run = subprocess.run([sys.executable, "-B", "-c", code,
                              str(Path(core.__file__).parent), str(self.lab.root), point],
                             capture_output=True, timeout=15)
        self.assertEqual(run.returncode, 73, run.stderr.decode())

    def test_actual_process_exit_after_replace_recovery_and_lock_release(self):
        self.put(self.spec.path, b"original before process died")
        self.child_crash("replaced:0")
        self.assertEqual(self.target().read_bytes(), b"child-process-synthetic-target")
        core.recover(core.Lab(self.lab.root))
        self.assertEqual(self.target().read_bytes(), b"original before process died")

    def test_actual_process_exit_before_first_replacement(self):
        self.put(self.spec.path, b"old")
        self.child_crash("prepared")
        core.recover(core.Lab(self.lab.root))
        self.assertEqual(self.target().read_bytes(), b"old")

    def test_actual_process_exit_after_commit_does_not_undo(self):
        self.put(self.spec.path, b"old")
        self.child_crash("committed")
        self.assertEqual(core.recover(self.lab)[0]["status"], "committed")
        self.assertEqual(self.target().read_bytes(), b"child-process-synthetic-target")

    def test_replace_system_failure_does_not_destroy_old_target(self):
        self.put(self.spec.path, b"old")
        real = core.os.replace
        def failing(src, dst):
            if Path(dst) == self.target():
                raise OSError("replacement denied")
            return real(src, dst)
        with patch("repair_core.os.replace", side_effect=failing):
            with self.assertRaises(OSError):
                self.runrepair()
        self.assertEqual(self.target().read_bytes(), b"old")

    def test_failure_persisting_applied_row_recovers_using_disk_journal(self):
        self.put(self.spec.path, b"old")
        real = core.atomic_json
        once = [False]
        def failing(path, obj):
            if (path.name == "journal.json" and obj.get("status") == "applying"
                    and obj["rows"][0]["applied"] and not once[0]):
                once[0] = True
                raise OSError("journal write failure")
            return real(path, obj)
        with patch("repair_core.atomic_json", side_effect=failing):
            with self.assertRaises(OSError):
                self.runrepair()
        self.assertEqual(self.target().read_bytes(), b"old")
        self.assertEqual(core.load_json(self.tx() / "journal.json")["status"], "rolled_back")

    def test_commit_write_error_after_durable_commit_never_rolls_back(self):
        self.put(self.spec.path, b"old")
        real = core.atomic_json
        def failing(path, obj):
            real(path, obj)
            if path.name == "journal.json" and obj.get("status") == "committed":
                raise OSError("post-commit directory sync failure")
        with patch("repair_core.atomic_json", side_effect=failing):
            with self.assertRaises(OSError):
                self.runrepair()
        self.assertEqual(core.recover(self.lab)[0]["status"], "committed")
        self.assertEqual(self.target().read_bytes(), self.good)

    def test_first_journal_write_failure_does_not_touch_original(self):
        self.put(self.spec.path, b"old")
        real = core.atomic_json
        def failing(path, obj):
            if path.name == "journal.json":
                raise OSError("journal unavailable")
            return real(path, obj)
        with patch("repair_core.atomic_json", side_effect=failing):
            with self.assertRaises(OSError):
                self.runrepair()
        self.assertEqual(self.target().read_bytes(), b"old")

    def test_offline_end_to_end_demo(self):
        import demo
        with patch("socket.socket", side_effect=AssertionError("unexpected network")):
            r = demo.demo(self.base / "demo-owned")
        self.assertEqual(r["download_resumed_at_byte"], 11)
        self.assertTrue(r["failure_restored_original"])
        self.assertEqual(r["second_repair_status"], "already_healthy")
        self.assertFalse(r["full_WoW_update_proven"])


if __name__ == "__main__":
    unittest.main()