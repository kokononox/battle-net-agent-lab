from dataclasses import dataclass, replace
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import install_download_coverage as c
import metadata_link_review as g
from pinned_download_model import Model, PINNED_MODEL

KEYS = ["11" * 16, "22" * 16, "33" * 16]


def fixture(records=None, bits=None, tags=PINNED_MODEL.tags):
    records = records if records is not None else [(KEYS[i], 10 + i, i) for i in range(3)]
    n = len(records)
    raw = b"DL\x01\x10\x00" + n.to_bytes(4, "big") + len(tags).to_bytes(2, "big")
    raw += b"".join(bytes.fromhex(k) + size.to_bytes(5, "big") + bytes([priority])
                    for k, size, priority in records)
    width = (n + 7) // 8
    bits = bits or {}
    for name, kind in tags:
        raw += name.encode() + b"\0" + kind.to_bytes(2, "big")
        mask = bits.get(name, 0)
        raw += mask.to_bytes(width, "big")
    model = Model("SYNTHETIC-TEST-ONLY", hashlib.md5(raw).hexdigest(),
                  hashlib.sha256(raw).hexdigest(), len(raw), 1, n, tags)
    return raw, model


@dataclass
class Entry:
    name: str
    digest: bytes
    declared_size: int


@dataclass
class Layout:
    entries: tuple


class ParserTests(unittest.TestCase):
    def parse(self, raw, model, wanted=None):
        return c.parse_download(io.BytesIO(raw), wanted or set(KEYS), model=model)

    def test_exact_one_pass_and_metadata_only(self):
        raw, model = fixture()
        result, used = self.parse(raw, model)
        self.assertEqual(used, len(raw))
        self.assertEqual([result[k][0]["declared_encoded_bytes"] for k in KEYS], [10, 11, 12])

    def test_all_requested_keys_preserved_absent_is_unknown(self):
        raw, model = fixture()
        absent = "44" * 16
        found, _ = self.parse(raw, model, {KEYS[0], absent})
        result = c.summarize({}, found)
        self.assertEqual(result["ekeys_by_reference_state"]["not_listed_in_pinned_download_unknown"], 1)
        self.assertFalse(result["installation_ready"])
        self.assertIsNone(result["required_network_download_bytes"])

    def test_nonrequested_keys_not_exported(self):
        raw, model = fixture()
        found, _ = self.parse(raw, model, {KEYS[0]})
        self.assertEqual(set(found), {KEYS[0]})

    def test_tag_msb_and_nonzero_padding(self):
        raw, model = fixture(bits={"Windows": 0x9F, "OSX": 0x3F})
        found, _ = self.parse(raw, model)
        self.assertEqual([x["name"] for x in found[KEYS[0]][0]["download_tags"]], ["Windows"])
        self.assertEqual([x["name"] for x in found[KEYS[2]][0]["download_tags"]], ["OSX"])
        self.assertFalse(found[KEYS[1]][0]["download_tags"])

    def test_exact_reader_does_not_probe_extra_byte(self):
        raw, model = fixture()
        class Limited(io.BytesIO):
            def read(self, size):
                if self.tell() + size > len(raw):
                    raise AssertionError("extra read")
                return super().read(size)
        stream = Limited(raw)
        _, used = c.parse_download(stream, set(KEYS), model=model)
        self.assertEqual(stream.tell(), used)

    def test_hash_mismatch_rejected_before_result(self):
        raw, model = fixture()
        raw = raw[:32] + bytes([raw[32] ^ 1]) + raw[33:]
        with self.assertRaisesRegex(c.Error, "download_whole_file_identity"):
            self.parse(raw, model)

    def test_sha256_independently_required(self):
        raw, model = fixture()
        with self.assertRaisesRegex(c.Error, "download_whole_file_identity"):
            self.parse(raw, replace(model, sha256="0" * 64))

    def test_truncated_rejected(self):
        raw, model = fixture()
        with self.assertRaisesRegex(c.Error, "download_truncated"):
            self.parse(raw[:-1], model)

    def test_unknown_header_rejected(self):
        raw, model = fixture()
        with self.assertRaisesRegex(c.Error, "download_pinned_header"):
            self.parse(raw[:2] + b"\x02" + raw[3:], model)

    def test_unknown_catalogue_rejected(self):
        raw, model = fixture()
        raw = raw.replace(b"Android\0", b"Unknown\0")
        with self.assertRaisesRegex(c.Error, "download_pinned_tag_catalogue"):
            self.parse(raw, model)

    def test_unknown_tag_kind_rejected(self):
        raw, model = fixture()
        raw = raw.replace(b"Android\0\x00\x01", b"Android\0\x00\x02")
        with self.assertRaisesRegex(c.Error, "download_pinned_tag_kind"):
            self.parse(raw, model)

    def test_zero_unrequested_ekey_rejected(self):
        raw, model = fixture(records=[(KEYS[0], 10, 0), ("0" * 32, 10, 0)])
        with self.assertRaisesRegex(c.Error, "download_zero_ekey"):
            self.parse(raw, model, {KEYS[0]})

    def test_reader_budget_rejected(self):
        raw, model = fixture()
        reader = c.Reader(io.BytesIO(raw), model, lambda: None)
        with self.assertRaisesRegex(c.Error, "download_read_budget"):
            reader.read(len(raw) + 1)

    def test_cancel_callback(self):
        raw, model = fixture()
        def cancel():
            raise c.Error("cancelled_test")
        with self.assertRaisesRegex(c.Error, "cancelled_test"):
            c.parse_download(io.BytesIO(raw), set(KEYS), cancel, model=model)

    def test_duplicate_aliases_preserved_and_size_conflict_unknown(self):
        raw, model = fixture(records=[(KEYS[0], 10, 0), (KEYS[0], 11, 1)])
        found, _ = self.parse(raw, model, {KEYS[0]})
        self.assertEqual(len(found[KEYS[0]]), 2)
        result = c.summarize({}, found)
        self.assertEqual(result["ekeys_by_reference_state"],
                         {"conflicting_download_encoded_sizes_unknown": 1})

    def test_zero_encoded_size_unknown(self):
        raw, model = fixture(records=[(KEYS[0], 0, 0)])
        found, _ = self.parse(raw, model, {KEYS[0]})
        self.assertIn("zero_download_encoded_size_unknown", c.summarize({}, found)["ekeys_by_reference_state"])

    def test_no_decoded_encoded_size_comparison(self):
        raw, model = fixture(records=[(KEYS[0], 20, 0)])
        found, _ = self.parse(raw, model, {KEYS[0]})
        result = c.summarize({"fake-ckey": {"decoded_size": 100000, "ekeys": [KEYS[0]]}}, found)
        self.assertIn("listed_metadata_reference_NOT_payload_proof", result["ekeys_by_reference_state"])
        self.assertFalse(result["alternative_ekey_chosen"])

    def test_match_cap(self):
        raw, model = fixture(records=[(KEYS[0], 10, 0)] * 3)
        with patch.object(c, "MAX_ALIASES", 2):
            with self.assertRaisesRegex(c.Error, "download_match_limit"):
                self.parse(raw, model, {KEYS[0]})

    def test_dimension_match_is_diagnostic_only(self):
        self.assertTrue(c.diagnostic_match([]))
        self.assertTrue(c.diagnostic_match([{"name": "Windows", "kind": 1}]))
        self.assertFalse(c.diagnostic_match([{"name": "OSX", "kind": 1}]))
        self.assertFalse(c.diagnostic_match([{"name": "CN", "kind": 4}]))
        self.assertTrue(c.diagnostic_match([{"name": "Alternate", "kind": 16384}, {"name": "speech", "kind": 5}]))

    def test_all_closure_and_apply_gates_remain_closed(self):
        result = c.summarize({}, {})
        for k in ("installation_ready", "apply_authorized", "vendor_install_policy_proven",
                  "actual_required_install_set_known", "fresh_local_content_verified"):
            self.assertIs(result[k], False)


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.layout = Layout((Entry("same", bytes.fromhex(KEYS[0]), 10),
                              Entry("same", bytes.fromhex(KEYS[1]), 11)))
        self.rows = [{"ckey": KEYS[0], "decoded_size": 10, "ekeys": [KEYS[1]]},
                     {"ckey": KEYS[1], "decoded_size": 11, "ekeys": [KEYS[2]]}]

    def test_all_variants_preserved(self):
        self.assertEqual(len(c.validate_references(self.rows, self.layout)), 2)

    def test_missing_key_rejected(self):
        with self.assertRaisesRegex(c.Error, "reference_key_set"):
            c.validate_references(self.rows[:1], self.layout)

    def test_duplicate_key_rejected(self):
        with self.assertRaisesRegex(c.Error, "reference_ckey"):
            c.validate_references(self.rows + [self.rows[0]], self.layout)

    def test_wrong_decoded_size_rejected(self):
        self.rows[0]["decoded_size"] = 100
        with self.assertRaisesRegex(c.Error, "reference_decoded_size"):
            c.validate_references(self.rows, self.layout)

    def test_invalid_ekey_rejected(self):
        self.rows[0]["ekeys"] = ["0" * 32]
        with self.assertRaisesRegex(c.Error, "reference_ekeys"):
            c.validate_references(self.rows, self.layout)

    def test_real_pinned_references_and_install(self):
        bundle = Path(c.__file__).parent
        _, _, layout = g.pinned_install(bundle / "target-install.metadata")
        _, _, _, refs = c.pinned_references(bundle, layout)
        self.assertEqual(len(refs), 180)
        self.assertEqual(len(layout.entries), 274)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_publish_no_overwrite(self):
        one = c.publish({"installation_ready": False}, [], None, self.root)
        two = c.publish({"installation_ready": False}, [], None, self.root)
        self.assertNotEqual(one, two)
        self.assertEqual(one.name, "INSTALL-DOWNLOAD-COVERAGE-to-share.json")

    def test_absent_metadata_appearance_stops(self):
        p = self.root / "appeared"
        p.write_bytes(b"x")
        with self.assertRaisesRegex(c.Error, "absent_metadata_appeared"):
            c.publish({}, [], p, self.root)
        self.assertFalse((self.root / "Results").exists())

    def test_input_changed_prevents_output(self):
        p = self.root / "input"
        p.write_bytes(b"x")
        before = g.fingerprint(p.stat())
        p.write_bytes(b"changed")
        with self.assertRaisesRegex(c.Error, "input_changed"):
            c.publish({}, [(p, before)], None, self.root)
        self.assertFalse((self.root / "Results").exists())

    def test_results_symlink_rejected(self):
        other = self.root / "other"
        other.mkdir()
        (self.root / "Results").symlink_to(other)
        with self.assertRaisesRegex(c.Error, "link_or_reparse"):
            c.publish({}, [], None, self.root)
        self.assertEqual(list(other.iterdir()), [])

    def test_changed_after_output_removes_only_own_report(self):
        p = self.root / "input"
        p.write_bytes(b"x")
        before = g.fingerprint(p.stat())
        calls = 0
        def changed(s):
            nonlocal calls
            calls += 1
            return before if calls == 1 else ("changed",)
        with patch.object(g, "fingerprint", side_effect=changed):
            with self.assertRaisesRegex(c.Error, "input_changed"):
                c.publish({}, [(p, before)], None, self.root)
        self.assertEqual(list((self.root / "Results").rglob("*.json")), [])
        self.assertEqual(p.read_bytes(), b"x")

    def test_production_cli_absent_exact_metadata(self):
        bundle, lab = self.root / "bundle", self.root / "Lab"
        bundle.mkdir()
        (lab / "objects").mkdir(parents=True)
        (lab / "objects" / "alternate.decoded").write_bytes(b"must not be searched")
        for name in ("install_download_coverage.py", "metadata_link_review.py", "install_structure.py",
                     "pinned_download_model.py", "target-install.metadata", "INSTALL-ENCODING-REFERENCES.json"):
            shutil.copyfile(Path(c.__file__).parent / name, bundle / name)
        before = {str(p.relative_to(lab)): p.read_bytes() for p in lab.rglob("*") if p.is_file()}
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        result = subprocess.run([sys.executable, "-B", str(bundle / "install_download_coverage.py"),
                                 "--lab", str(lab)], cwd=self.root, env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        paths = list((bundle / "Results").rglob("*to-share.json"))
        self.assertEqual(len(paths), 1)
        doc = json.loads(paths[0].read_text())
        self.assertEqual(doc["status"], "exact_saved_download_unavailable_unknown")
        self.assertEqual(doc["saved_download_metadata_bytes_read"], 0)
        self.assertFalse(doc["installation_ready"])
        self.assertEqual(before, {str(p.relative_to(lab)): p.read_bytes()
                                  for p in lab.rglob("*") if p.is_file()})

    def test_lab_bundle_overlap_rejected(self):
        with self.assertRaisesRegex(c.Error, "bundle_lab_overlap"):
            c.review(self.root, self.root)

    def test_bundle_inside_game_rejected(self):
        bundle, lab = self.root / "bundle", self.root / "Lab"
        bundle.mkdir()
        lab.mkdir()
        (self.root / ".build.info").write_bytes(b"marker only")
        with self.assertRaisesRegex(c.Error, "bundle_inside_game_or_lab"):
            c.review(lab, bundle)

    def test_help_no_input_selection(self):
        result = subprocess.run([sys.executable, "-B", str(Path(c.__file__)), "--help"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--lab", result.stdout)

    def test_network_forbidden_in_cli_module(self):
        result = subprocess.run([sys.executable, "-B", "-c",
            "import sys,socket; import install_download_coverage as c; "
            "sys.addaudithook(c.guard.block_network); socket.socket()"],
            cwd=Path(c.__file__).parent, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("network_forbidden", result.stderr)

    def synthetic_review(self, mode):
        """Explicit test-only pins; NEVER a production metadata override."""
        bundle, lab = self.root / "bundle", self.root / "Lab"
        bundle.mkdir()
        (lab / "objects").mkdir(parents=True)
        ip, rp = bundle / "target-install.metadata", bundle / "INSTALL-ENCODING-REFERENCES.json"
        ip.write_bytes(b"synthetic test fixture")
        rp.write_bytes(b"synthetic fixed references")
        raw, model = fixture(bits={"Windows": 0x80, "EU": 0x80})
        exact = lab / "objects" / (model.ckey + "-" + str(model.decoded_bytes) + ".decoded")
        exact.write_bytes(raw)
        refs = {KEYS[0]: {"decoded_size": 100000, "ekeys": (KEYS[0], KEYS[1])}}
        layout = Layout((Entry("not a destination", bytes.fromhex(KEYS[0]), 100000),))
        doc = {"target_build_config": "334a36cf5f3c32a5f7a167405487fa14",
               "source_report_sha256": "0" * 64}
        original_parse, original_fstat = c.parse_download, os.fstat
        calls = 0
        from types import SimpleNamespace
        def different(fd):
            nonlocal calls
            calls += 1
            original = original_fstat(fd)
            values = {k: getattr(original, k) for k in (
                "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")}
            values["st_ctime_ns"] += calls if mode == "changed" else 100
            return SimpleNamespace(**values)
        with patch.object(c, "PINNED_MODEL", model), \
             patch.object(g, "WINDOWS_CTIME_BRIDGE", True), \
             patch.object(g, "pinned_install", return_value=(ip, g.fingerprint(ip.stat()), layout)), \
             patch.object(c, "pinned_references", return_value=(rp, g.fingerprint(rp.stat()), doc, refs)), \
             patch.object(c, "parse_download", side_effect=lambda f, wanted, check, progress:
                          original_parse(f, wanted, check, progress, model=model)), \
             patch.object(g.os, "fstat", side_effect=different):
            if mode == "changed":
                with self.assertRaisesRegex(c.Error, "download_handle_changed"):
                    c.review(lab, bundle)
                self.assertFalse((bundle / "Results").exists())
            else:
                report, watched, absent = c.review(lab, bundle)
                self.assertEqual(report["saved_download_metadata_bytes_read"], len(raw))
                self.assertEqual(report["coverage"]["unique_referenced_ekeys"], 2)
                self.assertFalse(report["installation_ready"])
                final = c.publish(report, watched, absent, bundle)
                self.assertEqual(json.loads(final.read_text())["encoding_bytes_read"], 0)
        self.assertEqual(exact.read_bytes(), raw)

    def test_synthetic_end_to_end_explicit_pins_and_windows_ctime_bridge(self):
        self.synthetic_review("stable")

    def test_synthetic_review_handle_temporal_change_rejected(self):
        self.synthetic_review("changed")

    def test_production_reference_hash_rejects_tamper(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        source = Path(c.__file__).parent
        shutil.copyfile(source / "target-install.metadata", bundle / "target-install.metadata")
        _, _, layout = g.pinned_install(bundle / "target-install.metadata")
        raw = (source / "INSTALL-ENCODING-REFERENCES.json").read_bytes()
        (bundle / "INSTALL-ENCODING-REFERENCES.json").write_bytes(b" " + raw[1:])
        with self.assertRaisesRegex(c.Error, "reference_identity"):
            c.pinned_references(bundle, layout)

    def test_production_download_size_rejects_small_synthetic_file(self):
        bundle, lab = self.root / "bundle", self.root / "Lab"
        bundle.mkdir()
        (lab / "objects").mkdir(parents=True)
        for name in ("target-install.metadata", "INSTALL-ENCODING-REFERENCES.json"):
            shutil.copyfile(Path(c.__file__).parent / name, bundle / name)
        exact = lab / "objects" / (PINNED_MODEL.ckey + "-" + str(PINNED_MODEL.decoded_bytes) + ".decoded")
        exact.write_bytes(b"test fixture, not production metadata")
        with self.assertRaisesRegex(c.Error, "saved_download_size"):
            c.review(lab, bundle)
        self.assertFalse((bundle / "Results").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)