from copy import deepcopy
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import metadata_link_review as m

CK = bytes.fromhex("11"*16)
CK2 = bytes.fromhex("22"*16)
EK = bytes.fromhex("aa"*16)
EK2 = bytes.fromhex("bb"*16)


def record(ck=CK, size=5, links=(EK,)):
    return bytes([len(links)])+size.to_bytes(5, "big")+ck+b"".join(links)


def image(records=None, page_override=None, index_key=CK, checksum_override=None):
    records = [record()] if records is None else records
    body = b"".join(records)
    page = body+bytes(1024-len(body)) if page_override is None else page_override
    checksum = hashlib.md5(page).digest() if checksum_override is None else checksum_override
    h = b"EN\x01\x10\x10"+struct.pack(">HHII", 1, 1, 1, 1)+b"\0"+struct.pack(">I", 2)
    return h+b"n\0"+index_key+checksum+page+bytes(32)+bytes(1024)


@dataclass
class Entry:
    name: str
    digest: bytes
    declared_size: int


@dataclass
class Layout:
    entries: tuple


def table(raw):
    r = m.BudgetReader(io.BytesIO(raw), len(raw))
    return m.ContentLookup(r)


class Tests(unittest.TestCase):
    def rejected_table(self, raw, code):
        with self.assertRaisesRegex(m.ReviewError, code):
            table(raw)

    def rejected_content(self, raw, code):
        with self.assertRaisesRegex(m.ReviewError, code):
            table(raw).content(CK)

    def test_lookup_exact(self):
        self.assertEqual(table(image()).content(CK), (5, (EK,)))

    def test_lookup_absent_is_none_not_missing(self):
        self.assertIsNone(table(image()).content(CK2))

    def test_lookup_before_first_key(self):
        self.assertIsNone(table(image()).content(bytes.fromhex("01"*16)))

    def test_multiple_encodings_preserved(self):
        self.assertEqual(table(image([record(links=(EK, EK2))])).content(CK)[1], (EK, EK2))

    def test_multiple_content_keys(self):
        t = table(image([record(), record(CK2, 8, (EK2,))]))
        self.assertEqual(t.content(CK2), (8, (EK2,)))

    def test_page_cache_prevents_reread(self):
        t = table(image())
        t.content(CK)
        before = t.r.bytes_read
        t.content(CK2)
        t.content(CK)
        self.assertEqual(t.r.bytes_read, before)

    def test_page_checksum(self):
        self.rejected_content(image(checksum_override=b"x"*16), "selected_page_checksum")

    def test_magic(self):
        raw = image()
        self.rejected_table(b"XX"+raw[2:], "encoding_header")

    def test_version(self):
        raw = image()
        self.rejected_table(raw[:2]+b"\2"+raw[3:], "encoding_header")

    def test_hash_width(self):
        raw = image()
        self.rejected_table(raw[:3]+b"\x20"+raw[4:], "encoding_header")

    def test_header_flag(self):
        raw = image()
        self.rejected_table(raw[:17]+b"\1"+raw[18:], "encoding_header")

    def test_geometry_bounds(self):
        self.rejected_table(image()[:-1], "encoding_geometry_bounds")

    def test_geometry_limit(self):
        raw = image()
        self.rejected_table(raw[:9]+b"\0\0\0\0"+raw[13:], "encoding_geometry_limit")

    def test_index_zero_key(self):
        self.rejected_table(image(index_key=bytes(16)), "encoding_index_order")

    def test_first_page_key_must_match_index(self):
        self.rejected_content(image([record(CK2)]), "content_page_order")

    def test_page_order(self):
        self.rejected_content(image([record(), record(CK)]), "content_page_order")

    def test_zero_link(self):
        self.rejected_content(image([record(links=(bytes(16),))]), "content_links")

    def test_duplicate_links(self):
        self.rejected_content(image([record(links=(EK, EK))]), "content_links")

    def test_nonzero_padding(self):
        body = record()+b"\0x"
        self.rejected_content(image(page_override=body+bytes(1024-len(body))), "content_page_padding")

    def test_record_bounds(self):
        self.rejected_content(image(page_override=b"\xff"+bytes(1023)), "content_record_bounds")

    def test_zero_content_key_request(self):
        with self.assertRaisesRegex(m.ReviewError, "content_key_shape"):
            table(image()).content(bytes(16))

    def test_reader_limit_before_read(self):
        f = io.BytesIO(b"abc")
        r = m.BudgetReader(f, 3, limit=2)
        with self.assertRaisesRegex(m.ReviewError, "lookup_budget"):
            r.read(0, 3)
        self.assertEqual((r.bytes_read, f.tell()), (0, 0))

    def test_reader_bounds(self):
        with self.assertRaisesRegex(m.ReviewError, "lookup_bounds"):
            m.BudgetReader(io.BytesIO(b"a"), 1).read(1, 1)

    def test_reader_short(self):
        with self.assertRaisesRegex(m.ReviewError, "lookup_short_read"):
            m.BudgetReader(io.BytesIO(b""), 1).read(0, 1)

    def test_hash_exact_no_extra_read(self):
        class Recording(io.BytesIO):
            def __init__(self):
                super().__init__(b"abc")
                self.requests = []
            def read(self, n=-1):
                self.requests.append(n)
                return super().read(n)
        f = Recording()
        r = m.hash_exact(f, 3, hashlib.md5(b"abc").hexdigest())
        self.assertEqual((r["hash_bytes_read"], f.requests), (3, [3]))

    def test_hash_ckey_mismatch(self):
        with self.assertRaisesRegex(m.ReviewError, "encoding_whole_file_ckey"):
            m.hash_exact(io.BytesIO(b"abc"), 3, "0"*32)

    def test_hash_short_read(self):
        with self.assertRaisesRegex(m.ReviewError, "hash_short_read"):
            m.hash_exact(io.BytesIO(b"a"), 3, "0"*32)

    def test_hash_descriptor(self):
        for size in (-1, 0, True, m.ENCODING_SIZE+1):
            with self.subTest(size=size):
                with self.assertRaisesRegex(m.ReviewError, "hash_descriptor"):
                    m.hash_exact(io.BytesIO(b""), size, "0"*32)

    def test_hash_cancel_check(self):
        def stop():
            raise m.ReviewError("cancelled")
        with self.assertRaisesRegex(m.ReviewError, "cancelled"):
            m.hash_exact(io.BytesIO(b"abc"), 3, "0"*32, stop)

    def test_link_consistency(self):
        r = m.link_records(Layout((Entry("x", CK, 5),)), table(image()))
        self.assertEqual(r["unique_ckeys_by_state"], {
            "metadata_link_and_declared_size_agree_NOT_payload_proof": 1})
        self.assertFalse(r["installation_ready"])
        self.assertFalse(r["fresh_local_content_verified"])

    def test_absent_link_not_missing_or_zero_download(self):
        r = m.link_records(Layout((Entry("x", CK2, 5),)), table(image()))
        self.assertEqual(r["unique_ckeys_by_state"], {
            "not_resolved_in_pinned_encoding_unknown": 1})
        self.assertIsNone(r["required_network_download_bytes"])

    def test_declared_size_disagreement(self):
        r = m.link_records(Layout((Entry("x", CK, 7),)), table(image()))
        self.assertEqual(r["unique_ckeys_by_state"], {
            "encoding_and_install_size_disagreement_unknown": 1})

    def test_install_internal_size_disagreement(self):
        r = m.link_records(Layout((Entry("x", CK, 5), Entry("y", CK, 6))), table(image()))
        self.assertEqual(r["unique_ckeys_by_state"], {
            "install_declared_size_conflict_unknown": 1})

    def test_variants_not_deduplicated_for_install(self):
        entries = (Entry("x", CK, 5), Entry("x", CK2, 8))
        r = m.link_records(Layout(entries), table(image([record(), record(CK2, 8)])))
        self.assertEqual((r["serialized_install_records"], r["unique_install_ckeys"]), (2, 2))
        self.assertFalse(r["records_deduplicated_for_install"])

    def test_payload_aliases_keep_record_count(self):
        r = m.link_records(Layout((Entry("x", CK, 5), Entry("y", CK, 5))), table(image()))
        self.assertEqual((r["serialized_install_records"], r["unique_install_ckeys"]), (2, 1))

    def test_base_report_no_success_promotion(self):
        r = m.base_report()
        self.assertFalse(r["installation_ready"])
        self.assertFalse(r["saved_lab_snapshot_binding_checked"])
        self.assertFalse(r["installed_profile_revalidated"])

    def test_public_error_no_paths(self):
        r = m.public_error(OSError(22, "private path /secret/location"), "test")
        self.assertNotIn("secret", json.dumps(r))

    def test_public_error_safe_enum(self):
        self.assertEqual(m.public_error(m.ReviewError("lookup_budget"), "test")["code"], "lookup_budget")

    def test_public_error_unsafe_message_not_exported(self):
        self.assertNotIn("code", m.public_error(m.ReviewError("private /path"), "test"))

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/"real").write_bytes(b"x")
            (p/"link").symlink_to(p/"real")
            with self.assertRaisesRegex(m.ReviewError, "link_or_reparse_point"):
                m.safe(p/"link", True)

    def test_reject_hardlink(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/"real").write_bytes(b"x")
            os.link(p/"real", p/"link")
            with self.assertRaisesRegex(m.ReviewError, "regular_unshared"):
                m.safe(p/"link", True)

    def test_reject_bundle_lab_overlap(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(m.ReviewError, "bundle_lab_overlap"):
                m.review(Path(d), Path(d))

    def test_reject_bundle_inside_recognizable_game(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/"lab").mkdir()
            (root/"game").mkdir()
            (root/"game"/".build.info").write_text("not read")
            (root/"game"/"bundle").mkdir()
            with self.assertRaisesRegex(m.ReviewError, "bundle_inside_game_or_lab"):
                m.review(root/"lab", root/"game"/"bundle")

    def test_publish_new_output_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/"input").write_bytes(b"a")
            watched = [(p/"input", m.fingerprint((p/"input").stat()))]
            first = m.publish(m.base_report(), watched, p)
            second = m.publish(m.base_report(), watched, p)
            self.assertNotEqual(first, second)
            self.assertEqual((p/"input").read_bytes(), b"a")

    def test_changed_input_prevents_output(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/"input").write_bytes(b"a")
            watched = [(p/"input", m.fingerprint((p/"input").stat()))]
            (p/"input").write_bytes(b"changed")
            with self.assertRaisesRegex(m.ReviewError, "input_changed_before_output"):
                m.publish(m.base_report(), watched, p)
            self.assertFalse((p/"Results").exists())

    def test_source_pin_rejects_synthetic_install(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"fake"
            p.write_bytes(b"x"*m.INSTALL_SIZE)
            with self.assertRaisesRegex(m.ReviewError, "install_identity"):
                m.pinned_install(p)

    def test_socket_audit_hook_in_isolated_process(self):
        code = (
            "import sys,socket;import metadata_link_review as m;"
            "sys.addaudithook(m.block_network);"
            "\ntry: socket.socket()\n"
            "except m.ReviewError as e: print(str(e));sys.exit(0)\n"
            "sys.exit(1)\n")
        run = subprocess.run([sys.executable, "-B", "-c", code],
                             cwd=Path(__file__).resolve().parent,
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stdout.strip(), "network_forbidden")

    def test_cli_help_no_input_reads(self):
        run = subprocess.run([sys.executable, "-B", str(Path(m.__file__)), "--help"],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0)
        self.assertIn("--lab", run.stdout)

    def test_full_byte_reverse_formula(self):
        for byte in range(256):
            reversed_byte = (byte*0x0202020202 & 0x010884422010) % 1023
            self.assertEqual(reversed_byte, int(f"{byte:08b}"[::-1], 2))
            for i in range(8):
                self.assertEqual(bool(reversed_byte & (1 << i)),
                                 bool(byte & (0x80 >> i)))

    def test_wrong_bit_order_counterexample(self):
        self.assertNotEqual(bool(0x80 & (1 << 0)), bool(0x80 & (0x80 >> 0)))

    def test_real_pinned_install_full_bit_formula_agreement(self):
        _, _, layout = m.pinned_install(Path(m.__file__).parent/"target-install.metadata")
        compared = 0
        for tag in layout.tags:
            reversed_bytes = bytes(
                (b*0x0202020202 & 0x010884422010) % 1023 for b in tag.bitmap)
            for i in range(len(layout.entries)):
                self.assertEqual(bool(reversed_bytes[i//8] & (1 << (i%8))),
                                 bool(tag.bitmap[i//8] & (0x80 >> (i%8))))
                compared += 1
        self.assertEqual(compared, 8494)

    def test_real_wow_variants_do_not_use_first_name(self):
        _, _, layout = m.pinned_install(Path(m.__file__).parent/"target-install.metadata")
        tags = {t.name: t.bitmap for t in layout.tags}
        variants = [(i, e) for i, e in enumerate(layout.entries) if e.name == "Wow.exe"]
        self.assertEqual(len(variants), 2)
        first, second = variants
        self.assertNotEqual(first[1].digest, second[1].digest)
        def has(label, i):
            return bool(tags[label][i//8] & (0x80 >> (i%8)))
        self.assertTrue(has("CN", first[0]))
        self.assertFalse(has("EU", first[0]))
        self.assertTrue(has("EU", second[0]))
        self.assertFalse(has("CN", second[0]))
        # This is a regression vector, not a vendor-policy certificate.
        self.assertFalse(m.base_report()["vendor_install_policy_proven"])

    def test_standalone_cli_absent_cache_no_alternate_search(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            bundle, lab = p/"bundle", p/"lab"
            bundle.mkdir()
            (lab/"objects").mkdir(parents=True)
            (lab/"objects"/"alternate-encoding.decoded").write_bytes(image())
            originals = {x.relative_to(lab): x.read_bytes()
                         for x in lab.rglob("*") if x.is_file()}
            for name in ("metadata_link_review.py", "install_structure.py", "target-install.metadata"):
                shutil.copyfile(Path(m.__file__).parent/name, bundle/name)
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            run = subprocess.run([sys.executable, "-B", str(bundle/"metadata_link_review.py"),
                                  "--lab", str(lab)], env=env, cwd=bundle,
                                 capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
            reports = list((bundle/"Results").glob("*/INSTALL-ENCODING-LINKS-to-share.json"))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text())
            self.assertEqual(report["status"], "exact_saved_encoding_unavailable_unknown")
            self.assertEqual(report["encoding_hash_bytes_read"], 0)
            self.assertFalse(report["cache_search_or_scan_restart"])
            self.assertEqual(originals, {x.relative_to(lab): x.read_bytes()
                                        for x in lab.rglob("*") if x.is_file()})

    def test_production_encoding_descriptor_rejects_synthetic_file(self):
        with tempfile.TemporaryDirectory() as d:
            import shutil
            p = Path(d)
            bundle, lab = p/"bundle", p/"lab"
            bundle.mkdir()
            (lab/"objects").mkdir(parents=True)
            shutil.copyfile(Path(m.__file__).parent/"target-install.metadata",
                            bundle/"target-install.metadata")
            name = m.ENCODING_CKEY+"-"+str(m.ENCODING_SIZE)+".decoded"
            (lab/"objects"/name).write_bytes(image())
            with self.assertRaisesRegex(m.ReviewError, "saved_encoding_size"):
                m.review(lab, bundle)
            self.assertFalse((bundle/"Results").exists())

    def test_synthetic_end_to_end_only_explicit_test_pin_substitution(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            bundle, lab = p/"bundle", p/"lab"
            bundle.mkdir()
            (lab/"objects").mkdir(parents=True)
            (bundle/"target-install.metadata").write_bytes(b"synthetic-install")
            input_path = bundle/"target-install.metadata"
            fake_layout = Layout((Entry("x", CK, 5), Entry("x", CK2, 8)))
            raw = image([record(), record(CK2, 8, (EK2,))])
            ckey = hashlib.md5(raw).hexdigest()
            exact = lab/"objects"/(ckey+"-"+str(len(raw))+".decoded")
            exact.write_bytes(raw)
            before = exact.read_bytes()
            with patch.object(m, "ENCODING_CKEY", ckey), \
                 patch.object(m, "ENCODING_SIZE", len(raw)), \
                 patch.object(m, "pinned_install", return_value=(
                     input_path, m.fingerprint(input_path.stat()), fake_layout)):
                result, watched = m.review(lab, bundle)
                output = m.publish(result, watched, bundle)
            self.assertEqual(result["mapping"]["unique_install_ckeys"], 2)
            self.assertFalse(result["installation_ready"])
            self.assertFalse(result["saved_lab_snapshot_binding_checked"])
            self.assertEqual(exact.read_bytes(), before)
            self.assertEqual(json.loads(output.read_text())["archive_payload_bytes_read"], 0)

    def test_publish_rejects_results_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/"elsewhere").mkdir()
            (p/"Results").symlink_to(p/"elsewhere", target_is_directory=True)
            with self.assertRaisesRegex(m.ReviewError, "link_or_reparse_point"):
                m.publish(m.base_report(), [], p)
            self.assertEqual(list((p/"elsewhere").iterdir()), [])

    def test_publish_changed_input_removes_only_own_report(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            source = p/"input"
            source.write_bytes(b"x")
            original = m.fingerprint(source.stat())
            actual = m.fingerprint
            calls = 0
            def change_after_output(s):
                nonlocal calls
                calls += 1
                return original if calls == 1 else ("changed",)
            with patch.object(m, "fingerprint", side_effect=change_after_output):
                with self.assertRaisesRegex(m.ReviewError, "input_changed_after_output"):
                    m.publish(m.base_report(), [(source, original)], p)
            self.assertEqual(list((p/"Results").glob("*/*.json")), [])
            self.assertEqual(source.read_bytes(), b"x")

    def test_two_page_index_lookup_and_checksums(self):
        pages = []
        for ck, ek in ((CK, EK), (CK2, EK2)):
            raw = record(ck, 5, (ek,))
            pages.append(raw+bytes(1024-len(raw)))
        header = b"EN\x01\x10\x10"+struct.pack(">HHII", 1, 1, 2, 1)+b"\0"+struct.pack(">I", 2)
        index = CK+hashlib.md5(pages[0]).digest()+CK2+hashlib.md5(pages[1]).digest()
        t = table(header+b"n\0"+index+b"".join(pages)+bytes(32)+bytes(1024))
        self.assertEqual(t.content(CK2), (5, (EK2,)))
        self.assertEqual(t.content(CK), (5, (EK,)))
        self.assertEqual(len(t.pages), 2)

    def test_content_key_beyond_next_index_rejected(self):
        raw = record()+record(CK2)
        page1 = raw+bytes(1024-len(raw))
        page2 = record(CK2)+bytes(1024-len(record(CK2)))
        header = b"EN\x01\x10\x10"+struct.pack(">HHII", 1, 1, 2, 1)+b"\0"+struct.pack(">I", 2)
        index = CK+hashlib.md5(page1).digest()+CK2+hashlib.md5(page2).digest()
        t = table(header+b"n\0"+index+page1+page2+bytes(32)+bytes(1024))
        with self.assertRaisesRegex(m.ReviewError, "content_page_order"):
            t.content(CK)


class IdentityBridgeTests(unittest.TestCase):
    def stat_proxy(self, original, ctime_delta=0, ino_delta=0):
        from types import SimpleNamespace
        names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        values = {k: getattr(original, k) for k in names}
        values["st_ctime_ns"] += ctime_delta
        values["st_ino"] += ino_delta
        return SimpleNamespace(**values)

    def test_windows_cross_api_ctime_only_allowed(self):
        a = (1, 2, 24078, 4, 5, 1)
        b = (1, 2, 24078, 4, 99, 1)
        with patch.object(m, "WINDOWS_CTIME_BRIDGE", True):
            self.assertTrue(m.same_open_identity(a, b))

    def test_nonwindows_cross_api_ctime_still_required(self):
        with patch.object(m, "WINDOWS_CTIME_BRIDGE", False):
            self.assertFalse(m.same_open_identity((1,2,3,4,5,1), (1,2,3,4,99,1)))

    def test_windows_every_other_cross_api_field_required(self):
        a = (1, 2, 24078, 4, 5, 1)
        with patch.object(m, "WINDOWS_CTIME_BRIDGE", True):
            for i in (0, 1, 2, 3, 5):
                b = list(a); b[i] += 1
                with self.subTest(field=i):
                    self.assertFalse(m.same_open_identity(a, tuple(b)))

    def test_windows_stable_ctime_discrepancy_real_install_passes_pins(self):
        original = os.fstat
        def different(fd):
            return self.stat_proxy(original(fd), ctime_delta=1234567)
        with patch.object(m, "WINDOWS_CTIME_BRIDGE", True), patch.object(m.os, "fstat", side_effect=different):
            _, _, layout = m.pinned_install(Path(m.__file__).parent/"target-install.metadata")
        self.assertEqual(len(layout.entries),274)

    def test_windows_handle_ctime_change_still_rejected_install(self):
        original = os.fstat
        calls = 0
        def changed(fd):
            nonlocal calls
            calls += 1
            return self.stat_proxy(original(fd), ctime_delta=calls*123)
        with patch.object(m, "WINDOWS_CTIME_BRIDGE", True), patch.object(m.os, "fstat", side_effect=changed):
            with self.assertRaisesRegex(m.ReviewError, "install_handle_changed"):
                m.pinned_install(Path(m.__file__).parent/"target-install.metadata")

    def test_windows_handle_inode_disagreement_rejected_install(self):
        original = os.fstat
        def different(fd):return self.stat_proxy(original(fd), ino_delta=1)
        with patch.object(m, "WINDOWS_CTIME_BRIDGE", True), patch.object(m.os, "fstat", side_effect=different):
            with self.assertRaisesRegex(m.ReviewError, "install_path_handle_disagree"):
                m.pinned_install(Path(m.__file__).parent/"target-install.metadata")

    def test_windows_path_ctime_change_still_rejected_install(self):
        original = Path.stat
        target = Path(m.__file__).parent/"target-install.metadata"
        calls = 0
        def changed(path, *a, **kw):
            nonlocal calls
            s = original(path, *a, **kw)
            if path == target and kw.get("follow_symlinks", True):
                calls += 1
                if calls >= 3:return self.stat_proxy(s, ctime_delta=123)
            return s
        with patch.object(m,"WINDOWS_CTIME_BRIDGE",True), patch.object(Path,"stat",changed):
            with self.assertRaisesRegex(m.ReviewError,"install_changed"):
                m.pinned_install(target)

    def synthetic_windows_encoding(self, mode):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);bundle=p/"bundle";lab=p/"lab"
            bundle.mkdir();(lab/"objects").mkdir(parents=True)
            ip=bundle/"target-install.metadata";ip.write_bytes(b"test-only")
            raw=image();ckey=hashlib.md5(raw).hexdigest()
            exact=lab/"objects"/(ckey+"-"+str(len(raw))+".decoded")
            exact.write_bytes(raw)
            original=os.fstat;calls=0
            def different(fd):
                nonlocal calls
                calls+=1
                delta = 100 if mode == "stable" else calls*100
                return self.stat_proxy(original(fd),ctime_delta=delta)
            with patch.object(m,"WINDOWS_CTIME_BRIDGE",True), patch.object(m,"ENCODING_CKEY",ckey), patch.object(m,"ENCODING_SIZE",len(raw)), patch.object(m,"pinned_install",return_value=(ip,m.fingerprint(ip.stat()),Layout((Entry("x",CK,5),)))), patch.object(m.os,"fstat",side_effect=different):
                if mode=="stable":
                    result,_=m.review(lab,bundle)
                    self.assertEqual(result["status"],"pinned_install_encoding_metadata_links_reviewed")
                    self.assertFalse(result["installation_ready"])
                else:
                    with self.assertRaisesRegex(m.ReviewError,"encoding_handle_changed"):
                        m.review(lab,bundle)
            self.assertEqual(exact.read_bytes(),raw)
            self.assertFalse((bundle/"Results").exists())

    def test_synthetic_windows_encoding_stable_cross_api_difference(self):
        self.synthetic_windows_encoding("stable")

    def test_synthetic_windows_encoding_handle_ctime_change_rejected(self):
        self.synthetic_windows_encoding("changed")

    def test_report_discloses_dual_channel_identity_checks(self):
        with patch.object(m,"WINDOWS_CTIME_BRIDGE",True):
            guard=m.base_report()["identity_guard"]
        self.assertTrue(guard["ctime_in_both_temporal_checks"])
        self.assertTrue(guard["windows_cross_api_ctime_excluded"])


if __name__ == "__main__":
    unittest.main(verbosity=2)