import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repair_core as core
import target_metadata as meta
import download_inventory as inv


def fixture(entries, tags=(), version=3, checksum=1, flags=1, base=2,
            reserved=b"\0\0\0"):
    h = b"DL" + bytes([version, 16, checksum])
    h += len(entries).to_bytes(4, "big") + len(tags).to_bytes(2, "big")
    if version >= 2:
        h += bytes([flags])
    if version >= 3:
        h += bytes([base]) + reserved
    rows = bytearray(h)
    for ek, size, priority in entries:
        rows += ek + size.to_bytes(5, "big") + bytes([priority])
        if checksum:
            rows += b"\x11\x22\x33\x44"
        if version >= 2:
            rows += bytes([5]) * flags
    for name, kind, members in tags:
        bitmap = bytearray((len(entries) + 7) // 8)
        for i in members:
            bitmap[i // 8] |= 0x80 >> (i % 8)
        rows += name.encode() + b"\0" + kind.to_bytes(2, "big") + bitmap
    return bytes(rows)


class Response(io.BytesIO):
    def __init__(self, body, url, status=200, headers=None):
        super().__init__(body)
        self.url, self.status = url, status
        self.headers = headers if headers is not None else {"Content-Length": str(len(body))}

    def geturl(self):
        return self.url


class Chain:
    """A synthetic official-table/config/BLTE service, NOT a real network test."""
    def __init__(self, data):
        self.data = data
        self.encoded = b"BLTE\0\0\0\0Z" + zlib.compress(data)
        self.ck = hashlib.md5(data).hexdigest()
        self.ek = hashlib.md5(self.encoded).hexdigest()
        self.build = (
            "build-uid = wow\nbuild-name = WOW-70391patch12.1.5_Retail\n"
            "download = %s %s\ndownload-size = %d %d\n" %
            (self.ck, self.ek, len(data), len(self.encoded))).encode()
        self.bk = hashlib.md5(self.build).hexdigest()
        self.cdn = ("builds = " + self.bk + "\narchives = " + "a" * 32 + "\n").encode()
        self.dk = hashlib.md5(self.cdn).hexdigest()
        self.versions = (
            "# seqn = 1\n"
            "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16|BuildId!DEC:4|VersionsName!STRING:0\n"
            "eu|%s|%s|70391|12.1.5.70391\n" % (self.bk, self.dk)).encode()
        self.cdns = (
            "Name!STRING:0|Path!STRING:0|Hosts!STRING:0|Servers!STRING:0\n"
            "eu|tpr/wow|legacy.invalid|https://fixtures.invalid\n").encode()
        self.routes = {
            meta.VERSIONS: self.versions, meta.CDNS: self.cdns,
            meta.config_url("https://fixtures.invalid", self.bk): self.build,
            meta.config_url("https://fixtures.invalid", self.dk): self.cdn,
            "https://fixtures.invalid/tpr/wow/data/" + self.ek[:2] + "/" +
            self.ek[2:4] + "/" + self.ek: self.encoded,
        }
        self.requests = []
        self.edit = lambda r: r
        self.after_first = None

    def open(self, url, headers):
        self.requests.append((url, dict(headers)))
        if self.after_first and len(self.requests) > 5:
            self.after_first(self)
        data = self.routes[url]
        status, h = 200, {"Content-Length": str(len(data))}
        if "Range" in headers:
            start, end = (int(s) for s in headers["Range"][6:].split("-"))
            full = len(data)
            data = data[start:end + 1]
            status = 206
            h = {"Content-Length": str(len(data)),
                 "Content-Range": "bytes %d-%d/%d" % (start, end, full)}
        return self.edit(Response(data, url, status, h))


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.lab = core.Lab.create(self.base / "lab")
        self.entries = [(b"a" * 16, 123, 0), (b"b" * 16, 456, 2),
                        (b"a" * 16, 123, 1)]
        self.tags = [("Windows", 1, [0, 1]), ("enUS", 3, [1, 2])]
        self.data = fixture(self.entries, self.tags)
        self.chain = Chain(self.data)
        self.cancel = threading.Event()

    def build(self, data=None, cancel=None, notify=lambda _: None):
        data = self.data if data is None else data
        c = Chain(data)
        t = meta.discover(c)
        b, _ = meta.load_configs(t, c)
        spec = meta.download_spec(t, b)
        path = core.fetch_decoded(self.lab, spec, c)
        with self.lab.lock():
            return inv.build_inventory(self.lab, path, spec, {"version": t.version},
                                       cancel, notify)

    def db(self, path):
        connection = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)
        self.addCleanup(connection.close)
        return connection

    def test_end_to_end_trusted_chain_all_records_not_subset(self):
        result, path = inv.prepare_inventory(self.lab, self.chain)
        self.assertEqual(result["target_version"], "12.1.5.70391")
        self.assertEqual(result["manifest_records"], 3)
        self.assertEqual(result["unique_encoded_objects"], 2)
        self.assertEqual(result["unique_encoded_bytes_sum"], 579)
        self.assertEqual(result["record_encoded_bytes_sum"], 702)
        self.assertEqual(result["duplicate_records"], 1)
        self.assertTrue(result["official_target_binding_rechecked"])
        self.assertFalse(result["full_game_target_closure_proven"])
        self.assertFalse(result["installation_ready"])
        self.assertIsNone(result["required_network_download_bytes"])
        self.assertFalse(result["tag_filter_applied"])
        self.assertEqual(self.db(path).execute("SELECT COUNT(*) FROM entries").fetchone()[0], 3)
        self.assertEqual(list((self.lab.root / "target").iterdir()), [])
        self.assertEqual(len(self.chain.requests), 7)

    def test_v1_no_checksum(self):
        result, path = self.build(fixture(self.entries, version=1, checksum=0))
        self.assertEqual(result["format_version"], 1)
        self.assertFalse(result["entry_checksums_present"])
        self.assertEqual(self.db(path).execute("SELECT checksum,flags FROM entries LIMIT 1")
                         .fetchone(), (None, b""))

    def test_v1_optional_checksum(self):
        result, path = self.build(fixture(self.entries, version=1, checksum=1))
        self.assertTrue(result["entry_checksums_present"])
        self.assertEqual(self.db(path).execute("SELECT checksum FROM entries LIMIT 1")
                         .fetchone()[0], b"\x11\x22\x33\x44")

    def test_v2_flags_follow_checksum_not_before_key(self):
        _, path = self.build(fixture(self.entries, version=2, flags=4))
        self.assertEqual(self.db(path).execute(
            "SELECT ekey,encoded_size,checksum,flags FROM entries WHERE ordinal=0"
        ).fetchone(), (b"a" * 16, 123, b"\x11\x22\x33\x44", b"\x05" * 4))

    def test_v3_preserves_raw_priority_and_base(self):
        result, path = self.build(fixture(self.entries, version=3, base=200))
        self.assertEqual(result["base_priority_raw_unsigned"], 200)
        self.assertEqual(self.db(path).execute(
            "SELECT raw_priority,priority_minus_base FROM entries WHERE ordinal=0"
        ).fetchone(), (0, -200))

    def test_unknown_reserved_bytes_retained_as_observation(self):
        result, _ = self.build(fixture(self.entries, reserved=b"\1\2\3"))
        self.assertTrue(result["v3_reserved_bytes_nonzero"])

    def test_manual_hex_vector_v1(self):
        # Written without fixture(); one complete 11-byte header + 22-byte entry.
        data = bytes.fromhex(
            "444c011000000000010000"
            "0123456789abcdef0123456789abcdef"
            "0102030405" "07")
        result, path = self.build(data)
        row = self.db(path).execute("SELECT ekey,encoded_size,raw_priority FROM entries").fetchone()
        self.assertEqual(row, (bytes.fromhex("0123456789abcdef0123456789abcdef"),
                               0x0102030405, 7))
        self.assertEqual(result["unique_encoded_bytes_sum"], 0x0102030405)

    def test_manual_hex_vector_v3(self):
        data = bytes.fromhex(
            "444c031001000000010000" "02" "03" "000000"
            "0123456789abcdef0123456789abcdef" "0000000009" "01"
            "deadbeef" "1234")
        result, path = self.build(data)
        row = self.db(path).execute(
            "SELECT encoded_size,raw_priority,priority_minus_base,checksum,flags FROM entries"
        ).fetchone()
        self.assertEqual(row, (9, 1, -2, bytes.fromhex("deadbeef"), bytes.fromhex("1234")))
        self.assertEqual(result["manifest_tags"], 0)

    def test_msb_tag_bitmap_and_shared_records_not_excluded(self):
        entries = [(i.to_bytes(16, "big"), i * 100, 0) for i in range(1, 11)]
        data = fixture(entries, [("Windows", 1, [0, 7, 8, 9])])
        result, path = self.build(data)
        row = self.db(path).execute("SELECT bitmap,member_records FROM tags").fetchone()
        self.assertEqual(row, (b"\x81\xc0", 4))
        self.assertEqual(result["manifest_records"], 10)
        self.assertTrue(result["all_manifest_records_included"])

    def test_nonzero_bitmap_padding_not_counted_as_members(self):
        data = bytearray(fixture(self.entries, [("Windows", 1, [0])]))
        data[-1] |= 0x1f
        result, path = self.build(bytes(data))
        self.assertEqual(result["tags_with_nonzero_unused_padding_bits"], 1)
        self.assertEqual(self.db(path).execute("SELECT member_records FROM tags").fetchone()[0], 1)

    def test_duplicate_key_different_size_blocks_inventory(self):
        with self.assertRaisesRegex(inv.InventoryError, "conflicting_encoded_sizes"):
            self.build(fixture([(b"a" * 16, 2, 0), (b"a" * 16, 3, 0)]))
        self.assertEqual(list((self.lab.root / "objects").glob("*.sqlite")), [])

    def test_duplicate_key_same_size_retains_original_rows(self):
        result, path = self.build()
        db = self.db(path)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 3)
        self.assertEqual(db.execute("SELECT source_records FROM objects WHERE ekey=?",
                                   (b"a" * 16,)).fetchone()[0], 2)
        self.assertEqual(result["duplicate_records"], 1)

    def test_unknown_tag_type_retained_not_silently_selected(self):
        result, path = self.build(fixture(self.entries, [("Optional", 0x4000, [2])]))
        self.assertEqual(self.db(path).execute("SELECT kind FROM tags").fetchone()[0], 0x4000)
        self.assertFalse(result["tag_filter_applied"])

    def test_conflicting_tag_duplicate_rejected(self):
        with self.assertRaisesRegex(inv.InventoryError, "duplicate_download_tag"):
            self.build(fixture(self.entries, [("Windows", 1, [0]), ("Windows", 1, [1])]))

    def test_zero_encoded_size_observed_not_counted_as_valid_download(self):
        result, _ = self.build(fixture([(b"a" * 16, 0, 0)]))
        self.assertEqual(result["zero_size_objects"], 1)
        self.assertFalse(result["installation_ready"])

    def test_unknown_manifest_version_fails_closed(self):
        data = bytearray(self.data)
        data[2] = 4
        with self.assertRaisesRegex(inv.InventoryError, "unsupported_download_header"):
            self.build(bytes(data))

    def test_partial_ekey_not_accepted_as_full_identity(self):
        data = bytearray(self.data)
        data[3] = 9
        with self.assertRaisesRegex(inv.InventoryError, "full_ekey_length"):
            self.build(bytes(data))

    def test_unsupported_flag_width(self):
        with self.assertRaisesRegex(inv.InventoryError, "flag_size"):
            self.build(fixture(self.entries, flags=5))

    def test_declared_huge_record_count_rejected(self):
        data = bytearray(self.data)
        data[5:9] = (2**32 - 1).to_bytes(4, "big")
        with self.assertRaisesRegex(inv.InventoryError, "count_limit"):
            self.build(bytes(data))

    def test_every_truncated_prefix_fails_without_published_database(self):
        # Exercise parser boundaries directly; a truncated manifest is re-hashed
        # so container integrity cannot hide structural truncation bugs.
        for n in range(len(self.data)):
            with self.subTest(prefix=n), self.assertRaises(core.RepairError):
                self.build(self.data[:n])
        self.assertEqual(list((self.lab.root / "objects").glob("*.sqlite")), [])
        self.assertEqual(list((self.lab.root / "objects").glob("*.sqlite.part*")), [])

    def test_trailing_bytes_rejected(self):
        with self.assertRaisesRegex(inv.InventoryError, "trailing_bytes"):
            self.build(self.data + b"x")

    def test_zero_key_rejected_as_unsupported(self):
        with self.assertRaisesRegex(inv.InventoryError, "zero_download_ekey"):
            self.build(fixture([(bytes(16), 99, 0)]))

    def test_cancel_before_start(self):
        self.cancel.set()
        with self.assertRaises(core.Cancelled):
            inv.prepare_inventory(self.lab, self.chain, self.cancel)
        self.assertEqual(self.chain.requests, [])

    def test_cancel_during_parse_leaves_no_database(self):
        def notify(_):
            self.cancel.set()
        with self.assertRaises(core.Cancelled):
            self.build(cancel=self.cancel, notify=notify)
        self.assertEqual(list((self.lab.root / "objects").glob("*.sqlite*")), [])

    def test_input_mutation_during_parse_blocks_publication(self):
        def notify(_):
            for p in (self.lab.root / "objects").glob("*.decoded"):
                p.write_bytes(p.read_bytes() + b"x")
        with self.assertRaises(inv.InventoryError):
            self.build(notify=notify)
        self.assertEqual(list((self.lab.root / "objects").glob("*.sqlite")), [])

    def test_large_manifest_100k_disk_backed_and_crossfooted(self):
        entries = [(i.to_bytes(16, "big"), i + 1, i % 3) for i in range(1, 100001)]
        result, path = self.build(fixture(entries, version=2, checksum=0, flags=0))
        self.assertEqual(result["unique_encoded_objects"], 100000)
        self.assertEqual(result["unique_encoded_bytes_sum"], sum(i + 1 for i in range(1, 100001)))
        db = self.db(path)
        self.assertEqual(db.execute("SELECT COUNT(*),SUM(encoded_size) FROM entries").fetchone(),
                         (100000, 5_000_150_000))

    def test_sqlite_result_source_binding_and_sha_saved(self):
        _, path = self.build()
        d = dict(self.db(path).execute("SELECT name,value FROM metadata"))
        self.assertEqual(json.loads(d["target_binding"])["version"], "12.1.5.70391")
        self.assertEqual(d["source_sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(self.db(path).execute("PRAGMA quick_check").fetchone()[0], "ok")

    def test_pipeline_rejects_target_change_instead_of_silent_retarget(self):
        def change(c):
            c.routes[meta.VERSIONS] = c.versions.replace(b"70391", b"70392")
        self.chain.after_first = change
        with self.assertRaisesRegex(meta.MetadataError, "target_changed"):
            inv.prepare_inventory(self.lab, self.chain)
        self.assertEqual(list((self.lab.root / "target").iterdir()), [])

    def test_pipeline_rejects_origin_removed_at_end(self):
        def change(c):
            c.routes[meta.CDNS] = c.cdns.replace(b"fixtures.invalid", b"other.invalid")
        self.chain.after_first = change
        with self.assertRaisesRegex(meta.MetadataError, "target_changed"):
            inv.prepare_inventory(self.lab, self.chain)

    def test_cached_manifest_reused_and_source_not_overwritten(self):
        _, first = inv.prepare_inventory(self.lab, self.chain)
        n = sum("/data/" in u for u, _ in self.chain.requests)
        _, second = inv.prepare_inventory(self.lab, self.chain)
        self.assertNotEqual(first, second)
        self.assertEqual(sum("/data/" in u for u, _ in self.chain.requests), n)
        self.assertTrue(first.exists())

    def test_no_real_network_no_execution_and_no_game_directory_changes(self):
        external = self.base / "pretend-game"
        external.mkdir()
        (external / ".build.info").write_bytes(b"keep")
        with patch("socket.socket", side_effect=AssertionError("no real network")), \
             patch("subprocess.Popen", side_effect=AssertionError("no execution")):
            r, _ = inv.prepare_inventory(self.lab, self.chain)
        self.assertFalse(r["game_files_modified"])
        self.assertEqual((external / ".build.info").read_bytes(), b"keep")


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.chain = Chain(fixture([(b"a" * 16, 9, 0)]))

    def test_discover_full_eu_target(self):
        t = meta.discover(self.chain)
        self.assertEqual(t.identity(), ("12.1.5.70391", 70391, self.chain.bk, self.chain.dk))
        self.assertEqual(t.origins, ("https://fixtures.invalid",))

    def test_no_eu_row_no_region_fallback(self):
        self.chain.routes[meta.VERSIONS] = self.chain.versions.replace(b"eu|", b"us|")
        with self.assertRaisesRegex(meta.MetadataError, "one_eu"):
            meta.discover(self.chain)

    def test_duplicate_eu_row_rejected(self):
        self.chain.routes[meta.VERSIONS] += self.chain.versions.splitlines()[-1] + b"\n"
        with self.assertRaisesRegex(meta.MetadataError, "one_eu"):
            meta.discover(self.chain)

    def test_duplicate_table_column_rejected(self):
        with self.assertRaisesRegex(meta.MetadataError, "duplicate_columns"):
            meta.table(b"A|A\nx|y")

    def test_malformed_row_width_rejected(self):
        with self.assertRaisesRegex(meta.MetadataError, "row_width"):
            meta.table(b"Region|BuildId\neu")

    def test_version_build_id_conflict(self):
        self.chain.routes[meta.VERSIONS] = self.chain.versions.replace(b"|70391|", b"|99999|")
        with self.assertRaisesRegex(meta.MetadataError, "build_id_conflict"):
            meta.discover(self.chain)

    def test_no_unsupported_or_insecure_origin_fallback(self):
        for origin in ("http://cdn.invalid", "https://127.0.0.1",
                       "https://localhost", "https://x.local",
                       "https://user:password@cdn.invalid", "https://cdn.invalid/path",
                       "https://cdn.invalid?x=1", "https://cdn.invalid:444"):
            with self.subTest(origin=origin), self.assertRaises(meta.MetadataError):
                meta.origins({"Path": "tpr/wow", "Servers": origin})

    def test_supported_origins_deduplicated_in_official_order(self):
        r = meta.origins({"Path": "tpr/wow", "Servers":
                         "http://legacy.invalid https://A.invalid/ https://a.invalid https://b.invalid"})
        self.assertEqual(r, ("https://a.invalid", "https://b.invalid"))

    def test_official_server_selection_hints_not_forwarded_to_object_url(self):
        r = meta.origins({"Path": "tpr/wow", "Servers":
                         "http://level3.blizzard.com/?maxhosts=8 "
                         "https://level3.ssl.blizzard.com/?maxhosts=8&fallback=1"})
        self.assertEqual(r, ("https://level3.ssl.blizzard.com",))

    def test_invalid_or_duplicate_origin_selection_hints_fail_closed(self):
        for hint in ("maxhosts=0", "maxhosts=999", "maxhosts=8&maxhosts=9",
                     "fallback=2", "redirect=https://elsewhere.invalid",
                     "maxhosts=", "maxhosts=8&evil=1"):
            with self.subTest(hint=hint), self.assertRaises(meta.MetadataError):
                meta.origins({"Path": "tpr/wow", "Servers": "https://cdn.invalid/?" + hint})

    def test_wrong_product_path_rejected(self):
        with self.assertRaisesRegex(meta.MetadataError, "product_cdn_path"):
            meta.origins({"Path": "tpr/wowt", "Servers": "https://cdn.invalid"})

    def test_corrupt_build_config_rejected(self):
        t = meta.discover(self.chain)
        self.chain.routes[meta.config_url(t.origins[0], t.build_config)] += b"!"
        with self.assertRaisesRegex(meta.MetadataError, "config_checksum"):
            meta.load_configs(t, self.chain)

    def test_corrupt_cdn_config_rejected(self):
        t = meta.discover(self.chain)
        self.chain.routes[meta.config_url(t.origins[0], t.cdn_config)] += b"!"
        with self.assertRaisesRegex(meta.MetadataError, "config_checksum"):
            meta.load_configs(t, self.chain)

    def test_duplicate_config_field_rejected_after_checksum(self):
        data = b"download = one\ndownload = two\n"
        with self.assertRaisesRegex(meta.MetadataError, "duplicate_or_invalid_field"):
            meta.config(data, hashlib.md5(data).hexdigest())

    def test_missing_ekey_requires_encoding_lookup_not_guess(self):
        t = meta.discover(self.chain)
        b, _ = meta.load_configs(t, self.chain)
        b["download"] = [self.chain.ck]
        with self.assertRaisesRegex(meta.MetadataError, "encoding_lookup_not_implemented"):
            meta.download_spec(t, b)

    def test_missing_metadata_sizes_not_guessed(self):
        t = meta.discover(self.chain)
        b, _ = meta.load_configs(t, self.chain)
        b.pop("download-size")
        with self.assertRaisesRegex(meta.MetadataError, "size_pair_required"):
            meta.download_spec(t, b)

    def test_oversized_metadata_declared_stops_before_download(self):
        t = meta.discover(self.chain)
        b, _ = meta.load_configs(t, self.chain)
        b["download-size"] = [str(300 * 1024**2), "100"]
        with self.assertRaisesRegex(meta.MetadataError, "metadata_size_limit"):
            meta.download_spec(t, b)

    def test_metadata_response_length_mismatch(self):
        def edit(r):
            r.headers["Content-Length"] = "1"
            return r
        self.chain.edit = edit
        with self.assertRaisesRegex(meta.MetadataError, "truncated"):
            meta.discover(self.chain)

    def test_metadata_redirected_response_rejected(self):
        def edit(r):
            r.url = "https://elsewhere.invalid/"
            return r
        self.chain.edit = edit
        with self.assertRaisesRegex(meta.MetadataError, "response_invalid"):
            meta.discover(self.chain)

    def test_metadata_body_cap_even_without_length(self):
        class Infinite:
            def open(self, url, headers):
                return Response(b"x" * (meta.CAP + 1), url, headers={})
        with self.assertRaisesRegex(meta.MetadataError, "response_size"):
            meta.fetch_small(Infinite(), meta.VERSIONS, threading.Event())

    def test_metadata_can_be_bounded_without_content_length(self):
        class Small:
            def open(self, url, headers):
                return Response(b"bounded", url, headers={})
        self.assertEqual(meta.fetch_small(Small(), meta.VERSIONS, threading.Event()), b"bounded")


if __name__ == "__main__":
    unittest.main()