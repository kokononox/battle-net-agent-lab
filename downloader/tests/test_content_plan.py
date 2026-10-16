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
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repair_core as core
import target_metadata as meta
import download_inventory as dl
import encoding_inventory as en
import catalog_inventory as cat
import content_plan as planner
import cache_evidence as cache
import plan_pipeline as pipeline
import plan_storage as store
import test_download_inventory as di
import test_repair_core as rt


def md5(b):
    return hashlib.md5(b).digest()


def encoding(records, encoded_sizes):
    cp = b""
    for ck, size, keys in sorted(records):
        cp += bytes([len(keys)]) + size.to_bytes(5, "big") + ck + b"".join(keys)
    if len(cp) > 1024:
        raise ValueError("fixture capacity")
    cp = cp.ljust(1024, b"\0")
    ep = b"".join(ek + bytes(4) + size.to_bytes(5, "big")
                  for ek, size in sorted(encoded_sizes.items())).ljust(1024, b"\0")
    ci = sorted(records)[0][0] + md5(cp)
    ei = sorted(encoded_sizes)[0] + md5(ep)
    return (b"EN\x01\x10\x10" + struct.pack(">HHII", 1, 1, 1, 1) +
            bytes(5) + ci + cp + ei + ep)


def index(records, kind="group", sorted_keys=True):
    ob = {"archive": 4, "group": 6, "loose": 0}[kind]
    records = sorted(records) if sorted_keys else list(records)
    capacity = 1024 // (20 + ob)
    blocks, ends, hashes = [], [], []
    for i in range(0, len(records), capacity):
        rows = records[i:i + capacity]
        block = b""
        for ek, size, offset, ai in rows:
            loc = b"" if kind == "loose" else (
                (ai.to_bytes(2, "big") if kind == "group" else b"") +
                offset.to_bytes(4, "big"))
            block += ek + size.to_bytes(4, "big") + loc
        block = block.ljust(1024, b"\0")
        blocks.append(block)
        ends.append(rows[-1][0])
        hashes.append(md5(block)[:8])
    toc = b"".join(ends + hashes)
    base = bytes([1, 0, 0, 1, ob, 4, 16, 8]) + len(records).to_bytes(4, "little")
    footer = md5(toc)[:8] + base + md5(base + bytes(8))[:8]
    data = b"".join(blocks) + toc + footer
    return data, md5(footer).hex()


class FullChain(di.Chain):
    def __init__(self, variant=None):
        self.contents = [b"A target file" * 10, b"B locale target" * 7, b"C shared target"]
        self.blobs = [rt.encoded(b)[0] for b in self.contents]
        self.keys = [md5(b) for b in self.blobs]
        self.cks = [md5(b) for b in self.contents]
        entries = [(self.keys[i], len(self.blobs[i]), i) for i in range(3)]
        entries += [entries[0]]
        tags = [("Windows", 1, [0, 1, 3]), ("OSX", 1, [1]),
                ("x86_64", 2, [0, 1, 2, 3]),
                ("enUS", 3, [0, 2, 3]), ("deDE", 3, [1]),
                ("EU", 4, [0, 1, 2, 3]), ("Alternate", 0x4000, [2])]
        super().__init__(di.fixture(entries, tags))
        records = [(self.cks[i], len(self.contents[i]), [self.keys[i]]) for i in range(3)]
        sizes = {self.keys[i]: len(self.blobs[i]) for i in range(3)}
        if variant == "size_conflict":
            sizes[self.keys[0]] += 1
        if variant == "missing_size":
            sizes.pop(self.keys[0])
        if variant == "unmapped":
            records.pop(0)
        if variant == "ambiguous":
            records += [(b"q" * 16, 999, [self.keys[0]])]
        if variant == "duplicate_link":
            records[0] = (records[0][0], records[0][1], records[0][2] * 2)
        if variant == "too_large_decoded":
            records[0] = (records[0][0], core.decoded_payload.MAX_DECODED + 1, records[0][2])
        self.en = encoding(records, sizes)
        if variant == "bad_c_page":
            b = bytearray(self.en)
            b[60] ^= 1
            self.en = bytes(b)
        if variant == "bad_e_page":
            b = bytearray(self.en)
            b[-1000] ^= 1
            self.en = bytes(b)
        self.en_blob = b"BLTE\0\0\0\0Z" + __import__("zlib").compress(self.en)
        self.en_ck, self.en_ek = md5(self.en).hex(), md5(self.en_blob).hex()
        self.group, self.group_key = index([
            (self.keys[0], len(self.blobs[0]), 200, 1),
            (self.keys[0], len(self.blobs[0]), 100, 0),
            (self.keys[1], len(self.blobs[1]), 500, 1)])
        self.loose, self.loose_key = index([
            (self.keys[0], len(self.blobs[0]), 0, 0)], "loose")
        self.build += ("encoding = %s %s\nencoding-size = %d %d\n" %
                       (self.en_ck, self.en_ek, len(self.en), len(self.en_blob))).encode()
        self.bk = md5(self.build).hex()
        self.cdn = ("builds = %s\narchives = %s %s\narchive-group = %s\nfile-index = %s\n" %
                    (self.bk, "a" * 32, "b" * 32, self.group_key, self.loose_key)).encode()
        self.dk = md5(self.cdn).hex()
        self.versions = (
            "Region|BuildConfig|CDNConfig|BuildId|VersionsName\n"
            "eu|%s|%s|70391|12.1.5.70391\n" % (self.bk, self.dk)).encode()
        self.routes = {
            meta.VERSIONS: self.versions, meta.CDNS: self.cdns,
            meta.config_url("https://fixtures.invalid", self.bk): self.build,
            meta.config_url("https://fixtures.invalid", self.dk): self.cdn}
        for ek, data, suffix in ((self.ek, self.encoded, ""),
                                 (self.en_ek, self.en_blob, ""),
                                 (self.group_key, self.group, ".index"),
                                 (self.loose_key, self.loose, ".index")):
            self.routes["https://fixtures.invalid/tpr/wow/data/" + ek[:2] +
                        "/" + ek[2:4] + "/" + ek + suffix] = data
        self.requests = []
        self.after_first = None


class NormalChain(FullChain):
    def __init__(self):
        super().__init__()
        self.normal_a, a = index([(self.keys[0], len(self.blobs[0]), 100, 0)], "archive")
        self.normal_b, b = index([
            (self.keys[0], len(self.blobs[0]), 200, 0),
            (self.keys[1], len(self.blobs[1]), 500, 0)], "archive")
        self.archive_keys = [a, b]
        old = self.dk
        self.cdn = ("builds = %s\narchives = %s %s\narchive-group = %s\nfile-index = %s\n" %
                    (self.bk, a, b, self.group_key, self.loose_key)).encode()
        self.dk = md5(self.cdn).hex()
        self.versions = self.versions.replace(old.encode(), self.dk.encode())
        self.routes[meta.VERSIONS] = self.versions
        self.routes[meta.config_url("https://fixtures.invalid", self.dk)] = self.cdn
        for k, raw in ((a, self.normal_a), (b, self.normal_b)):
            self.routes["https://fixtures.invalid/tpr/wow/data/" + k[:2] + "/" +
                        k[2:4] + "/" + k + ".index"] = raw


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.lab = core.Lab.create(self.base / "lab")
        self.cancel = threading.Event()
        self.chain = FullChain()

    def sources(self, variant=None):
        if variant:
            self.chain = FullChain(variant)
        _, dpath = dl.prepare_inventory(self.lab, self.chain)
        target = meta.discover(self.chain)
        build, cdn = meta.load_configs(target, self.chain)
        with store.input_db(self.lab, dpath) as (_, binding):
            spec = meta.manifest_spec(target, build, "encoding")
            source = core.fetch_decoded(self.lab, spec, self.chain)
            e_result, epath = en.build(self.lab, source, spec, binding)
            gp = cat.fetch_index(self.lab, target.origins[0], self.chain.group_key, self.chain)
            lp = cat.fetch_index(self.lab, target.origins[0], self.chain.loose_key, self.chain)
            c_result, cpath = cat.build(self.lab,
                [(gp, self.chain.group_key, "group"), (lp, self.chain.loose_key, "loose")],
                cdn["archives"], binding)
        return dpath, epath, cpath

    def plan(self, variant=None, profile=None):
        sources = self.sources(variant)
        return planner.build(self.lab, *sources, profile=profile)

    def readonly(self, path):
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        self.addCleanup(db.close)
        return db

    def put(self, name, data):
        p = self.base / name
        p.write_bytes(data)
        return p

    def test_complete_join_and_deterministic_archive_range(self):
        r, path = self.plan()
        self.assertEqual(r["selected_manifest_records"], 4)
        self.assertEqual(r["selected_unique_objects"], 3)
        self.assertEqual(r["mapping_states"], {"mapped": 3})
        self.assertEqual(r["mapped_objects_with_verified_candidate_route"], 2)
        self.assertEqual(r["mapped_objects_without_route_in_checked_catalogs"], 1)
        row = self.readonly(path).execute(
            "SELECT ckey,decoded_size,archive_key,archive_offset,route_options FROM plan WHERE ekey=?",
            (self.chain.keys[0],)).fetchone()
        self.assertEqual(row, (self.chain.cks[0], len(self.chain.contents[0]), "a" * 32, 100, 3))
        self.assertIsNone(r["required_network_download_bytes"])

    def test_profile_keeps_unclassified_shared_platform_records(self):
        r, path = self.plan(profile=planner.Profile(("enUS",)))
        self.assertEqual(r["selected_manifest_records"], 3)
        keys = {r[0] for r in self.readonly(path).execute("SELECT ekey FROM plan")}
        self.assertEqual(keys, {self.chain.keys[0], self.chain.keys[2]})
        self.assertFalse(r["tag_selection"]["vendor_install_policy_proven"])

    def test_multiple_locales_union_not_intersection(self):
        r, _ = self.plan(profile=planner.Profile(("enUS", "deDE")))
        self.assertEqual(r["selected_unique_objects"], 3)

    def test_unknown_locale_not_silently_replaced_with_enUS(self):
        with self.assertRaisesRegex(core.RepairError, "tag_missing_no_fallback"):
            self.plan(profile=planner.Profile(("frFR",)))
        self.assertEqual(list((self.lab.root / "objects").glob("content-plan-*.sqlite")), [])

    def test_invalid_profile(self):
        with self.assertRaisesRegex(core.RepairError, "unsupported_plan_profile"):
            planner.Profile(("enUS",), platform="OSX").validate()

    def test_encoding_size_conflict_is_blocker_not_candidate(self):
        r, path = self.plan("size_conflict")
        state = self.readonly(path).execute(
            "SELECT mapping_state FROM plan WHERE ekey=?", (self.chain.keys[0],)).fetchone()[0]
        self.assertEqual(state, "download_encoding_size_conflict")
        self.assertEqual(r["mapped_objects_with_verified_candidate_route"], 1)

    def test_missing_encoding_size_is_unknown(self):
        _, path = self.plan("missing_size")
        self.assertEqual(self.readonly(path).execute(
            "SELECT mapping_state FROM plan WHERE ekey=?", (self.chain.keys[0],)).fetchone()[0],
            "encoding_size_not_found")

    def test_missing_ckey_is_not_guessed(self):
        _, path = self.plan("unmapped")
        self.assertEqual(self.readonly(path).execute(
            "SELECT ckey,mapping_state FROM plan WHERE ekey=?", (self.chain.keys[0],)).fetchone(),
            (None, "ckey_not_mapped"))

    def test_ambiguous_ckey_blocks_payload_proof(self):
        _, path = self.plan("ambiguous")
        self.assertEqual(self.readonly(path).execute(
            "SELECT ckey,mapping_state FROM plan WHERE ekey=?", (self.chain.keys[0],)).fetchone(),
            (None, "ambiguous_ckey_mapping"))
        source = self.put("blob", self.chain.blobs[0])
        with self.assertRaisesRegex(core.RepairError, "unambiguous_target"):
            cache.build(self.lab, path, [cache.Candidate(self.chain.keys[0], source, "encoded")])

    def test_all_c_page_checksums_required_even_if_outer_ckey_valid(self):
        with self.assertRaises(Exception):
            self.sources("bad_c_page")
        self.assertEqual(list((self.lab.root / "objects").glob("encoding-*.sqlite")), [])

    def test_all_e_page_checksums_required(self):
        with self.assertRaisesRegex(core.RepairError, "page_checksum"):
            self.sources("bad_e_page")

    def test_duplicate_ckey_ekey_links_not_silently_dropped(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.sources("duplicate_link")

    def test_wrong_index_checksum_never_produces_routes(self):
        sources = self.sources()
        gp = self.lab.root / "objects" / (self.chain.group_key + ".index")
        gp.write_bytes(gp.read_bytes()[:-1] + bytes([gp.read_bytes()[-1] ^ 1]))
        with store.input_db(self.lab, sources[0]) as (_, binding):
            with self.assertRaises(Exception):
                cat.build(self.lab, [(gp, self.chain.group_key, "group")],
                          ["a" * 32, "b" * 32], binding)
        self.assertEqual(list((self.lab.root / "objects").glob("catalog-*.sqlite.part")), [])

    def test_group_uses_configured_archive_order(self):
        d, _, _ = self.sources()
        gp = self.lab.root / "objects" / (self.chain.group_key + ".index")
        with store.input_db(self.lab, d) as (_, binding):
            _, path = cat.build(self.lab, [(gp, self.chain.group_key, "group")],
                                ["b" * 32, "a" * 32], binding)
        rows = self.readonly(path).execute(
            "SELECT archive_key,archive_offset FROM routes WHERE ekey=? ORDER BY archive_offset",
            (self.chain.keys[0],)).fetchall()
        self.assertEqual(rows, [("b" * 32, 100), ("a" * 32, 200)])

    def test_same_target_binding_required_across_metadata(self):
        d, e, c = self.sources()
        db = sqlite3.connect(c)
        b = json.loads(db.execute("SELECT value FROM metadata WHERE name='target_binding'").fetchone()[0])
        b["version"] = "12.1.5.00000"
        db.execute("UPDATE metadata SET value=? WHERE name='target_binding'", (json.dumps(b),))
        db.commit()
        db.close()
        with self.assertRaisesRegex(core.RepairError, "binding_conflict"):
            planner.build(self.lab, d, e, c)

    def test_no_direct_url_invented_for_missing_catalog_object(self):
        _, path = self.plan()
        self.assertIsNone(self.readonly(path).execute(
            "SELECT route_kind FROM plan WHERE ekey=?", (self.chain.keys[2],)).fetchone()[0])

    def test_empty_cache_batch_is_not_complete_game_inventory(self):
        _, plan = self.plan()
        r, ev = cache.build(self.lab, plan, [])
        s = cache.transfer_summary(self.lab, plan, ev)
        self.assertEqual(s["objects_without_explicit_cache_check"], 3)
        self.assertIsNone(s["required_network_download_bytes"])
        self.assertFalse(r["game_inventory_exhaustively_checked"])

    def test_verified_encoded_cache_subtracted_from_conditional_bytes_once(self):
        r, plan = self.plan()
        p = self.put("a.blte", self.chain.blobs[0])
        candidate = cache.Candidate(self.chain.keys[0], p, "encoded")
        evr, ev = cache.build(self.lab, plan, [candidate, candidate])
        s = cache.transfer_summary(self.lab, plan, ev)
        self.assertEqual(evr["encoded_target_objects_fully_verified"], 1)
        self.assertEqual(s["verified_encoded_objects_reusable"], 1)
        self.assertEqual(s["remaining_conditional_transfer_candidates"], 1)
        self.assertEqual(s["remaining_conditional_encoded_body_bytes"], len(self.chain.blobs[1]))
        self.assertIsNone(s["required_network_download_bytes"])

    def test_decoded_cache_not_confused_with_encoded_representation(self):
        _, plan = self.plan()
        p = self.put("a.decoded", self.chain.contents[0])
        r, ev = cache.build(self.lab, plan, [cache.Candidate(self.chain.keys[0], p, "decoded")])
        s = cache.transfer_summary(self.lab, plan, ev)
        self.assertEqual(r["objects_with_decoded_target_content_verified"], 1)
        self.assertEqual(s["verified_encoded_objects_reusable"], 0)
        self.assertEqual(s["remaining_conditional_transfer_candidates"], 2)

    def test_corrupt_cache_not_reused_no_source_writes(self):
        _, plan = self.plan()
        data = self.chain.blobs[0][:-1] + b"!"
        p = self.put("bad.blte", data)
        r, ev = cache.build(self.lab, plan, [cache.Candidate(self.chain.keys[0], p, "encoded")])
        self.assertEqual(r["encoded_target_objects_fully_verified"], 0)
        self.assertEqual(p.read_bytes(), data)
        self.assertEqual(self.readonly(ev).execute("SELECT state FROM evidence").fetchone()[0],
                         "candidate_content_mismatch")

    def test_index_prefix_collision_not_a_full_ekey_match(self):
        _, plan = self.plan()
        p = self.put("wrong.blte", self.chain.blobs[1])
        r, _ = cache.build(self.lab, plan, [cache.Candidate(self.chain.keys[0], p, "encoded")])
        self.assertEqual(r["encoded_target_objects_fully_verified"], 0)

    def test_read_only_casc_span_with_zero_wrapper_full_proof(self):
        _, plan = self.plan()
        data = b"x" * 50 + bytes(30) + self.chain.blobs[0] + b"unread suffix"
        p = self.put("data.000", data)
        c = cache.Candidate(self.chain.keys[0], p, "casc_span",
                            offset=50, span=30 + len(self.chain.blobs[0]))
        r, _ = cache.build(self.lab, plan, [c])
        self.assertEqual(r["encoded_target_objects_fully_verified"], 1)
        self.assertEqual(r["candidate_bytes_read"], len(self.chain.blobs[0]))
        self.assertEqual(p.read_bytes(), data)

    def test_direct_casc_span_same_payload_also_fully_verified(self):
        _, plan = self.plan()
        p = self.put("data.000", bytes(80) + self.chain.blobs[0])
        c = cache.Candidate(self.chain.keys[0], p, "casc_span",
                            offset=80, span=len(self.chain.blobs[0]))
        r, _ = cache.build(self.lab, plan, [c])
        self.assertEqual(r["encoded_target_objects_fully_verified"], 1)

    def test_out_of_bounds_span_never_borrows_other_record(self):
        _, plan = self.plan()
        p = self.put("short", self.chain.blobs[0])
        c = cache.Candidate(self.chain.keys[0], p, "casc_span",
                            offset=1, span=len(self.chain.blobs[0]))
        r, ev = cache.build(self.lab, plan, [c])
        self.assertEqual(r["candidate_bytes_read"], 0)
        self.assertIn("bounds", self.readonly(ev).execute("SELECT state FROM evidence").fetchone()[0])

    def test_bool_span_not_accepted_as_integer(self):
        _, plan = self.plan()
        p = self.put("short", self.chain.blobs[0])
        c = cache.Candidate(self.chain.keys[0], p, "casc_span", offset=True,
                            span=len(self.chain.blobs[0]))
        r, _ = cache.build(self.lab, plan, [c])
        self.assertEqual(r["encoded_target_objects_fully_verified"], 0)

    def test_candidate_must_exist_in_selected_plan(self):
        _, plan = self.plan(profile=planner.Profile(("enUS",)))
        p = self.put("excluded", self.chain.blobs[1])
        with self.assertRaisesRegex(core.RepairError, "unambiguous_target"):
            cache.build(self.lab, plan, [cache.Candidate(self.chain.keys[1], p, "encoded")])

    def test_cache_byte_budget_is_unknown_not_verified(self):
        _, plan = self.plan()
        p = self.put("a", self.chain.blobs[0])
        r, ev = cache.build(self.lab, plan,
            [cache.Candidate(self.chain.keys[0], p, "encoded")], byte_budget=0)
        self.assertEqual(r["encoded_target_objects_fully_verified"], 0)
        self.assertEqual(r["candidate_bytes_read"], 0)
        self.assertEqual(self.readonly(ev).execute("SELECT state FROM evidence").fetchone()[0],
                         "verification_limit")

    def test_cache_candidate_missing_or_shared_file_never_reused(self):
        _, plan = self.plan()
        p = self.base / "not-there"
        with self.assertRaises(FileNotFoundError):
            cache.build(self.lab, plan, [cache.Candidate(self.chain.keys[0], p, "encoded")])

    def test_evidence_cannot_be_applied_to_different_plan(self):
        d, e, c = self.sources()
        _, p1 = planner.build(self.lab, d, e, c)
        _, p2 = planner.build(self.lab, d, e, c)
        _, ev = cache.build(self.lab, p1, [])
        with self.assertRaisesRegex(core.RepairError, "different_plan"):
            cache.transfer_summary(self.lab, p2, ev)

    def test_plan_cancel_before_selection_no_publication(self):
        sources = self.sources()
        self.cancel.set()
        with self.assertRaises(core.Cancelled):
            planner.build(self.lab, *sources, cancel=self.cancel)
        self.assertEqual(list((self.lab.root / "objects").glob("content-plan-*.sqlite")), [])

    def test_full_official_metadata_pipeline_no_asset_requests(self):
        self.chain = NormalChain()
        _, d = dl.prepare_inventory(self.lab, self.chain)
        with patch("socket.socket", side_effect=AssertionError("unexpected real network")), \
             patch("subprocess.Popen", side_effect=AssertionError("no process execution")):
            r, path = pipeline.prepare(self.lab, d, transport=self.chain)
        self.assertEqual(r["plan"]["selected_unique_objects"], 3)
        self.assertTrue(r["official_target_rechecked"])
        self.assertFalse(r["game_assets_downloaded"])
        requested = {url for url, _ in self.chain.requests}
        for ek in self.chain.keys:
            self.assertFalse(any(url.endswith(ek.hex()) for url in requested))
        self.assertEqual(list((self.lab.root / "target").iterdir()), [])
        self.assertFalse(any(url.endswith(self.chain.group_key + ".index") for url in requested))

    def test_cached_group_used_without_remote_group_request(self):
        _, d = dl.prepare_inventory(self.lab, self.chain)
        (self.lab.root / "objects" / (self.chain.group_key + ".index")).write_bytes(self.chain.group)
        r, _ = pipeline.prepare(self.lab, d, transport=self.chain)
        self.assertTrue(r["catalogs"]["archive_catalog_covered"])
        self.assertFalse(any(u.endswith(self.chain.group_key + ".index")
                             for u, _ in self.chain.requests))

    def test_normal_index_request_limit_stops_before_network(self):
        chain = NormalChain()
        target = meta.discover(chain)
        _, config = meta.load_configs(target, chain)
        n = len(chain.requests)
        with self.assertRaisesRegex(core.RepairError, "network_request_limit"):
            cat.acquire(self.lab, target.origins[0], config, chain, max_network_indexes=1)
        self.assertEqual(len(chain.requests), n)

    def test_normal_indexes_fully_verified_and_cover_archive_catalog(self):
        chain = NormalChain()
        target = meta.discover(chain)
        _, config = meta.load_configs(target, chain)
        sources = cat.acquire(self.lab, target.origins[0], config, chain)
        self.assertEqual([k for _, _, k in sources], ["archive", "archive", "loose"])
        _, d = dl.prepare_inventory(self.lab, chain)
        with store.input_db(self.lab, d) as (_, binding):
            r, _ = cat.build(self.lab, sources, config["archives"], binding)
        self.assertTrue(r["archive_catalog_covered"])
        self.assertEqual(r["index_files_fully_verified"], 3)

    def test_metadata_transfer_budget_blocks_large_index_body(self):
        chain = NormalChain()
        target = meta.discover(chain)
        _, config = meta.load_configs(target, chain)
        with self.assertRaises(core.RepairError):
            cat.acquire(self.lab, target.origins[0], config, chain, byte_budget=1)
        self.assertEqual(list((self.lab.root / "objects").glob("*.index")), [])

    def test_pipeline_mismatched_download_target_stops_before_encoding(self):
        _, d = dl.prepare_inventory(self.lab, self.chain)
        self.chain.routes[meta.VERSIONS] = self.chain.versions.replace(b"70391", b"70392")
        n = len(self.chain.requests)
        with self.assertRaisesRegex(core.RepairError, "not_current"):
            pipeline.prepare(self.lab, d, transport=self.chain)
        self.assertEqual(len(self.chain.requests) - n, 2)

    def test_sources_not_modified_and_source_databases_are_attached_readonly(self):
        sources = self.sources()
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        planner.build(self.lab, *sources)
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
        with store.Writer(self.lab, "readonly-check", self.cancel) as out:
            out.db.execute("ATTACH DATABASE ? AS source", (sources[0].as_uri() + "?mode=ro",))
            with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                out.db.execute("UPDATE source.entries SET encoded_size=1")

    def test_source_change_during_plan_blocks_file_publication(self):
        sources = self.sources()
        def change(_):
            with sources[0].open("ab") as f:
                f.write(b"concurrent mutation")
        with self.assertRaises(core.RepairError):
            planner.build(self.lab, *sources, notify=change)
        self.assertEqual(list((self.lab.root / "objects").glob("content-plan-*.sqlite")), [])

    def test_mutated_cache_source_during_full_verification_blocks_evidence(self):
        _, plan = self.plan()
        p = self.put("mutable", self.chain.blobs[0])
        real = cache.decoded_payload.extract
        def mutate(*args, **kwargs):
            r = real(*args, **kwargs)
            p.write_bytes(p.read_bytes() + b"x")
            return r
        with patch("cache_evidence.decoded_payload.extract", side_effect=mutate):
            with self.assertRaisesRegex(core.RepairError, "changed"):
                cache.build(self.lab, plan, [cache.Candidate(self.chain.keys[0], p, "encoded")])
        self.assertEqual(list((self.lab.root / "objects").glob("cache-evidence-*.sqlite")), [])

    def test_encoding_and_catalog_output_integrity_and_counts(self):
        _, e, c = self.sources()
        for path in (e, c):
            self.assertEqual(self.readonly(path).execute("PRAGMA integrity_check").fetchall(), [("ok",)])
        self.assertEqual(self.readonly(e).execute(
            "SELECT COUNT(*) FROM contents").fetchone()[0], 3)
        self.assertEqual(self.readonly(e).execute(
            "SELECT COUNT(*) FROM links").fetchone()[0], 3)
        self.assertEqual(self.readonly(c).execute(
            "SELECT SUM(record_count) FROM index_proofs").fetchone()[0], 4)

    def test_catalog_disallows_duplicate_source_definition(self):
        d, _, _ = self.sources()
        gp = self.lab.root / "objects" / (self.chain.group_key + ".index")
        with store.input_db(self.lab, d) as (_, binding):
            with self.assertRaisesRegex(core.RepairError, "source_kind_or_duplicate"):
                cat.build(self.lab, [(gp, self.chain.group_key, "group")] * 2,
                          ["a" * 32, "b" * 32], binding)

    def test_catalog_never_promotes_interrupted_http_body(self):
        chain = FullChain()
        chain.edit = lambda r: di.Response(r.getvalue()[:10], r.url, r.status, r.headers)
        with self.assertRaisesRegex(core.RepairError, "interrupted_partial_retained"):
            cat.fetch_index(self.lab, "https://fixtures.invalid", chain.group_key, chain)
        self.assertFalse((self.lab.root / "objects" / (chain.group_key + ".index")).exists())
        self.assertTrue(list((self.lab.root / "objects").glob("*.index.partial")))

    def test_cancel_cache_evidence_no_output(self):
        _, plan = self.plan()
        self.cancel.set()
        with self.assertRaises(core.Cancelled):
            cache.build(self.lab, plan, [], self.cancel)
        self.assertEqual(list((self.lab.root / "objects").glob("cache-evidence-*.sqlite")), [])

    def test_invalid_candidate_kind_not_accepted_even_with_zero_budget(self):
        _, plan = self.plan()
        p = self.put("a", self.chain.blobs[0])
        with self.assertRaisesRegex(core.RepairError, "unknown_cache_candidate_kind"):
            cache.build(self.lab, plan, [cache.Candidate(self.chain.keys[0], p, "unknown")],
                        byte_budget=0)

    def test_valid_mapping_beyond_decoder_limit_is_not_a_transfer_candidate(self):
        r, p = self.plan("too_large_decoded")
        self.assertEqual(r["mapped_objects_outside_current_transfer_limits"], 1)
        self.assertEqual(self.readonly(p).execute(
            "SELECT mapping_state,transfer_supported FROM plan WHERE ekey=?",
            (self.chain.keys[0],)).fetchone(), ("mapped", 0))
        data = self.put("not-decoded", self.chain.blobs[0])
        evr, ev = cache.build(self.lab, p, [cache.Candidate(self.chain.keys[0], data, "encoded")])
        self.assertEqual(evr["candidate_bytes_read"], 0)
        self.assertEqual(cache.transfer_summary(self.lab, p, ev)
                         ["remaining_conditional_transfer_candidates"], 1)


if __name__ == "__main__":
    unittest.main()