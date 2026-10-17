"""Read-only exact SAVED Download metadata -> fixed Install/Encoding references.

NOT a game installer, complete install selector, scan, downloader or repair.
One sequential metadata pass only. No Encoding, inventory, game or archives.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

import metadata_link_review as guard
from pinned_download_model import PINNED_MODEL

VERSION = "install-download-coverage-1"
REFERENCE_SIZE = 20275
REFERENCE_SHA256 = "5f5debea63ffc66f90a8db93cc015c1503fa23def54b67e5ca8343ed2d9d40f7"
PROFILE = {"platform": "Windows", "architecture": "x86_64", "region": "EU",
           "locales": ["enUS"]}
MAX_MATCHES = 8192
MAX_ALIASES = 64
MAX_SECONDS = 300
need = guard.need
Error = guard.ReviewError


def pinned_references(bundle, layout):
    path = guard.safe(bundle / "INSTALL-ENCODING-REFERENCES.json", True)
    before = guard.fingerprint(path.stat())
    need(before[2] == REFERENCE_SIZE, "reference_size")
    with path.open("rb") as f:
        hb = guard.fingerprint(os.fstat(f.fileno()))
        need(guard.same_open_identity(before, hb), "reference_path_handle_disagree")
        raw = f.read(REFERENCE_SIZE)
        ha = guard.fingerprint(os.fstat(f.fileno()))
        need(hb == ha, "reference_handle_changed")
        need(guard.same_open_identity(guard.fingerprint(path.stat()), ha),
             "reference_path_handle_disagree")
    need(guard.fingerprint(path.stat()) == before, "reference_changed")
    need(len(raw) == REFERENCE_SIZE and hashlib.sha256(raw).hexdigest() == REFERENCE_SHA256,
         "reference_identity")
    doc = json.loads(raw)
    need(doc["format"] == "fixed-install-encoding-references-1"
         and doc["install_ckey"] == guard.INSTALL_CKEY
         and doc["encoding_ckey"] == guard.ENCODING_CKEY
         and doc["target_build_config"] == "334a36cf5f3c32a5f7a167405487fa14",
         "reference_target")
    refs = validate_references(doc["references"], layout)
    return path, before, doc, refs


def validate_references(rows, layout):
    expected = {}
    for entry in layout.entries:
        expected.setdefault(entry.digest.hex(), set()).add(entry.declared_size)
    need(type(rows) is list and 0 < len(rows) <= 512, "reference_count")
    refs = {}
    for row in rows:
        ck, size, ekeys = row["ckey"], row["decoded_size"], row["ekeys"]
        need(type(ck) is str and re.fullmatch("[0-9a-f]{32}", ck)
             and ck not in refs and ck in expected, "reference_ckey")
        need(type(size) is int and expected[ck] == {size}, "reference_decoded_size")
        need(type(ekeys) is list and 0 < len(ekeys) <= MAX_ALIASES
             and all(type(k) is str and re.fullmatch("[0-9a-f]{32}", k)
                     and int(k, 16) > 0 for k in ekeys)
             and len(ekeys) == len(set(ekeys)), "reference_ekeys")
        refs[ck] = {"decoded_size": size, "ekeys": tuple(ekeys)}
    need(set(refs) == set(expected), "reference_key_set")
    need(len({k for r in refs.values() for k in r["ekeys"]}) <= 2048, "reference_ekey_limit")
    return refs


class Reader:
    def __init__(self, stream, model, checked):
        self.stream, self.model, self.checked = stream, model, checked
        self.used = 0
        self.md5, self.sha = hashlib.md5(), hashlib.sha256()

    def read(self, size):
        self.checked()
        need(type(size) is int and size >= 0
             and self.used + size <= self.model.decoded_bytes, "download_read_budget")
        raw = self.stream.read(size)
        self.used += len(raw)
        need(len(raw) == size, "download_truncated")
        self.md5.update(raw)
        self.sha.update(raw)
        return raw


def parse_download(stream, wanted, checked=lambda: None, progress=lambda _: None,
                   model=PINNED_MODEL):
    """Retain only exact requested EKeys; no general object inventory is built."""
    need(0 < len(wanted) <= 2048
         and all(type(k) is str and re.fullmatch("[0-9a-f]{32}", k) for k in wanted),
         "wanted_key_shape")
    wanted_raw = {bytes.fromhex(k): k for k in wanted}
    reader = Reader(stream, model, checked)
    h = reader.read(11)
    n = int.from_bytes(h[5:9], "big")
    nt = int.from_bytes(h[9:11], "big")
    need(h[:5] == b"DL\x01\x10\x00" and model.format_version == 1
         and n == model.manifest_records and 0 < n <= 3000000
         and nt == len(model.tags) <= 64, "download_pinned_header")
    width = (n + 7) // 8
    need(reader.used + n * 22 + nt * (width + 3) <= model.decoded_bytes,
         "download_geometry")
    matches = {key: [] for key in wanted}
    flat = []
    progress("read_exact_saved_download_records")
    for start in range(0, n, 4096):
        count = min(4096, n - start)
        raw = reader.read(count * 22)
        for j in range(count):
            entry = raw[j * 22:(j + 1) * 22]
            key = entry[:16]
            need(key != bytes(16), "download_zero_ekey")
            if key in wanted_raw:
                text = wanted_raw[key]
                need(len(matches[text]) < MAX_ALIASES and len(flat) < MAX_MATCHES,
                     "download_match_limit")
                row = {"record_index": start + j,
                       "declared_encoded_bytes": int.from_bytes(entry[16:21], "big"),
                       "priority_metadata_only": entry[21],
                       "download_tags": []}
                matches[text].append(row)
                flat.append(row)
        if start % (4096 * 32) == 0:
            progress("read_exact_saved_download_records")
    progress("read_saved_download_tag_bitmaps")
    for expected_name, expected_kind in model.tags:
        name = bytearray()
        while True:
            c = reader.read(1)
            if c == b"\0":
                break
            name += c
            need(len(name) <= 64, "download_tag_name_limit")
        need(bytes(name) == expected_name.encode("ascii"), "download_pinned_tag_catalogue")
        kind = int.from_bytes(reader.read(2), "big")
        need(kind == expected_kind, "download_pinned_tag_kind")
        bits = reader.read(width)
        # Only real record ordinals are inspected; padding is hashed, not interpreted.
        for row in flat:
            i = row["record_index"]
            if bits[i // 8] & (128 >> (i % 8)):
                row["download_tags"].append({"name": expected_name, "kind": kind})
    need(reader.used == model.decoded_bytes, "download_trailing_bytes")
    need(reader.md5.hexdigest() == model.ckey and reader.sha.hexdigest() == model.sha256,
         "download_whole_file_identity")
    checked()
    # Nothing from provisional matches is published before exact identity succeeds.
    return matches, reader.used


def diagnostic_match(tags):
    requested = {1: {"Windows"}, 2: {"x86_64"}, 3: {"enUS"}, 4: {"EU"}}
    dimensions = {i: set() for i in requested}
    for tag in tags:
        kind = tag["kind"] & ~0x4000
        if kind in dimensions:
            dimensions[kind].add(tag["name"])
    return all(not values or bool(values & requested[kind])
               for kind, values in dimensions.items())


def summarize(refs, matches):
    rows = []
    for key in sorted(matches):
        found = matches[key]
        sizes = {x["declared_encoded_bytes"] for x in found}
        if not found:
            state = "not_listed_in_pinned_download_unknown"
        elif len(sizes) > 1:
            state = "conflicting_download_encoded_sizes_unknown"
        elif sizes == {0}:
            state = "zero_download_encoded_size_unknown"
        else:
            state = "listed_metadata_reference_NOT_payload_proof"
        rows.append({
            "ekey": key, "state": state,
            "matching_download_records": [{
                **row,
                "matches_prior_diagnostic_profile_NOT_vendor_selection":
                    diagnostic_match(row["download_tags"]),
            } for row in found],
            "encoded_size_is_NOT_install_decoded_size": True,
            "network_download_required": None,
            "local_payload_state": "unknown_NOT_missing_or_corrupt",
        })
    return {
        "unique_install_ckeys": len(refs), "unique_referenced_ekeys": len(rows),
        "ekeys_by_reference_state": dict(Counter(x["state"] for x in rows)),
        "references": rows,
        "alternative_ekey_chosen": False, "vendor_install_policy_proven": False,
        "actual_required_install_set_known": False,
        "fresh_local_content_verified": False, "installation_ready": False,
        "apply_authorized": False, "required_network_download_bytes": None,
    }


def review(lab, bundle, progress=lambda _: None):
    start = time.monotonic()
    def checked():
        need(time.monotonic() - start <= MAX_SECONDS, "coverage_time_limit")
    lab, bundle = guard.safe(lab), guard.safe(bundle)
    need(lab.is_dir() and bundle.is_dir(), "directory_required")
    need(not (lab == bundle or lab in bundle.parents or bundle in lab.parents),
         "bundle_lab_overlap")
    for parent in (bundle,) + tuple(bundle.parents):
        need(not any((parent / marker).exists()
                     for marker in (".build.info", ".build.db", "LAB-ONLY.json")),
             "bundle_inside_game_or_lab")
    progress("verify_bundled_install_and_fixed_references")
    ip, ib, layout = guard.pinned_install(bundle / "target-install.metadata")
    rp, rb, doc, refs = pinned_references(bundle, layout)
    path = lab / "objects" / (PINNED_MODEL.ckey + "-" + str(PINNED_MODEL.decoded_bytes) + ".decoded")
    report = {
        "format": "readonly-install-download-coverage-1", "version": VERSION,
        "status": "exact_saved_download_unavailable_unknown",
        "target_build_config": doc["target_build_config"], "pinned_target_version": "12.1.5.70391",
        "profile_historical_NOT_revalidated": PROFILE,
        "profile_policy": "matching_or_unclassified_per_dimension;OR_locales;AND_dimensions_DIAGNOSTIC_ONLY",
        "reference_source_report_sha256": doc["source_report_sha256"],
        "encoding_identity_revalidated_this_run": False,
        "encoding_reference_origin": "fixed references from prior user report, not new payload proof",
        "download_ckey": PINNED_MODEL.ckey, "download_sha256_expected": PINNED_MODEL.sha256,
        "saved_download_metadata_bytes_read": 0,
        "saved_download_metadata_max_bytes": PINNED_MODEL.decoded_bytes,
        "download_metadata_passes_max": 1,
        "bundled_install_bytes_read": guard.INSTALL_SIZE,
        "bundled_reference_bytes_read": REFERENCE_SIZE,
        "encoding_bytes_read": 0, "game_bytes_read": 0, "archive_payload_bytes_read": 0,
        "inventory_bytes_read": 0, "network_requests": 0,
        "game_or_lab_writes": False, "inventory_rebuilt": False, "scan_restart": False,
        "selected_game_matches_saved_snapshot_storage": None,
        "saved_lab_snapshot_binding_checked": False, "installed_profile_revalidated": False,
        "unknown_is_not_missing_or_corrupt": True,
        "vendor_install_policy_proven": False, "actual_required_install_set_known": False,
        "installation_ready": False, "apply_authorized": False,
        "required_network_download_bytes": None, "coverage": None,
    }
    watched = [(ip, ib), (rp, rb)]
    try:
        path.lstat()
    except FileNotFoundError:
        return report, watched, path
    path = guard.safe(path, True)
    before = guard.fingerprint(path.stat())
    need(before[2] == PINNED_MODEL.decoded_bytes, "saved_download_size")
    checked()
    with path.open("rb") as f:
        hb = guard.fingerprint(os.fstat(f.fileno()))
        need(guard.same_open_identity(before, hb), "download_path_handle_disagree")
        wanted = {k for r in refs.values() for k in r["ekeys"]}
        found, used = parse_download(f, wanted, checked, progress)
        ha = guard.fingerprint(os.fstat(f.fileno()))
        need(hb == ha, "download_handle_changed")
        need(guard.same_open_identity(guard.fingerprint(path.stat()), ha),
             "download_path_handle_disagree")
    need(guard.fingerprint(path.stat()) == before, "download_changed")
    checked()
    report.update(status="pinned_install_download_reference_coverage_reviewed",
                  saved_download_metadata_bytes_read=used,
                  download_whole_file_ckey_and_sha256_verified=True,
                  coverage=summarize(refs, found))
    watched.append((path, before))
    return report, watched, None


def publish(report, watched, absent, bundle):
    bundle = guard.safe(bundle)
    def recheck():
        for path, before in watched:
            need(guard.fingerprint(guard.safe(path, True).stat()) == before,
                 "input_changed_before_or_after_output")
        if absent is not None:
            need(not os.path.lexists(absent), "absent_metadata_appeared_no_continuation")
    recheck()
    results = bundle / "Results"
    if not results.exists():
        results.mkdir()
    need(guard.safe(results).is_dir(), "results_directory")
    output = results / ("Install-Download-" + uuid.uuid4().hex)
    output.mkdir(exist_ok=False)
    final = output / "INSTALL-DOWNLOAD-COVERAGE-to-share.json"
    with final.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    try:
        recheck()
    except BaseException:
        final.unlink()  # Only this invocation's new report, never Lab/game input.
        raise
    return final


def main():
    sys.addaudithook(guard.block_network)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path)
    args = parser.parse_args()
    stage = "select_existing_lab"
    def progress(value):
        nonlocal stage
        stage = value
        print(value, flush=True)
    print("Diagnostic build:", VERSION)
    print("ONE sequential pass of exact EXISTING Download metadata <=74,562,151 bytes.")
    print("ZERO Encoding/game/archive/inventory reads, network, scans or source writes.")
    print("Fixed prior Install->Encoding references; ALL variants, NOT an install selection.")
    try:
        lab = args.lab
        if lab is None:
            import tkinter as tk
            from tkinter import filedialog, messagebox
            root = tk.Tk()
            root.withdraw()
            try:
                if not messagebox.askyesno(
                    "Read-only saved metadata coverage",
                    "Read ONE exact EXISTING saved Download metadata file in Lab "
                    "(one pass, at most 74,562,151 bytes)?\n\n"
                    "No Encoding, game/archive/inventory reads, network, scan or source writes.\n"
                    "Only a NEW separate report. Continue?"):
                    print("Cancelled.")
                    return 0
                lab = filedialog.askdirectory(title="Select EXISTING Lab, NOT game folder")
            finally:
                root.destroy()
            if not lab:
                print("Cancelled.")
                return 0
        bundle = Path(__file__).absolute().parent
        report, watched, absent = review(Path(lab), bundle, progress)
        stage = "publish_new_separate_report"
        final = publish(report, watched, absent, bundle)
        print("Share ONLY:", final)
        print(json.dumps({"status": report["status"], "installation_ready": False}))
        print("No automatic continuation. Do NOT delete Lab or restart scans.")
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "cancelled_safely", "installation_ready": False}))
        return 130
    except Exception as error:
        q = guard.public_error(error, stage)
        q["version"] = VERSION
        print(json.dumps(q))
        print("Do NOT change game, Lab or permissions; share diagnostic only.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())