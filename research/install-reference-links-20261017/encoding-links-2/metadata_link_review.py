"""READ-ONLY Install -> Encoding metadata link review, NOT an updater.

Only the exact already saved decoded Encoding metadata is opened in Lab.
No game paths, archive payload, SQLite, cache search, download or repair.
All Install variants are checked; no guessed profile selection is installed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

VERSION = "install-encoding-links-2"
WINDOWS_CTIME_BRIDGE = sys.platform == "win32"
ENCODING_CKEY = "8d0576391f8e80ce55940381fc3f674a"
ENCODING_SIZE = 200255318
INSTALL_CKEY = "d7c8cd9845e2b5d39821678f481324da"
INSTALL_SHA256 = "1e9a735e4ec5ffe7fc10b9f39e347cf6f9745a89d15ba700a3982399644d92a6"
INSTALL_SIZE = 24078
LOOKUP_LIMIT = 32 * 1024**2
TOTAL_ENCODING_LIMIT = ENCODING_SIZE + LOOKUP_LIMIT
MAX_SECONDS = 300


class ReviewError(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise ReviewError(code)


def fingerprint(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
            s.st_ctime_ns, s.st_nlink)


def same_open_identity(path_state, handle_state):
    """Compare path and handle identities, NOT two temporal observations.

    Windows stat/fstat ctime values can differ, as diagnosed on Python 3.13.
    Keep ctime in each channel's full before/after fingerprint; only omit it
    from the cross-API bridge. All other fields must still agree exactly.
    """
    if WINDOWS_CTIME_BRIDGE:
        return path_state[:4] == handle_state[:4] and path_state[5:] == handle_state[5:]
    return path_state == handle_state


def safe(path, regular=False):
    p = Path(os.path.abspath(str(path)))
    for item in reversed((p,) + tuple(p.parents)):
        s = item.lstat()
        need(not stat.S_ISLNK(s.st_mode) and
             not getattr(s, "st_file_attributes", 0) & 0x400,
             "link_or_reparse_point")
        if item != p:
            need(stat.S_ISDIR(s.st_mode), "non_directory_ancestor")
    if regular:
        s = p.stat()
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1,
             "regular_unshared_input_required")
    return p


def block_network(event, arguments):
    if event.startswith("socket."):
        raise ReviewError("network_forbidden")


class BudgetReader:
    def __init__(self, stream, size, limit=LOOKUP_LIMIT, checked=lambda: None):
        self.stream, self.size, self.limit = stream, size, limit
        self.bytes_read = 0
        self.calls = 0
        self.checked = checked

    def read(self, at, count):
        self.checked()
        need(type(at) is int and type(count) is int and
             at >= 0 and count >= 0 and at + count <= self.size,
             "lookup_bounds")
        need(self.bytes_read + count <= self.limit, "lookup_budget")
        self.stream.seek(at)
        raw = self.stream.read(count)
        self.calls += 1
        self.bytes_read += len(raw)
        need(len(raw) == count, "lookup_short_read")
        self.checked()
        return raw


class ContentLookup:
    """Only CKey pages; never downloads payload or parses all archive entries."""
    def __init__(self, reader):
        self.r = reader
        h = reader.read(0, 22)
        need(h[:5] == b"EN\x01\x10\x10" and h[17] == 0, "encoding_header")
        self.cs = int.from_bytes(h[5:7], "big") * 1024
        es = int.from_bytes(h[7:9], "big") * 1024
        self.cn = int.from_bytes(h[9:13], "big")
        en = int.from_bytes(h[13:17], "big")
        specsize = int.from_bytes(h[18:22], "big")
        need(1024 <= self.cs <= 65536 and 1024 <= es <= 65536 and
             0 < self.cn <= 500000 and 0 < en <= 500000 and
             0 < specsize <= 16 * 1024**2, "encoding_geometry_limit")
        ci = 22 + specsize
        self.cp = ci + 32 * self.cn
        ei = self.cp + self.cs * self.cn
        ep = ei + 32 * en
        need(ep + es * en <= reader.size, "encoding_geometry_bounds")
        self.unparsed_tail = reader.size - (ep + es * en)
        self.index = reader.read(ci, 32 * self.cn)
        previous = None
        for i in range(self.cn):
            key = self.index[i*32:i*32+16]
            need(key != bytes(16) and (previous is None or previous < key),
                 "encoding_index_order")
            previous = key
        self.pages = {}

    def key(self, i):
        return self.index[i*32:i*32+16]

    def content(self, key):
        need(type(key) is bytes and len(key) == 16 and key != bytes(16),
             "content_key_shape")
        lo, hi = 0, self.cn
        while lo < hi:
            middle = (lo+hi)//2
            if self.key(middle) <= key:
                lo = middle+1
            else:
                hi = middle
        i = lo-1
        if i < 0:
            return None
        if i not in self.pages:
            raw = self.r.read(self.cp+i*self.cs, self.cs)
            need(hashlib.md5(raw).digest() == self.index[i*32+16:i*32+32],
                 "selected_page_checksum")
            # Parse and validate the entire selected page before returning any key.
            first = self.key(i)
            following = self.key(i+1) if i+1 < self.cn else None
            pos, last, entries = 0, None, {}
            while pos < len(raw):
                count = raw[pos]
                if count == 0:
                    need(not any(raw[pos:]), "content_page_padding")
                    break
                stop = pos+22+16*count
                need(stop <= len(raw), "content_record_bounds")
                ck = raw[pos+6:pos+22]
                size = int.from_bytes(raw[pos+1:pos+6], "big")
                need(ck != bytes(16) and (last is not None or ck == first) and
                     (last is None or last < ck) and
                     (following is None or ck < following), "content_page_order")
                links = tuple(raw[j:j+16] for j in range(pos+22, stop, 16))
                need(all(x != bytes(16) for x in links) and
                     len(set(links)) == len(links), "content_links")
                entries[ck] = (size, links)
                last, pos = ck, stop
            self.pages[i] = entries
        return self.pages[i].get(key)


def hash_exact(stream, expected_size, expected_ckey, checked=lambda: None,
               progress=lambda _: None):
    need(type(expected_size) is int and 0 < expected_size <= ENCODING_SIZE and
         type(expected_ckey) is str and
         re.fullmatch("[0-9a-f]{32}", expected_ckey), "hash_descriptor")
    total, md5, sha = 0, hashlib.md5(), hashlib.sha256()
    while total < expected_size:
        checked()
        data = stream.read(min(1024**2, expected_size-total))
        need(bool(data), "hash_short_read")
        total += len(data)
        need(total <= expected_size, "hash_budget")
        md5.update(data)
        sha.update(data)
        if total % (32*1024**2) == 0:
            progress("hashing_exact_saved_encoding")
    # No size+1 read. Descriptor and pathname stat checks enforce exact size.
    need(md5.hexdigest() == expected_ckey, "encoding_whole_file_ckey")
    checked()
    return {"hash_bytes_read": total, "encoding_sha256": sha.hexdigest()}


def pinned_install(path):
    import install_structure as parser
    path = safe(path, True)
    before = fingerprint(path.stat())
    need(before[2] == INSTALL_SIZE, "install_size")
    with path.open("rb") as f:
        handle_before = fingerprint(os.fstat(f.fileno()))
        need(same_open_identity(before, handle_before), "install_path_handle_disagree")
        raw = f.read(INSTALL_SIZE)
        handle_after = fingerprint(os.fstat(f.fileno()))
        need(handle_after == handle_before, "install_handle_changed")
        need(same_open_identity(fingerprint(path.stat()), handle_after),
             "install_path_handle_disagree")
    need(fingerprint(path.stat()) == before, "install_changed")
    need(len(raw) == INSTALL_SIZE and hashlib.md5(raw).hexdigest() == INSTALL_CKEY
         and hashlib.sha256(raw).hexdigest() == INSTALL_SHA256, "install_identity")
    layout = parser.parse_candidate(raw)
    need(len(layout.entries) == 274 and len(layout.tags) == 31, "install_geometry")
    return path, before, layout


def link_records(layout, table):
    # All serialized records, including duplicate names and all profile variants.
    expected = {}
    for entry in layout.entries:
        expected.setdefault(entry.digest, set()).add(entry.declared_size)
    states, bykey = {}, {}
    for ck, install_sizes in sorted(expected.items()):
        found = table.content(ck)
        if len(install_sizes) != 1:
            state = "install_declared_size_conflict_unknown"
        elif found is None:
            state = "not_resolved_in_pinned_encoding_unknown"
        elif found[0] != next(iter(install_sizes)):
            state = "encoding_and_install_size_disagreement_unknown"
        else:
            state = "metadata_link_and_declared_size_agree_NOT_payload_proof"
        states[state] = states.get(state, 0)+1
        bykey[ck] = {
            "ckey": ck.hex(), "install_declared_sizes": sorted(install_sizes),
            "state": state,
            "encoding_declared_decoded_size": None if found is None else found[0],
            "encoding_ekeys": [] if found is None else [k.hex() for k in found[1]],
            "ekeys_are_metadata_references_NOT_payload_validation": True,
        }
    need(sum(states.values()) == len(expected), "mapping_reconciliation")
    return {
        "serialized_install_records": len(layout.entries),
        "unique_install_ckeys": len(expected),
        "unique_ckeys_by_state": states,
        "links": [bykey[k] for k in sorted(bykey)],
        "all_install_variants_checked_without_profile_selection": True,
        "records_deduplicated_for_install": False,
        "vendor_install_policy_proven": False,
        "actual_required_install_set_known": False,
        "fresh_local_content_verified": False,
        "installation_ready": False,
        "apply_authorized": False,
        "required_network_download_bytes": None,
    }


def base_report():
    return {
        "format": "readonly-install-encoding-link-review-1", "version": VERSION,
        "identity_guard": {
            "path_full_fingerprint_before_after": True,
            "handle_full_fingerprint_before_after": True,
            "ctime_in_both_temporal_checks": True,
            "windows_cross_api_ctime_excluded": WINDOWS_CTIME_BRIDGE,
            "cross_api_identity_size_mtime_nlink_required": True,
        },
        "status": "not_started",
        "target_build_config": "334a36cf5f3c32a5f7a167405487fa14",
        "pinned_target_version": "12.1.5.70391",
        "encoding_ckey": ENCODING_CKEY, "encoding_decoded_bytes": ENCODING_SIZE,
        "install_ckey": INSTALL_CKEY,
        "unknown_is_not_missing_or_corrupt": True,
        "network_requests": 0, "archive_payload_bytes_read": 0,
        "raw_download_metadata_bytes_read": 0, "game_metadata_bytes_read": 0,
        "saved_lab_snapshot_binding_checked": False,
        "installed_profile_revalidated": False,
        "game_or_lab_writes": False, "cache_search_or_scan_restart": False,
        "vendor_install_policy_proven": False,
        "actual_required_install_set_known": False,
        "installation_ready": False, "apply_authorized": False,
        "required_network_download_bytes": None,
    }


def review(lab, bundle, progress=lambda _: None):
    started = time.monotonic()
    def checked():
        need(time.monotonic()-started <= MAX_SECONDS, "review_time_limit")
    lab, bundle = safe(lab), safe(bundle)
    need(lab.is_dir() and bundle.is_dir(), "directory_required")
    need(not (lab == bundle or lab in bundle.parents or bundle in lab.parents),
         "bundle_lab_overlap")
    # Avoid new result files inside a recognisable game or Lab root.
    for parent in (bundle,)+tuple(bundle.parents):
        need(not (parent/".build.info").exists() and
             not (parent/"LAB-ONLY.json").exists(), "bundle_inside_game_or_lab")
    progress("verify_bundled_install_identity")
    install_path, install_before, layout = pinned_install(bundle/"target-install.metadata")
    report = base_report()
    report["bundled_install_bytes_read"] = INSTALL_SIZE
    exact = lab/"objects"/(ENCODING_CKEY+"-"+str(ENCODING_SIZE)+".decoded")
    report["exact_cache_available"] = False
    progress("locate_one_exact_saved_encoding_reference")
    try:
        exact.lstat()
    except FileNotFoundError:
        report.update(status="exact_saved_encoding_unavailable_unknown",
                      encoding_hash_bytes_read=0, encoding_lookup_bytes_read=0)
        return report, [(install_path, install_before)]
    path = safe(exact, True)
    before = fingerprint(path.stat())
    need(before[2] == ENCODING_SIZE, "saved_encoding_size")
    report["exact_cache_available"] = True
    checked()
    with path.open("rb") as f:
        handle_before = fingerprint(os.fstat(f.fileno()))
        need(same_open_identity(before, handle_before), "encoding_path_handle_disagree")
        progress("hashing_exact_saved_encoding")
        proof = hash_exact(f, ENCODING_SIZE, ENCODING_CKEY, checked, progress)
        progress("looking_up_install_content_keys_only")
        reader = BudgetReader(f, ENCODING_SIZE, checked=checked)
        table = ContentLookup(reader)
        links = link_records(layout, table)
        handle_after = fingerprint(os.fstat(f.fileno()))
        need(handle_after == handle_before, "encoding_handle_changed")
        need(same_open_identity(fingerprint(path.stat()), handle_after),
             "encoding_path_handle_disagree")
    need(fingerprint(path.stat()) == before, "encoding_changed")
    need(fingerprint(install_path.stat()) == install_before, "install_changed")
    checked()
    report.update(status="pinned_install_encoding_metadata_links_reviewed",
                  encoding_whole_file_ckey_verified=True,
                  encoding_sha256=proof["encoding_sha256"],
                  encoding_hash_bytes_read=proof["hash_bytes_read"],
                  encoding_lookup_bytes_read=reader.bytes_read,
                  total_encoding_metadata_bytes_read=proof["hash_bytes_read"]+reader.bytes_read,
                  total_encoding_metadata_max_bytes=TOTAL_ENCODING_LIMIT,
                  selected_content_pages_checked=len(table.pages),
                  selected_content_page_checksums_verified=True,
                  encoding_other_pages_semantically_parsed=False,
                  unparsed_encoding_tail_bytes=table.unparsed_tail,
                  mapping=links)
    return report, [(install_path, install_before), (path, before)]


def publish(report, watched, bundle):
    bundle = safe(bundle)
    for path, before in watched:
        need(fingerprint(safe(path, True).stat()) == before, "input_changed_before_output")
    results = bundle/"Results"
    if results.exists():
        need(safe(results).is_dir(), "results_directory")
    else:
        results.mkdir()
        safe(results)
    out = results/("Install-Encoding-"+uuid.uuid4().hex)
    out.mkdir(exist_ok=False)
    final = out/"INSTALL-ENCODING-LINKS-to-share.json"
    with final.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    try:
        for path, before in watched:
            need(fingerprint(safe(path, True).stat()) == before, "input_changed_after_output")
    except Exception:
        final.unlink()  # Only this invocation's newly created report.
        raise
    return final


def public_error(error, stage):
    result = {"status": "stopped_safely", "version": VERSION,
              "stage": stage, "error_type": type(error).__name__,
              "installation_ready": False, "apply_authorized": False,
              "unknown_is_not_missing_or_corrupt": True}
    if isinstance(error, ReviewError) and re.fullmatch("[a-z0-9_]{1,100}", str(error)):
        result["code"] = str(error)
    if isinstance(error, OSError):
        for name in ("errno", "winerror"):
            if type(getattr(error, name, None)) is int:
                result[name] = getattr(error, name)
    return result


def main():
    import argparse
    sys.addaudithook(block_network)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lab", type=Path)
    args = p.parse_args()
    base = Path(__file__).resolve().parent
    stage = "select_existing_lab"
    def progress(value):
        nonlocal stage
        stage = value
        print(value, flush=True)
    print("Diagnostic build:", VERSION)
    print("READ-ONLY metadata: ONE exact EXISTING decoded Encoding cache.")
    print("Full hash <=200,255,318 bytes + indexed lookups <=32 MiB.")
    print("Bundled verified Install metadata <=24,078 bytes.")
    print("ZERO game/archive/Download reads, network, scans or game/Lab writes.")
    print("All Install variants: NOT an installer or a profile selection.")
    try:
        lab = args.lab
        if lab is None:
            import tkinter as tk
            from tkinter import filedialog, messagebox
            root = tk.Tk()
            root.withdraw()
            try:
                if not messagebox.askyesno(
                    "Read-only metadata review",
                    "Read only the exact EXISTING Encoding metadata in Lab "
                    "(200,255,318 bytes for identity + at most 32 MiB lookups)?\n\n"
                    "No archive/game reads, network, scan or source writes. "
                    "Do not select the game folder. Continue?"):
                    print("Cancelled.")
                    return 0
                lab = filedialog.askdirectory(title="Select EXISTING Lab (not the game folder)")
            finally:
                root.destroy()
            if not lab:
                print("Cancelled.")
                return 0
        report, watched = review(Path(lab), base, progress)
        stage = "publish_new_separate_report"
        final = publish(report, watched, base)
        print("Share ONLY:", final)
        print(json.dumps({"status": report["status"], "installation_ready": False}))
        print("No automatic continuation. Do NOT delete Lab or restart scans.")
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "cancelled_safely", "installation_ready": False}))
        return 130
    except Exception as error:
        print(json.dumps(public_error(error, stage)))
        print("Do NOT change game, Lab or permissions; share this diagnostic only.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())