"""READ-ONLY exact saved Install identity observation; NOT an installer.

One <=24,078-byte read at ONE pinned decoded cache name. No cache search,
Download/Encoding reads, extraction, archive payload, network or source writes.
Two previously approved game metadata files and saved binding metadata only.
Unknown is NOT missing/corrupt. No Install selection semantics are inferred.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import sys
import time
import uuid
import installed_profile_probe as p
import source_binding as b
import patch_audit as a

VERSION = "saved-install-review-1"
INSTALL_CKEY = "d7c8cd9845e2b5d39821678f481324da"
INSTALL_EKEY = "25ed9bec6e5d43e266d93a8b191b42cc"
INSTALL_SIZE = 24078
INSTALL_ENCODED_SIZE = 23106
CONFIG_SHA256 = "f30cdd30bcbb613795557606c0015411640ffa4a2710f7419ea75dae345c964d"
MAX_INSTALL_READ = 24078
PHASES = set(p.PHASES) | {
    "bind_saved_snapshot", "bind_selected_storage", "validate_pinned_install_reference",
    "locate_exact_install", "read_exact_install", "verify_install_identity",
    "prepare_report_output", "write_pending_report", "publish_report_noreplace",
    "postpublication_recheck", "final_input_recheck", "complete",
}


class Progress:
    def __init__(self):
        self.stage = "start"
    def mark(self, stage):
        b.need(stage in PHASES, "install_phase_invalid")
        self.stage = stage


def public_error(error, stage="start"):
    report = {
        "status": "stopped_safely", "install_review_version": VERSION,
        "stage": stage if stage in PHASES else "start",
        "error_type": type(error).__name__, "installation_ready": False,
        "unknown_is_not_missing_or_corrupt": True,
    }
    if isinstance(error, (b.BindingError, p.ProbeError, a.AuditError)) and re.fullmatch(
            "[a-z0-9_]{1,100}", str(error)):
        report["code"] = str(error)
    if isinstance(error, OSError):
        for key in ("errno", "winerror"):
            if type(getattr(error, key, None)) is int:
                report[key] = getattr(error, key)
    return report


def pinned_descriptor(raw):
    # This is a content identity check, NOT a publisher signature.
    build = a.config(raw, a.BUILD)
    b.need(hashlib.sha256(raw).hexdigest() == CONFIG_SHA256, "install_pinned_config_sha256")
    b.need(build.get("build-uid") == ["wow"] and
           build.get("build-name") == ["WOW-70391patch12.1.5_Retail"], "install_pinned_target")
    b.need(build.get("install") == [INSTALL_CKEY, INSTALL_EKEY] and
           build.get("install-size") == [str(INSTALL_SIZE), str(INSTALL_ENCODED_SIZE)],
           "install_pinned_reference_conflict")
    return {"ckey": INSTALL_CKEY, "ekey": INSTALL_EKEY, "decoded_bytes": INSTALL_SIZE,
            "encoded_bytes": INSTALL_ENCODED_SIZE}


def reconstruct(private):
    watch = b.Watch()
    for row in private["watched_files"]:
        watch.file(row["path"], row["fingerprint"])
    watch.databases = [Path(name) for name in private["closed_databases"]]
    watch.snapshot(private["local_storage_snapshot"])
    watch.check()
    return watch


def observe_exact(lab, descriptor, watch, checked=lambda: None, progress=lambda _: None):
    """Internal helper; production descriptor can ONLY come from fixed config."""
    size = descriptor["decoded_bytes"]
    b.need(type(size) is int and 10 <= size <= MAX_INSTALL_READ, "install_read_budget")
    b.need(re.fullmatch("[0-9a-f]{32}", descriptor["ckey"]) is not None, "install_key_shape")
    path = Path(lab) / "objects" / (descriptor["ckey"] + "-" + str(size) + ".decoded")
    observation = {
        "status": "not_available_at_exact_saved_cache_reference",
        "expected_decoded_bytes": size, "expected_ckey": descriptor["ckey"],
        "content_identity_revalidated": False, "metadata_bytes_read": 0,
        "absence_is_not_game_object_missing_or_corrupt": True,
        "schema_semantics_validated": False, "install_entries_parsed": False,
        "install_policy_proven": False,
    }
    progress("locate_exact_install")
    checked()
    try:
        path.lstat()
    except FileNotFoundError:
        # No fallback, path search, alternative cache, download or extraction.
        return observation, str(path)
    path = watch.file(path)
    before = watch.files[path]
    b.need(before[2] == size, "saved_install_size_conflict")
    checked()
    progress("read_exact_install")
    with path.open("rb") as stream:
        b.need(b.fp(os.fstat(stream.fileno())) == before, "saved_install_changed")
        raw = stream.read(size)  # NOT size+1: absolute read budget stays exact.
        b.need(len(raw) == size, "saved_install_short_read")
        b.need(b.fp(os.fstat(stream.fileno())) == before, "saved_install_changed")
    progress("verify_install_identity")
    b.need(hashlib.md5(raw).hexdigest() == descriptor["ckey"], "saved_install_ckey_mismatch")
    watch.check()
    checked()
    # Only identity-bound public bytes are observable. No filenames, entry
    # records, tags, private paths or policy guesses are exported.
    observation.update({
        "status": "decoded_install_identity_revalidated_structure_uninterpreted",
        "content_identity_revalidated": True, "metadata_bytes_read": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "header_observation": {
            "first_10_bytes_hex": raw[:10].hex(),
            "first_two_bytes_equal_IN": raw[:2] == b"IN",
            "byte_2_value": raw[2], "byte_3_value": raw[3],
            "byte_positions_are_observations_NOT_validated_format_semantics": True,
        },
    })
    return observation, None


def review(lab, audit, game, *, cancel=lambda: False, progress=lambda _: None):
    started = time.monotonic()
    def checked():
        b.need(not cancel(), "install_cancelled")
        b.need(time.monotonic() - started <= 300, "install_time_limit")
    checked()
    lab, audit, game = b.safe(lab), b.safe(audit), b.safe(game)
    b.need(not (lab == game or lab in game.parents or game in lab.parents), "install_lab_game_overlap")
    installed, probe = p.read(game, cancel=cancel, progress=progress)
    b.need(installed["profile"] is not None, "installed_profile_unresolved_no_guess")
    progress("bind_saved_snapshot")
    _, saved = b.bind(lab, audit, max_private=1, cancel=cancel, time_limit=120)
    private = {
        **saved,
        "closed_databases": [row["path"] for row in saved["watched_files"]
                             if Path(row["path"]).suffix == ".sqlite"],
        "protected_roots": [str(lab), str(audit), str(game)],
    }
    watch = reconstruct(private)
    for path, fingerprint in probe["watch"].files.items():
        watch.file(path, fingerprint)
    progress("bind_selected_storage")
    storage = b.safe(game / "Data/data")
    b.need(storage.is_dir() and storage == b.safe(saved["local_storage_snapshot"]["directory"]),
           "selected_game_not_saved_snapshot_storage")
    checked()
    progress("validate_pinned_install_reference")
    descriptor = pinned_descriptor(watch.read(audit / "build.config"))
    observation, absent = observe_exact(lab, descriptor, watch, checked, progress)
    report = {
        "format": "readonly-saved-install-review-1", "install_review_version": VERSION,
        "status": ("bound_install_identity_observed_policy_unresolved"
                   if observation["content_identity_revalidated"] else "bound_install_metadata_unavailable"),
        "pinned_target": saved["target"], "installed_identity": installed["installed_identity"],
        "profile": installed["profile"],
        "selected_game_matches_saved_snapshot_storage": True,
        "bound_to_existing_Lab_snapshot": True,
        "saved_snapshot_stat_fingerprints_rechecked": True,
        "install_metadata": observation,
        "scope": {
            "game_metadata_files_read": 2, "game_metadata_bytes_read": probe["watch"].read_bytes,
            "saved_install_metadata_bytes_read": observation["metadata_bytes_read"],
            "saved_install_metadata_max_bytes": MAX_INSTALL_READ,
            "saved_install_max_passes": 1,
            "saved_download_metadata_bytes_read": 0, "encoding_metadata_bytes_read": 0,
            "archive_payload_bytes_read": 0, "archive_payload_read_calls": 0,
            "archive_scan_restarted": False, "inventory_database_rebuilt": False,
            "cache_directory_enumerated_or_searched": False,
            "existing_snapshot_directory_names_and_stats_rechecked": True,
            "raw_paths_account_labels_file_entries_or_tags_exported": False,
        },
        "actual_required_install_set_known": False, "vendor_install_policy_proven": False,
        "fresh_local_content_verified": False, "installed_files_health_proven": False,
        "active_CASC_generation_proven": False, "publisher_authentication_proven": False,
        "unknown_is_not_missing_or_corrupt": True,
        "old_success_flags_used_for_content_proof": False,
        "network_requests": 0, "lab_files_modified": False, "game_files_modified": False,
        "apply_authorized": False, "installation_ready": False,
        "required_network_download_bytes": None,
        "consistency_model": "saved_stat_and_file_set_NOT_OS_snapshot_or_hostile_writer_protection",
    }
    progress("final_input_recheck")
    checked()
    watch.check()
    private["watched_files"] = [{"path": str(path), "fingerprint": value}
                                for path, value in watch.files.items()]
    private["absent_install_path"] = absent
    return report, private


def final_check(private):
    watch = reconstruct(private)
    absent = private["absent_install_path"]
    if absent is not None:
        b.need(not os.path.lexists(absent), "install_metadata_appeared_retry_required")
    return watch


def publish(report, private, out, *, progress=lambda _: None):
    progress("prepare_report_output")
    out = Path(os.path.abspath(str(out)))
    for name in private["protected_roots"]:
        root = Path(name)
        b.need(out != root and root not in out.parents and out not in root.parents,
               "install_output_overlaps_input")
    for root in (out, *out.parents):
        b.need(not any((root / name).exists() for name in (".build.info", ".build.db", "LAB-ONLY.json")),
               "install_output_in_game_or_lab")
    existing = out
    while not os.path.lexists(existing):
        existing = existing.parent
    b.safe(existing)
    b.need(not os.path.lexists(out), "install_new_output_required")
    final_check(private)
    out.mkdir(parents=True)
    pending = out / ("install-" + uuid.uuid4().hex + ".pending")
    final = out / "INSTALL-REVIEW-to-share.json"
    published = False
    try:
        progress("write_pending_report")
        with pending.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
        final_check(private)
        progress("publish_report_noreplace")
        p.publish_noreplace(pending, final)
        published = True
        progress("postpublication_recheck")
        final_check(private)
    except BaseException:
        if published:
            final.unlink()
        raise
    finally:
        if pending.exists():
            pending.unlink()
    return final


def run(lab, audit, game, out, **kwargs):
    report, private = review(lab, audit, game, **kwargs)
    final = publish(report, private, out, progress=kwargs.get("progress", lambda _: None))
    return report, final


def block_network(event, arguments):
    if event.startswith("socket."):
        raise b.BindingError("install_network_forbidden")


def main():
    sys.addaudithook(block_network)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("lab", "audit-dir", "game-root", "out-new"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    progress = Progress()
    try:
        report, final = run(args.lab, args.audit_dir, args.game_root, args.out_new, progress=progress.mark)
        print(json.dumps(report, indent=2))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "cancelled_safely", "installation_ready": False}))
        return 130
    except Exception as error:
        print(json.dumps(public_error(error, progress.stage)))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())