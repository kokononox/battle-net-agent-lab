"""Disk-backed inventory of ALL records in a verified TACT Download manifest.

Not a minimal download plan, vendor tag selection, local diff or CASC writer.
"""
import hashlib
import os
import shutil
import sqlite3
import threading
import uuid
from pathlib import Path
import repair_core as core
import target_metadata as metadata

MAX_BYTES = 256 * 1024**2
MAX_ENTRIES = 10_000_000
MAX_TAGS = 4096
SOURCE = "https://wowdev.wiki/TACT#Download_manifest"
REFERENCE = ("https://github.com/ladislav-zezula/CascLib/blob/"
             "38a34665624b8775bb875274b36191b21c38d97b/src/CascOpenStorage.cpp")


class InventoryError(core.RepairError):
    pass


def _read_exact(src, n):
    b = src.read(n)
    if len(b) != n:
        raise InventoryError("download_manifest_truncated")
    return b


def _parse(src, db, cancel, notify):
    h = _read_exact(src, 11)
    if h[:2] != b"DL" or h[2] not in (1, 2, 3) or h[3] != 16:
        raise InventoryError("unsupported_download_header_or_full_ekey_length")
    version, has_checksum = h[2], h[4]
    if has_checksum not in (0, 1):
        raise InventoryError("unsupported_download_checksum_marker")
    count, nt = int.from_bytes(h[5:9], "big"), int.from_bytes(h[9:11], "big")
    if not 1 <= count <= MAX_ENTRIES or nt > MAX_TAGS:
        raise InventoryError("download_manifest_count_limit")
    flag_size, base, reserved = 0, 0, b""
    if version >= 2:
        flag_size = _read_exact(src, 1)[0]
        if flag_size > 4:
            raise InventoryError("unsupported_download_flag_size")
    if version >= 3:
        extra = _read_exact(src, 4)
        base, reserved = extra[0], extra[1:]
    entry_size = 22 + 4 * has_checksum + flag_size
    pos = src.tell()
    remaining = os.fstat(src.fileno()).st_size - pos
    if count * entry_size + nt * (3 + (count + 7) // 8) > remaining:
        raise InventoryError("download_manifest_declared_bounds")
    pending = []
    declared_bytes = 0
    for ordinal in range(count):
        if ordinal % 4096 == 0:
            core.check(cancel)
            notify("Reading Download records: %d / %d" % (ordinal, count))
        b = _read_exact(src, entry_size)
        ek, size, priority = b[:16], int.from_bytes(b[16:21], "big"), b[21]
        if ek == bytes(16):
            raise InventoryError("zero_download_ekey_unsupported")
        declared_bytes += size
        if declared_bytes > 2**63 - 1:
            raise InventoryError("declared_byte_sum_outside_sqlite_integer_range")
        at = 22
        checksum = b[at:at + 4] if has_checksum else None
        at += 4 * has_checksum
        flags = b[at:]
        # Retain raw fields. No claim that adjusted priority is vendor scheduling.
        pending.append((ordinal, ek, size, priority, priority - base, checksum, flags))
        if len(pending) == 4096:
            db.executemany("INSERT INTO entries VALUES (?,?,?,?,?,?,?)", pending)
            pending.clear()
    if pending:
        db.executemany("INSERT INTO entries VALUES (?,?,?,?,?,?,?)", pending)
    seen = set()
    width = (count + 7) // 8
    nonzero_padding = 0
    for ordinal in range(nt):
        core.check(cancel)
        name = bytearray()
        while True:
            c = _read_exact(src, 1)
            if c == b"\0":
                break
            name += c
            if len(name) > 256:
                raise InventoryError("download_tag_name_limit")
        try:
            text = name.decode("utf-8")
        except UnicodeError:
            raise InventoryError("download_tag_encoding") from None
        if not text or any(ord(c) < 32 or ord(c) == 127 for c in text):
            raise InventoryError("download_tag_name_invalid")
        kind = int.from_bytes(_read_exact(src, 2), "big")
        identity = (kind, text)
        if identity in seen:
            raise InventoryError("duplicate_download_tag")
        seen.add(identity)
        mask = _read_exact(src, width)
        padding = (8 - count % 8) % 8
        if padding and mask[-1] & ((1 << padding) - 1):
            nonzero_padding += 1
        # MSB first. Padding bits are observed, never used as membership.
        members = sum(bin(b).count("1") for b in mask)
        if padding:
            members -= bin(mask[-1] & ((1 << padding) - 1)).count("1")
        db.execute("INSERT INTO tags VALUES (?,?,?,?,?,?)",
                   (ordinal, text, kind, mask, members, bool(padding and
                    mask[-1] & ((1 << padding) - 1))))
    if src.read(1):
        raise InventoryError("download_manifest_trailing_bytes")
    core.check(cancel)
    db.execute("CREATE INDEX entries_ekey ON entries(ekey)")
    conflict = db.execute(
        "SELECT 1 FROM entries GROUP BY ekey HAVING MIN(encoded_size)<>MAX(encoded_size) LIMIT 1"
    ).fetchone()
    if conflict:
        raise InventoryError("same_ekey_conflicting_encoded_sizes")
    db.execute("""CREATE VIEW objects AS
        SELECT ekey, MIN(encoded_size) AS encoded_size, COUNT(*) AS source_records,
               MIN(raw_priority) AS minimum_raw_priority
        FROM entries GROUP BY ekey""")
    total_rows, raw_bytes = db.execute(
        "SELECT COUNT(*),COALESCE(SUM(encoded_size),0) FROM entries").fetchone()
    unique, unique_bytes = db.execute(
        "SELECT COUNT(*),COALESCE(SUM(encoded_size),0) FROM objects").fetchone()
    # Independent totals, not the GROUP BY view above.
    distinct = db.execute("SELECT COUNT(DISTINCT ekey) FROM entries").fetchone()[0]
    if total_rows != count or unique != distinct:
        raise InventoryError("inventory_reconciliation_failed")
    if raw_bytes != declared_bytes:
        raise InventoryError("inventory_byte_sum_reconciliation_failed")
    return {
        "format_version": version, "manifest_records": count, "manifest_tags": nt,
        "unique_encoded_objects": unique, "duplicate_records": count - unique,
        "record_encoded_bytes_sum": raw_bytes, "unique_encoded_bytes_sum": unique_bytes,
        "flag_bytes_per_record": flag_size, "base_priority_raw_unsigned": base,
        "v3_reserved_bytes_nonzero": any(reserved),
        "entry_checksums_present": bool(has_checksum),
        "entry_checksum_algorithm_validated": False,
        "tags_with_nonzero_unused_padding_bits": nonzero_padding,
        "zero_size_objects": db.execute(
            "SELECT COUNT(*) FROM objects WHERE encoded_size=0").fetchone()[0],
        "all_manifest_records_included": True, "tag_filter_applied": False,
        "vendor_install_selection_proven": False,
        "full_game_target_closure_proven": False,
        "local_missing_or_corrupt_objects_computed": False,
        "required_network_download_bytes": None,
        "installation_ready": False,
    }


def build_inventory(lab, source, spec, binding, cancel=None, notify=lambda _: None):
    """Caller holds the lab lock. Source must be an owned, verified decoded object."""
    cancel = cancel or threading.Event()
    spec.validate()
    source = core.regular(source)
    if source.parent != lab.root / "objects":
        raise InventoryError("owned_metadata_cache_required")
    if source.stat().st_size > MAX_BYTES:
        raise InventoryError("download_manifest_size_limit")
    proof = core.digest(source, cancel)
    if proof["md5"] != spec.ckey or proof["size"] != spec.decoded_size:
        raise InventoryError("download_manifest_ckey_or_size_mismatch")
    before = core.fingerprint(source.stat())
    # Bounded disk-backed SQLite, not millions of in-memory dictionaries.
    if shutil.disk_usage(source.parent).free < 4 * proof["size"] + 64 * 1024**2:
        raise InventoryError("inventory_disk_space")
    token = uuid.uuid4().hex
    temp = core.safe(source.parent / ("inventory-" + token + ".sqlite.part"))
    final = core.safe(source.parent / ("inventory-" + token + ".sqlite"))
    db = None
    try:
        # Reserve exclusively. sqlite3.connect by itself would open an existing DB.
        with temp.open("xb"):
            pass
        db = sqlite3.connect(str(temp))
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA temp_store=FILE")
        db.execute("PRAGMA cache_size=-8192")
        db.set_progress_handler(lambda: int(cancel.is_set()), 10000)
        db.executescript("""
            CREATE TABLE entries(
              ordinal INTEGER PRIMARY KEY, ekey BLOB NOT NULL,
              encoded_size INTEGER NOT NULL, raw_priority INTEGER NOT NULL,
              priority_minus_base INTEGER NOT NULL, checksum BLOB, flags BLOB NOT NULL);
            CREATE TABLE tags(
              ordinal INTEGER PRIMARY KEY, name TEXT NOT NULL, kind INTEGER NOT NULL,
              bitmap BLOB NOT NULL, member_records INTEGER NOT NULL,
              nonzero_padding INTEGER NOT NULL);
            CREATE TABLE metadata(name TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        with source.open("rb") as src:
            if core.fingerprint(os.fstat(src.fileno())) != before:
                raise InventoryError("manifest_source_changed")
            result = _parse(src, db, cancel, notify)
            if core.fingerprint(os.fstat(src.fileno())) != before:
                raise InventoryError("manifest_source_changed")
        if core.fingerprint(core.regular(source).stat()) != before:
            raise InventoryError("manifest_source_changed")
        import json
        db.execute("INSERT INTO metadata VALUES (?,?)",
                   ("target_binding", json.dumps(binding, sort_keys=True)))
        db.execute("INSERT INTO metadata VALUES (?,?)",
                   ("inventory_summary", json.dumps(result, sort_keys=True)))
        db.execute("INSERT INTO metadata VALUES (?,?)",
                   ("source_sha256", proof["sha256"]))
        db.commit()
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise InventoryError("inventory_database_check_failed")
        db.close()
        db = None
        core.check(cancel)
        os.replace(temp, final)
        core.sync_dir(final.parent)
        return result, final
    except sqlite3.OperationalError:
        if cancel.is_set():
            raise core.Cancelled("cancelled") from None
        raise InventoryError("inventory_database_operation_failed") from None
    finally:
        if db is not None:
            db.close()
        if temp.exists():
            core.regular(temp).unlink()
        for suffix in ("-journal", "-wal", "-shm"):
            aux = core.safe(Path(str(temp) + suffix))
            if aux.exists():
                core.regular(aux).unlink()


def prepare_inventory(lab, transport=None, cancel=None, notify=lambda _: None):
    """Discover target, verify configs + DL object, inventory ALL DL records.

    Downloads only small metadata (DL capped at 256 MiB). Does not fetch game assets.
    Target binding is checked again at the end; no silent retargeting mid-run.
    """
    cancel = cancel or threading.Event()
    transport = transport or core.HTTPS()
    with lab.lock():
        target = metadata.discover(transport, cancel)
        build, _cdn = metadata.load_configs(target, transport, cancel)
        spec = metadata.download_spec(target, build)
        decoded = core.fetch_decoded(lab, spec, transport, cancel)
        binding = {
            "product": "wow", "region": "eu", "version": target.version,
            "build_config": target.build_config, "cdn_config": target.cdn_config,
            "download_ckey": spec.ckey, "download_ekey": spec.ekey,
            "origin": target.origins[0],
        }
        result, path = build_inventory(lab, decoded, spec, binding, cancel, notify)
        after = metadata.discover(transport, cancel)
        if after.identity() != target.identity() or target.origins[0] not in after.origins:
            # Retain inventory as pinned evidence, but DO NOT publish a ready plan.
            raise metadata.MetadataError("official_target_changed_refresh_required")
        result = dict(result, status="bound_download_manifest_inventory_complete",
                      target_version=target.version, product="wow", region="eu",
                      official_target_binding_rechecked=True,
                      game_files_modified=False, bulk_game_assets_downloaded=False,
                      sources=[SOURCE, REFERENCE])
        return result, path