"""Verified complete CDN catalog indexes -> SQLite. No guessed direct routes."""
import hashlib
import mmap
import os
import re
import shutil
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
import cdn_catalog
import repair_core as core
import plan_storage as store
import target_metadata as metadata

MAX_INDEX_BYTES = 256 * 1024**2


def fetch_index(lab, origin, index_key, transport, cancel=None,
                max_bytes=MAX_INDEX_BYTES, budget=None):
    """Small/medium metadata transfer, not a bulk asset transfer.

    Index HTTP resume is not implemented yet. On interruption, retain the partial
    under a unique name, never mistake it for a complete/verified index.
    """
    cancel = cancel or threading.Event()
    metadata.key(index_key)
    target = core.safe(lab.root / "objects" / (index_key + ".index"))
    if target.exists():
        core.regular(target)
        if not 28 <= target.stat().st_size <= max_bytes:
            raise core.RepairError("cached_catalog_size_limit")
        return target  # The build step MUST verify every checksum before use.
    tmp = target.with_name(index_key + "." + uuid.uuid4().hex + ".index.partial")
    url = origin + "/tpr/wow/data/" + index_key[:2] + "/" + index_key[2:4] + "/" + index_key + ".index"
    core.check(cancel)
    with transport.open(url, {}) as r:
        if (r.status != 200 or r.geturl() != url or r.headers.get("Content-Range")
                or r.headers.get("Content-Encoding", "identity").lower() not in ("", "identity")):
            raise core.RepairError("catalog_http_response_invalid")
        length = r.headers.get("Content-Length", "")
        if not re.fullmatch("[0-9]+", length) or not 28 <= int(length) <= max_bytes:
            raise core.RepairError("catalog_http_size_invalid")
        length = int(length)
        if budget:
            budget.reserve(length)
        if shutil.disk_usage(target.parent).free < length + 64 * 1024**2:
            raise core.RepairError("catalog_download_space")
        with core.safe(tmp).open("xb") as f:
            total = 0
            while total < length:
                core.check(cancel)
                b = r.read(min(65536, length - total))
                if not b:
                    raise core.RepairError("catalog_download_interrupted_partial_retained")
                f.write(b)
                total += len(b)
            if r.read(1):
                raise core.RepairError("catalog_download_extra_body")
            f.flush()
            os.fsync(f.fileno())
    os.replace(tmp, target)
    core.sync_dir(target.parent)
    return target


class TransferBudget:
    def __init__(self, cap):
        self.cap, self.used, self.lock = cap, 0, threading.Lock()

    def reserve(self, count):
        with self.lock:
            if self.used + count > self.cap:
                raise core.RepairError("catalog_metadata_transfer_budget")
            self.used += count


def acquire(lab, origin, cdn, transport, cancel=None, notify=lambda _: None,
            max_network_indexes=2048, byte_budget=512 * 1024**2):
    """Use a verified-config cached group OR actual advertised archive indexes.

    archive-group is CLIENT-GENERATED, not a downloadable CDN file. Never request
    it remotely. Up to four bounded metadata transfers run concurrently.
    """
    cancel = cancel or threading.Event()
    archives = cdn.get("archives", [])
    if (not archives or len(archives) > 10000 or len(set(archives)) != len(archives)
            or any(not isinstance(k, str) or not metadata.HEX.fullmatch(k) for k in archives)):
        raise core.RepairError("catalog_archive_configuration_invalid")
    group = cdn.get("archive-group", [])
    if len(group) > 1:
        raise core.RepairError("multiple_group_catalog_keys_not_supported")
    if group:
        metadata.key(group[0])
    cached_group = core.safe(lab.root / "objects" / ((group[0] if group else "absent") + ".index"))
    sources = []
    budget = TransferBudget(byte_budget)
    if group and cached_group.exists():
        core.regular(cached_group)
        sources.append((cached_group, group[0], "group"))
    else:
        absent = [k for k in archives if not core.safe(lab.root / "objects" / (k + ".index")).exists()]
        if len(absent) > max_network_indexes:
            raise core.RepairError("normal_catalog_network_request_limit")
        abort = threading.Event()
        failures, failure_lock = [], threading.Lock()
        class CombinedCancel:
            def is_set(self):
                return cancel.is_set() or abort.is_set()
        combined = CombinedCancel()
        def worker(k):
            try:
                core.check(combined)
                return fetch_index(lab, origin, k, transport, combined,
                                   max_bytes=16 * 1024**2, budget=budget), k, "archive"
            except BaseException as e:
                with failure_lock:
                    if not failures:
                        failures.append(e)
                abort.set()
                raise
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                for i, item in enumerate(pool.map(worker, archives), 1):
                    sources.append(item)
                    if i % 25 == 0 or i == len(archives):
                        notify("Archive index metadata: %d / %d" % (i, len(archives)))
        except BaseException:
            if failures:
                raise failures[0] from None
            raise
        # The same transfer budget covers loose metadata below.
        if abort.is_set():
            raise core.RepairError("catalog_acquisition_incomplete")
    loose = cdn.get("file-index", [])
    if len(loose) > 1:
        raise core.RepairError("multiple_loose_catalog_keys_not_supported")
    if loose:
        metadata.key(loose[0])
        # A configured loose index is a REAL advertised CDN object.
        path = fetch_index(lab, origin, loose[0], transport, cancel,
                           budget=budget)
        sources.append((path, loose[0], "loose"))
    return sources


def build(lab, sources, archives, binding, cancel=None, notify=lambda _: None):
    """sources: [(owned_path, index_key, 'group'|'archive'|'loose')].

    Catalog coverage is separately reported. Invalid indexes abort the output;
    missing catalogs must not be represented by callers as known absence.
    """
    cancel = cancel or threading.Event()
    store.binding_id(binding)
    if (not isinstance(archives, list) or not archives or len(archives) > 10000
            or any(not isinstance(a, str) or not metadata.HEX.fullmatch(a) for a in archives)
            or len(set(archives)) != len(archives)):
        raise core.RepairError("catalog_archive_configuration_invalid")
    if not 1 <= len(sources) <= 10002:
        raise core.RepairError("catalog_source_count")
    # Check all source coordinates/configuration before reading any of them.
    seen = set()
    for path, index_key, kind in sources:
        metadata.key(index_key)
        if kind not in ("group", "archive", "loose") or (kind, index_key) in seen:
            raise core.RepairError("catalog_source_kind_or_duplicate")
        if kind == "archive" and index_key not in archives:
            raise core.RepairError("catalog_archive_not_configured")
        seen.add((kind, index_key))
        store.owned(lab, path)
    required = sum(core.regular(p).stat().st_size for p, _, _ in sources)
    if any(not 28 <= core.regular(p).stat().st_size <= MAX_INDEX_BYTES for p, _, _ in sources):
        raise core.RepairError("catalog_source_size_limit")
    if required > 1024**3 or shutil.disk_usage(lab.root).free < required * 8 + 64 * 1024**2:
        raise core.RepairError("catalog_inventory_space_or_total_limit")
    with store.Writer(lab, "catalog", cancel) as out:
        db = out.db
        db.executescript("""
          CREATE TABLE routes(ekey BLOB NOT NULL,encoded_size INTEGER NOT NULL,
            route_kind TEXT NOT NULL,archive_key TEXT NOT NULL,archive_offset INTEGER,
            index_key TEXT NOT NULL);
          CREATE TABLE index_proofs(index_key TEXT NOT NULL,kind TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,record_count INTEGER NOT NULL,
            PRIMARY KEY(index_key,kind)) WITHOUT ROWID;
        """)
        total_rows = 0
        for source, index_key, kind in sources:
            source = store.owned(lab, source)
            before = core.fingerprint(source.stat())
            out.watch(source, before)
            notify("Verifying catalog: " + kind)
            with source.open("rb") as src, mmap.mmap(src.fileno(), 0, access=mmap.ACCESS_READ) as data:
                if core.fingerprint(os.fstat(src.fileno())) != before:
                    raise core.RepairError("catalog_source_changed")
                # Empty wanted set means no bounded match-list: validates EVERY
                # row/checksum/order/bound without the old 16K match-output cap.
                _, proof = cdn_catalog.matches(
                    data, index_key, {}, kind, archives if kind == "group" else None, cancel)
                footer = data[-28:]
                block_size = footer[11] * 1024
                entry_size = 20 + footer[12]
                per_block = block_size // entry_size
                count = proof["index_records"]
                pending = []
                for ordinal in range(count):
                    if ordinal % 4096 == 0:
                        core.check(cancel)
                    at = (ordinal // per_block) * block_size + (ordinal % per_block) * entry_size
                    ek = data[at:at + 16]
                    size = int.from_bytes(data[at + 16:at + 20], "big")
                    if kind == "loose":
                        archive, offset, route_kind = "", None, "advertised_direct"
                    elif kind == "group":
                        ai = int.from_bytes(data[at + 20:at + 22], "big")
                        archive = archives[ai]
                        offset, route_kind = int.from_bytes(data[at + 22:at + 26], "big"), "archive_range"
                    else:
                        archive, offset, route_kind = index_key, int.from_bytes(data[at + 20:at + 24], "big"), "archive_range"
                    pending.append((ek, size, route_kind, archive, offset, index_key))
                    if len(pending) == 4096:
                        db.executemany("INSERT INTO routes VALUES (?,?,?,?,?,?)", pending)
                        pending.clear()
                if pending:
                    db.executemany("INSERT INTO routes VALUES (?,?,?,?,?,?)", pending)
                db.execute("INSERT INTO index_proofs VALUES (?,?,?,?)",
                           (index_key, kind, hashlib.sha256(data).hexdigest(), count))
                total_rows += count
                if core.fingerprint(os.fstat(src.fileno())) != before:
                    raise core.RepairError("catalog_source_changed")
            if core.fingerprint(core.regular(source).stat()) != before:
                raise core.RepairError("catalog_source_changed")
        db.execute("CREATE INDEX route_lookup ON routes(ekey,encoded_size)")
        assert total_rows == db.execute("SELECT COUNT(*) FROM routes").fetchone()[0]
        result = {
            "index_files_fully_verified": len(sources), "verified_route_rows": total_rows,
            "archive_catalog_covered": any(k == "group" for _, _, k in sources) or
                {key for _, key, k in sources if k == "archive"} == set(archives),
            "loose_catalog_checked": any(k == "loose" for _, _, k in sources),
            "catalogs_prove_current_http_availability": False,
            "guessed_direct_routes": 0, "installation_ready": False}
        out.metadata("target_binding", binding)
        out.metadata("catalog_summary", result)
    return result, out.path