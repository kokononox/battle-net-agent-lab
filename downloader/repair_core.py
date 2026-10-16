"""Development repair engine. WRITES ONLY INSIDE A NEW, OWNED LAB WORKSPACE.

Not a WoW installation writer. No API accepts an existing game directory.
Input specs are supplied by a future trusted manifest coordinator, not authenticated
by this module. CKey/EKey proofs are integrity proofs, not publisher signatures.
"""
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import decoded_payload


class RepairError(Exception):
    pass


class Cancelled(RepairError):
    pass


def check(cancel):
    if cancel.is_set():
        raise Cancelled("cancelled")


def safe(path):
    """Reject symlinks, Windows reparse points and non-directory ancestors."""
    path = Path(os.path.abspath(str(path)))
    for p in reversed((path,) + tuple(path.parents)):
        try:
            s = p.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x400:
            raise RepairError("link_or_reparse_point")
        if p != path and not stat.S_ISDIR(s.st_mode):
            raise RepairError("non_directory_ancestor")
    return path


def regular(path):
    path = safe(path)
    s = path.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise RepairError("regular_unshared_file_required")
    return path


def relative(name):
    if not isinstance(name, str) or len(name) > 220:
        raise RepairError("invalid_relative_path")
    parts = name.split("/")
    if len(parts) < 2 or parts[0] != "_retail_":
        raise RepairError("standalone_retail_path_required")
    forbidden = {"wtf", "interface", "screenshots", "cache", "logs", "data",
                 ".build.info", ".build.db"}
    for p in parts:
        if (not p or p in (".", "..") or p[-1:] in (" ", ".")
                or re.search(r'[\\:<>"|?*\x00-\x1f]', p)
                or p.casefold() in forbidden
                or p.split(".")[0].upper() in
                {"CON", "PRN", "AUX", "NUL", "COM0", "LPT0",
                 *("COM" + str(i) for i in range(1, 10)),
                 *("LPT" + str(i) for i in range(1, 10))}):
            raise RepairError("protected_or_unsafe_path")
    return name


def fingerprint(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink)


def digest(path, cancel=None):
    """Hash a regular, non-hard-linked file with before/open/after identity checks."""
    cancel = cancel or threading.Event()
    path = regular(path)
    before = fingerprint(path.stat())
    md5, sha = hashlib.md5(), hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        if fingerprint(os.fstat(f.fileno())) != before:
            raise RepairError("source_changed")
        while True:
            check(cancel)
            b = f.read(65536)
            if not b:
                break
            md5.update(b)
            sha.update(b)
            size += len(b)
        if fingerprint(os.fstat(f.fileno())) != before:
            raise RepairError("source_changed")
    if fingerprint(regular(path).stat()) != before:
        raise RepairError("source_changed")
    return {"size": size, "md5": md5.hexdigest(), "sha256": sha.hexdigest()}


def state(path):
    safe(path)
    if not path.exists():
        return None
    d = digest(path)
    return {"size": d["size"], "sha256": d["sha256"]}


def sync_dir(path):
    # Windows directory fsync is not provided here. No power-loss claim is made.
    if os.name != "nt":
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_json(path, obj):
    safe(path)
    tmp = safe(path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp"))
    with tmp.open("x", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    sync_dir(path.parent)


def load_json(path):
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise RepairError("duplicate_json_key")
            d[k] = v
        return d
    with regular(path).open("rb") as f:
        b = f.read(8 * 1024 * 1024 + 1)
    if len(b) > 8 * 1024 * 1024:
        raise RepairError("journal_size_limit")
    try:
        d = json.loads(b, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(
                           RepairError("nonfinite_json")))
    except (ValueError, UnicodeError):
        raise RepairError("invalid_json") from None
    if not isinstance(d, dict):
        raise RepairError("json_object_required")
    return d


class Lab:
    """Creation is exclusive: pre-existing directories, including games, rejected."""
    @classmethod
    def create(cls, path):
        path = safe(path)
        if not path.parent.is_dir() or path.exists():
            raise RepairError("new_workspace_required")
        path.mkdir()
        for name in ("target", "objects", "transactions"):
            (path / name).mkdir()
        atomic_json(path / "LAB-ONLY.json", {
            "format": "wow-repair-lab-1", "id": uuid.uuid4().hex,
            "real_game_installation": False})
        return cls(path)

    def __init__(self, path):
        self.root = safe(path)
        marker = load_json(self.root / "LAB-ONLY.json")
        if (marker.get("format") != "wow-repair-lab-1"
                or not re.fullmatch("[0-9a-f]{32}", str(marker.get("id", "")))
                or marker.get("real_game_installation") is not False):
            raise RepairError("invalid_lab_marker")
        self.id = marker["id"]
        for name in ("target", "objects", "transactions"):
            if not safe(self.root / name).is_dir():
                raise RepairError("workspace_layout_invalid")

    def target(self, name):
        return safe(self.root / "target" / relative(name))

    @contextlib.contextmanager
    def lock(self):
        path = safe(self.root / "engine.lock")
        if path.exists():
            regular(path)
        with path.open("a+b") as f:
            if path.stat().st_size == 0:
                f.write(b"\0")
                f.flush()
            f.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise RepairError("workspace_busy") from None
            try:
                yield
            finally:
                if os.name == "nt":
                    import msvcrt
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True)
class Spec:
    path: str
    ckey: str
    decoded_size: int
    ekey: str
    encoded_size: int
    # URL must be bound to official metadata by the future integration layer.
    url: str
    archive_offset: object = None

    def validate(self):
        relative(self.path)
        for h in (self.ckey, self.ekey):
            if not isinstance(h, str) or not re.fullmatch("[0-9a-f]{32}", h):
                raise RepairError("invalid_content_key")
        if (type(self.decoded_size) is not int or
                not 0 <= self.decoded_size <= decoded_payload.MAX_DECODED or
                type(self.encoded_size) is not int or
                not 0 < self.encoded_size <= decoded_payload.MAX_ENCODED):
            raise RepairError("object_size_limit")
        try:
            p = urlsplit(self.url)
            port = p.port
        except (ValueError, TypeError):
            raise RepairError("invalid_https_route") from None
        if (p.scheme != "https" or not p.hostname or p.username or p.password
                or port not in (None, 443) or p.query or p.fragment):
            raise RepairError("invalid_https_route")
        if self.archive_offset is not None and (
                type(self.archive_offset) is not int or
                not 0 <= self.archive_offset < 2**63 - self.encoded_size):
            raise RepairError("invalid_archive_offset")
        key = p.path.rsplit("/", 1)[-1]
        if (not re.fullmatch("[0-9a-f]{32}", key) or
                p.path != "/tpr/wow/data/" + key[:2] + "/" + key[2:4] + "/" + key):
            raise RepairError("invalid_data_route")
        if self.archive_offset is None and key != self.ekey:
            raise RepairError("direct_route_key_mismatch")
        return self


def specs_guard(specs):
    specs = list(specs)
    if not 1 <= len(specs) <= 256:
        raise RepairError("file_count_limit")
    seen = set()
    for spec in specs:
        spec.validate()
        key = spec.path.casefold()
        if key in seen:
            raise RepairError("duplicate_target")
        if any(key.startswith(x + "/") or x.startswith(key + "/") for x in seen):
            raise RepairError("file_directory_target_conflict")
        seen.add(key)
    if sum(s.decoded_size + s.encoded_size for s in specs) > 4 * 1024**3:
        raise RepairError("batch_size_limit")
    return specs


def scan(lab, specs, cancel=None):
    cancel = cancel or threading.Event()
    rows = []
    for spec in specs_guard(specs):
        check(cancel)
        path = lab.target(spec.path)
        old = digest(path, cancel) if path.exists() else None
        kind = "missing" if old is None else (
            "healthy" if old["size"] == spec.decoded_size and
            old["md5"] == spec.ckey else "damaged")
        rows.append({"path": spec.path, "status": kind,
                     "observed": None if old is None else {
                         "size": old["size"], "sha256": old["sha256"]}})
    return rows


class HTTPS:
    """HTTPS only, no redirects or environment proxy. Caller binds source metadata."""
    def __init__(self):
        import ssl
        import urllib.request
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise RepairError("redirect_rejected")
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def open(self, url, headers):
        import urllib.request
        req = urllib.request.Request(url, headers={
            "Accept-Encoding": "identity", "User-Agent": "WoW-Repair-Lab/1",
            **headers})
        return self.opener.open(req, timeout=30)


def validate_response(r, spec, resumed):
    offset = spec.archive_offset or 0
    ranged = spec.archive_offset is not None or resumed > 0
    remaining = spec.encoded_size - resumed
    if r.status != (206 if ranged else 200) or r.geturl() != spec.url:
        raise RepairError("response_status_or_url")
    h = r.headers
    if h.get("Content-Encoding", "identity").lower() not in ("", "identity"):
        raise RepairError("content_encoding_rejected")
    if h.get("Transfer-Encoding") or h.get("Content-Length") != str(remaining):
        raise RepairError("response_length_mismatch")
    cr = h.get("Content-Range")
    if ranged:
        m = re.fullmatch(r"bytes ([0-9]+)-([0-9]+)/([0-9]+)", cr or "")
        if (not m or int(m[1]) != offset + resumed
                or int(m[2]) != offset + spec.encoded_size - 1
                or int(m[3]) < offset + spec.encoded_size
                or (spec.archive_offset is None and int(m[3]) != spec.encoded_size)):
            raise RepairError("response_range_mismatch")
    elif cr is not None:
        raise RepairError("unexpected_response_range")


def quarantine(path):
    safe(path)
    if path.exists():
        regular(path)
        os.rename(path, path.with_name(path.name + ".rejected-" + uuid.uuid4().hex))


def fetch_decoded(lab, spec, transport, cancel=None):
    """Resume retained encoded prefix; publish only after full EKey/CKey proof."""
    cancel = cancel or threading.Event()
    spec.validate()
    objects = safe(lab.root / "objects")
    decoded = safe(objects / (spec.ckey + "-" + str(spec.decoded_size) + ".decoded"))
    if decoded.exists():
        d = digest(decoded, cancel)
        if d["md5"] == spec.ckey and d["size"] == spec.decoded_size:
            return decoded
        quarantine(decoded)
    # Bind a partial to all routing and content expectations, not merely filename.
    binding = hashlib.sha256(json.dumps(spec.__dict__, sort_keys=True).encode()).hexdigest()
    part = safe(objects / (binding + ".part"))
    if part.exists():
        regular(part)
    resumed = part.stat().st_size if part.exists() else 0
    if resumed > spec.encoded_size:
        quarantine(part)
        raise RepairError("partial_oversized")
    needed = spec.encoded_size - resumed + spec.decoded_size + 64 * 1024**2
    if shutil.disk_usage(objects).free < needed:
        raise RepairError("insufficient_space")
    check(cancel)
    if resumed < spec.encoded_size:
        start = (spec.archive_offset or 0) + resumed
        end = (spec.archive_offset or 0) + spec.encoded_size - 1
        headers = ({"Range": "bytes=" + str(start) + "-" + str(end)}
                   if resumed or spec.archive_offset is not None else {})
        with transport.open(spec.url, headers) as r:
            validate_response(r, spec, resumed)
            with part.open("ab" if resumed else "xb") as f:
                try:
                    total = resumed
                    while total < spec.encoded_size:
                        check(cancel)
                        b = r.read(min(65536, spec.encoded_size - total))
                        if not b:
                            raise RepairError("download_interrupted_prefix_retained")
                        if len(b) > spec.encoded_size - total:
                            raise RepairError("response_body_oversized")
                        f.write(b)
                        total += len(b)
                    if r.read(1):
                        raise RepairError("response_body_extra")
                finally:
                    f.flush()
                    os.fsync(f.fileno())
    check(cancel)
    temp = safe(objects / ("decode-" + uuid.uuid4().hex + ".tmp"))
    try:
        before = fingerprint(regular(part).stat())
        with part.open("rb") as src, temp.open("xb") as sink:
            proof = decoded_payload.extract(
                src, spec.encoded_size, spec.decoded_size,
                bytes.fromhex(spec.ckey), bytes.fromhex(spec.ekey), cancel, sink)
            sink.flush()
            os.fsync(sink.fileno())
            if fingerprint(os.fstat(src.fileno())) != before:
                raise RepairError("encoded_source_changed")
        if fingerprint(regular(part).stat()) != before:
            raise RepairError("encoded_source_changed")
        if not proof["encoded_integrity_verified"] or not proof["decoded_ckey_verified"]:
            raise RepairError("content_proof_missing")
        d = digest(temp, cancel)
        if d["size"] != spec.decoded_size or d["md5"] != spec.ckey:
            raise RepairError("decoded_readback_failed")
        check(cancel)
        os.replace(temp, decoded)
        sync_dir(objects)
        return decoded
    except decoded_payload.PayloadError as e:
        if e.reason != "cancelled":
            quarantine(part)
        raise RepairError("payload_" + e.reason) from None
    finally:
        if temp.exists():
            regular(temp).unlink()


def copy_verified(source, target, expected):
    regular(source)
    safe(target)
    with source.open("rb") as src, target.open("xb") as out:
        shutil.copyfileobj(src, out, 65536)
        out.flush()
        os.fsync(out.fileno())
    if state(target) != expected or state(source) != expected:
        raise RepairError("copy_readback_or_source_changed")


def install_file(source, target, expected):
    """Atomic per-file replacement, NOT atomic all-file activation."""
    safe(target)
    safe(target.parent).mkdir(parents=True, exist_ok=True)
    tmp = safe(target.with_name(".repair-" + uuid.uuid4().hex + ".tmp"))
    try:
        copy_verified(source, tmp, expected)
        if target.exists():
            regular(target)
        os.replace(tmp, target)
        sync_dir(target.parent)
        if state(target) != expected:
            raise RepairError("replacement_readback_failed")
    finally:
        if tmp.exists():
            regular(tmp).unlink()


def journal_guard(lab, tx):
    if not re.fullmatch("tx-[0-9a-f]{32}", tx.name):
        raise RepairError("invalid_transaction_name")
    j = load_json(safe(tx / "journal.json"))
    if (j.get("format") != "repair-lab-tx-1" or j.get("workspace") != lab.id
            or j.get("id") != tx.name or j.get("status") not in
            ("prepared", "applying", "committed", "rolling_back", "rolled_back", "conflict")
            or not isinstance(j.get("rows"), list) or not 1 <= len(j["rows"]) <= 256):
        raise RepairError("invalid_transaction_journal")
    seen = set()
    for row in j["rows"]:
        name = relative(row.get("path"))
        if name.casefold() in seen:
            raise RepairError("duplicate_journal_target")
        if any(name.casefold().startswith(x + "/") or
               x.startswith(name.casefold() + "/") for x in seen):
            raise RepairError("journal_file_directory_conflict")
        seen.add(name.casefold())
        for k in ("old", "new"):
            v = row.get(k)
            if k == "old" and v is None:
                continue
            if (not isinstance(v, dict) or type(v.get("size")) is not int
                    or not 0 <= v["size"] <= decoded_payload.MAX_DECODED
                    or not re.fullmatch("[0-9a-f]{64}", str(v.get("sha256", "")))
                    or set(v) != {"size", "sha256"}):
                raise RepairError("invalid_journal_file_state")
    return j


def rollback(lab, tx, j):
    if j["status"] == "committed":
        raise RepairError("committed_transaction_not_rollback_candidate")
    j["status"] = "rolling_back"
    atomic_json(tx / "journal.json", j)
    # Preflight EVERY row and backup before changing any target.
    for i, row in enumerate(j["rows"]):
        current = state(lab.target(row["path"]))
        if current != row["old"] and current != row["new"]:
            j["status"] = "conflict"
            atomic_json(tx / "journal.json", j)
            raise RepairError("recovery_conflict_preserved")
        if row["old"] is not None and state(tx / (str(i) + ".backup")) != row["old"]:
            j["status"] = "conflict"
            atomic_json(tx / "journal.json", j)
            raise RepairError("backup_invalid_recovery_blocked")
    for i in reversed(range(len(j["rows"]))):
        row = j["rows"][i]
        target = lab.target(row["path"])
        current = state(target)
        if current == row["old"]:
            continue
        if current != row["new"]:
            raise RepairError("recovery_conflict_preserved")
        if row["old"] is None:
            regular(target).unlink()
            sync_dir(target.parent)
        else:
            install_file(tx / (str(i) + ".backup"), target, row["old"])
    j["status"] = "rolled_back"
    atomic_json(tx / "journal.json", j)
    return {"transaction": tx.name, "status": "rolled_back"}


def _recover(lab):
    results = []
    for tx in sorted(safe(lab.root / "transactions").iterdir()):
        safe(tx)
        if not tx.is_dir() or not re.fullmatch("tx-[0-9a-f]{32}", tx.name):
            raise RepairError("unexpected_transaction_entry")
        if not (tx / "journal.json").exists():
            # Preparation never touches targets before publishing its journal.
            results.append({"transaction": tx.name, "status": "preparation_incomplete_retained"})
            continue
        j = journal_guard(lab, tx)
        if j["status"] in ("committed", "rolled_back"):
            # Historical successful transactions must not be replayed over later work.
            results.append({"transaction": tx.name, "status": j["status"]})
        else:
            results.append(rollback(lab, tx, j))
    return results


def recover(lab):
    with lab.lock():
        return _recover(lab)


def apply(lab, specs, decoded_paths, baselines, cancel, failpoint=lambda _: None):
    """Internal: caller holds workspace lock; full backup before first replacement."""
    tx = safe(lab.root / "transactions" / ("tx-" + uuid.uuid4().hex))
    tx.mkdir()
    rows = []
    needed = 64 * 1024**2
    largest_replacement_or_restore = 0
    for spec in specs:
        old = state(lab.target(spec.path))
        needed += spec.decoded_size + (old["size"] if old else 0)
        largest_replacement_or_restore = max(
            largest_replacement_or_restore, spec.decoded_size,
            old["size"] if old else 0)
    needed += largest_replacement_or_restore
    if shutil.disk_usage(tx).free < needed:
        raise RepairError("insufficient_transaction_space")
    for i, spec in enumerate(specs):
        check(cancel)
        target = lab.target(spec.path)
        old = state(target)
        if old != baselines[spec.path]:
            raise RepairError("target_changed_since_scan")
        source = decoded_paths[spec.path]
        # Do not permit arbitrary external source paths in the application phase.
        if source.parent != lab.root / "objects":
            raise RepairError("owned_decoded_cache_required")
        d = digest(source, cancel)
        if d["size"] != spec.decoded_size or d["md5"] != spec.ckey:
            raise RepairError("replacement_content_invalid")
        new = {"size": d["size"], "sha256": d["sha256"]}
        copy_verified(source, tx / (str(i) + ".stage"), new)
        if old is not None:
            copy_verified(target, tx / (str(i) + ".backup"), old)
        rows.append({"path": spec.path, "old": old, "new": new, "applied": False})
    j = {"format": "repair-lab-tx-1", "workspace": lab.id, "id": tx.name,
         "status": "prepared", "rows": rows}
    atomic_json(tx / "journal.json", j)
    try:
        failpoint("prepared")
        check(cancel)
        j["status"] = "applying"
        atomic_json(tx / "journal.json", j)
        for i, row in enumerate(rows):
            check(cancel)
            target = lab.target(row["path"])
            if state(target) != row["old"]:
                raise RepairError("target_changed_before_replacement")
            if row["old"] is not None and state(tx / (str(i) + ".backup")) != row["old"]:
                raise RepairError("backup_invalid_before_replacement")
            install_file(tx / (str(i) + ".stage"), target, row["new"])
            failpoint("replaced:" + str(i))
            row["applied"] = True
            atomic_json(tx / "journal.json", j)
            failpoint("recorded:" + str(i))
        check(cancel)
        # Reverify the whole applied set before publishing logical commit.
        if any(state(lab.target(r["path"])) != r["new"] for r in rows):
            raise RepairError("final_readback_failed")
        j["status"] = "committed"
        atomic_json(tx / "journal.json", j)
    except Exception:
        # Never restore over unrelated concurrent edits; retain journal/backups.
        durable = journal_guard(lab, tx)
        if durable["status"] != "committed":
            rollback(lab, tx, durable)
        raise
    failpoint("committed")
    return {"transaction": tx.name, "status": "committed", "files_repaired": len(rows)}


def repair(lab, specs, transport=None, cancel=None, failpoint=lambda _: None):
    cancel = cancel or threading.Event()
    specs = specs_guard(specs)
    with lab.lock():
        _recover(lab)
        before = scan(lab, specs, cancel)
        work = [s for s, row in zip(specs, before) if row["status"] != "healthy"]
        if not work:
            return {"status": "already_healthy", "files_repaired": 0, "scan": before}
        transport = transport or HTTPS()
        decoded = {}
        for spec in work:
            decoded[spec.path] = fetch_decoded(lab, spec, transport, cancel)
        baselines = {r["path"]: r["observed"] for r in before}
        result = apply(lab, work, decoded, baselines, cancel, failpoint)
        result["scan"] = before
        result["scope"] = "owned_lab_standalone_files_only_not_a_WoW_update"
        return result