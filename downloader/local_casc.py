"""Read-only local CASC candidate discovery and resumable full-content evidence.

Only revision-7 continuous indexes (4/5/9 byte fields, 30 segment bits).
All observed generations, never guessed active generation. A 9-byte prefix is
ONLY a candidate selector. Complete target EKey/chunk+CKey proof is mandatory.
Outputs/checkpoints are immutable owned lab DBs, never game paths.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import threading
import uuid
from collections import Counter
import cache_evidence as cache
import lookup3
import plan_storage as store
import repair_core as core

IDX = re.compile(r'^([0-9a-fA-F]{2})([0-9a-fA-F]{8})\.idx$')
ARCH = re.compile(r'^data\.(\d{3,})$')
MAX_INDEX = 64 * 1024**2
MAX_INDEX_TOTAL = 512 * 1024**2
MAX_ENTRIES = 20_000_000
MAX_CANDIDATES = 10_000_000
MAX_NAMES = 20_000


def _names(folder):
    names = []
    with os.scandir(folder) as items:
        for item in items:
            names.append(item.name)
            if len(names) > MAX_NAMES:
                raise core.RepairError('local_storage_directory_limit')
    return sorted(names)


def _directory(path):
    path = core.safe(path)
    if not stat.S_ISDIR(path.stat().st_mode):
        raise core.RepairError('local_storage_directory_required')
    return path


def _snapshot(folder):
    folder = _directory(folder)
    names = _names(folder)
    observed = {}
    for name in names:
        if ARCH.fullmatch(name) or name.lower().endswith('.idx') or name == 'shmem':
            p = core.regular(folder / name)
            observed[name] = list(core.fingerprint(p.stat()))
    return {'directory': str(folder), 'names': names, 'files': observed,
            'directory_identity': list(core.fingerprint(folder.stat()))}


def _stable(snapshot):
    folder = _directory(snapshot['directory'])
    if (list(core.fingerprint(folder.stat())) != snapshot['directory_identity']
            or _names(folder) != snapshot['names']):
        raise core.RepairError('local_storage_snapshot_changed_rescan_required')
    for name, fp in snapshot['files'].items():
        if list(core.fingerprint(core.regular(folder / name).stat())) != fp:
            raise core.RepairError('local_storage_snapshot_changed_rescan_required')


class StableWriter(store.Writer):
    def __init__(self, lab, label, cancel, snapshot):
        super().__init__(lab, label, cancel)
        self.snapshot = snapshot

    def _check_sources(self):
        super()._check_sources()
        _stable(self.snapshot)


def _meta(db, name):
    row = db.execute('SELECT value FROM metadata WHERE name=?', (name,)).fetchone()
    if row is None:
        raise core.RepairError('local_evidence_metadata_missing')
    return json.loads(row[0])


def _read_index(path, expected, cancel):
    if expected[2] > MAX_INDEX:
        raise core.RepairError('local_index_byte_limit')
    with path.open('rb') as f:
        if list(core.fingerprint(os.fstat(f.fileno()))) != expected:
            raise core.RepairError('local_storage_snapshot_changed_rescan_required')
        raw = f.read(MAX_INDEX + 1)
        if list(core.fingerprint(os.fstat(f.fileno()))) != expected:
            raise core.RepairError('local_storage_snapshot_changed_rescan_required')
    core.check(cancel)
    if len(raw) != expected[2]:
        raise core.RepairError('local_index_short_or_changed')
    return raw


def index_proof(raw, filename, cancel):
    """Return checksum/layout evidence; unknown is never a corruption verdict."""
    m = IDX.fullmatch(filename)
    result = {'state': 'unsupported_layout', 'entries': 0, 'checksum_verified': False}
    if (not m or int(m[1], 16) >= 16 or len(raw) < 40
            or int.from_bytes(raw[:4], 'little') != 16
            or raw[8:16] != b'\x07\x00' + bytes([int(m[1], 16), 0, 4, 5, 9, 30])):
        return result
    if lookup3.hashlittle(raw[8:24]) != int.from_bytes(raw[4:8], 'little'):
        result['state'] = 'header_checksum_not_verified'
        return result
    size = int.from_bytes(raw[32:36], 'little')
    if not size or size % 18 or 40 + size > len(raw):
        return result
    count = size // 18
    if count > MAX_ENTRIES:
        raise core.RepairError('local_index_entry_limit')
    hi = lo = 0
    for i in range(count):
        if i % 4096 == 0:
            core.check(cancel)
        hi, lo = lookup3.hashlittle2(raw[40 + i*18:58 + i*18], hi, lo)
    variant = 'native_rolling_hashlittle2'
    stored = int.from_bytes(raw[36:40], 'little')
    if hi != stored:
        alt = 0
        for i in range(count):
            if i % 4096 == 0:
                core.check(cancel)
            alt = lookup3.hashlittle(raw[40 + i*18:58 + i*18], alt)
        if alt != stored:
            result['state'] = 'entry_checksum_not_verified'
            return result
        variant = 'blizzget_rolling_hashlittle'
    result.update(state='continuous_block_checksums_verified', entries=count,
                  checksum_verified=True, checksum_variant=variant,
                  trailing_bytes_not_interpreted=len(raw)-40-size)
    return result


def inventory(lab, plan_path, storage_directory, cancel=None, notify=lambda _: None):
    """Capture direct Data/data file set and verify every supported observed index.

    Never read archive payloads here. Bounds/size-compatible references become
    normalized candidates, not evidence of possession. No shmem parsing.
    """
    cancel = cancel or threading.Event()
    core.check(cancel)
    folder = _directory(storage_directory)
    if folder == lab.root or folder in lab.root.parents or lab.root in folder.parents:
        raise core.RepairError('local_storage_must_be_separate_from_lab')
    with lab.lock():
        snapshot = _snapshot(folder)
        indexes = [n for n in snapshot['files'] if n.lower().endswith('.idx')]
        if len(indexes) > 1024 or sum(snapshot['files'][n][2] for n in indexes) > MAX_INDEX_TOTAL:
            raise core.RepairError('local_index_aggregate_limit')
        if shutil.disk_usage(lab.root).free < sum(snapshot['files'][n][2] for n in indexes)*16 + 64*1024**2:
            raise core.RepairError('local_inventory_insufficient_lab_space')
        archives = {}
        for name in snapshot['files']:
            m = ARCH.fullmatch(name)
            if m:
                aid = int(m[1])
                if aid >= 1024:
                    raise core.RepairError('local_archive_id_outside_supported_range')
                archives.setdefault(aid, []).append(name)
        plan_path = store.owned(lab, plan_path)
        plan_fp = core.fingerprint(plan_path.stat())
        with store.input_db(lab, plan_path) as (plan, binding), \
                StableWriter(lab, 'local-casc-inventory', cancel, snapshot) as out:
            out.watch(plan_path, plan_fp)
            db = out.db
            db.execute('ATTACH DATABASE ? AS p', (plan_path.as_uri()+'?mode=ro',))
            db.executescript('''CREATE TABLE indexes(name TEXT PRIMARY KEY,state TEXT NOT NULL,
                checksum_verified INTEGER NOT NULL,entries INTEGER NOT NULL,sha256 TEXT NOT NULL);
                CREATE TABLE archives(archive_id INTEGER PRIMARY KEY,name TEXT,size INTEGER,
                ambiguous INTEGER NOT NULL);
                CREATE TABLE refs(prefix BLOB NOT NULL,archive_id INTEGER NOT NULL,
                raw_offset INTEGER NOT NULL,span INTEGER NOT NULL);
                CREATE TABLE candidates(id INTEGER PRIMARY KEY,ekey BLOB NOT NULL,
                archive_id INTEGER NOT NULL,payload_offset INTEGER NOT NULL,
                encoded_size INTEGER NOT NULL,ckey BLOB NOT NULL,decoded_size INTEGER NOT NULL,
                matching_reference_rows INTEGER NOT NULL,
                UNIQUE(ekey,archive_id,payload_offset));''')
            for aid, names in archives.items():
                name = names[0] if len(names) == 1 else None
                db.execute('INSERT INTO archives VALUES (?,?,?,?)',
                    (aid, name, snapshot['files'][name][2] if name else None, name is None))
            total = verified = 0
            buckets = Counter()
            for number, name in enumerate(indexes):
                core.check(cancel)
                notify('Checking local index %d / %d; no game writes.' % (number+1, len(indexes)))
                raw = _read_index(core.regular(folder/name), snapshot['files'][name], cancel)
                if len(raw) >= 40:
                    declared = int.from_bytes(raw[32:36], 'little') // 18
                    if declared > MAX_ENTRIES - total:
                        raise core.RepairError('local_index_aggregate_entry_limit')
                proof = index_proof(raw, name, cancel)
                db.execute('INSERT INTO indexes VALUES (?,?,?,?,?)',
                    (name, proof['state'], proof['checksum_verified'], proof['entries'], hashlib.sha256(raw).hexdigest()))
                if not proof['checksum_verified']:
                    continue
                verified += 1
                total += proof['entries']
                buckets[int(IDX.fullmatch(name)[1], 16)] += 1
                rows = []
                for i in range(proof['entries']):
                    if i % 4096 == 0:
                        core.check(cancel)
                    e = raw[40+i*18:58+i*18]
                    packed = int.from_bytes(e[9:14], 'big')
                    rows.append((e[:9], packed >> 30, packed & ((1 << 30)-1), int.from_bytes(e[14:], 'little')))
                    if len(rows) == 4096:
                        db.executemany('INSERT INTO refs VALUES (?,?,?,?)', rows)
                        rows.clear()
                if rows:
                    db.executemany('INSERT INTO refs VALUES (?,?,?,?)', rows)
            db.execute('''CREATE TEMP TABLE targets AS SELECT substr(ekey,1,9) AS prefix,
                ekey,encoded_size,ckey,decoded_size FROM p.plan
                WHERE mapping_state='mapped' AND transfer_supported=1''')
            db.execute('CREATE INDEX target_prefix ON targets(prefix)')
            core.check(cancel)
            notify('Joining local references to full target keys; prefixes are not proof.')
            db.execute('''INSERT INTO candidates(ekey,archive_id,payload_offset,encoded_size,
                ckey,decoded_size,matching_reference_rows)
                SELECT t.ekey,r.archive_id,
                    r.raw_offset+CASE WHEN r.span=t.encoded_size+30 THEN 30 ELSE 0 END AS normalized,
                    t.encoded_size,t.ckey,t.decoded_size,COUNT(*)
                FROM refs r JOIN targets t ON t.prefix=r.prefix
                JOIN archives a ON a.archive_id=r.archive_id
                WHERE a.ambiguous=0 AND t.encoded_size>0
                  AND r.span IN (t.encoded_size,t.encoded_size+30)
                  AND r.raw_offset+r.span<=a.size
                GROUP BY t.ekey,r.archive_id,normalized
                ORDER BY t.ekey,r.archive_id,normalized LIMIT ?''', (MAX_CANDIDATES+1,))
            count = db.execute('SELECT COUNT(*) FROM candidates').fetchone()[0]
            if count > MAX_CANDIDATES:
                raise core.RepairError('local_candidate_limit')
            db.execute('CREATE INDEX candidate_target ON candidates(ekey)')
            target_count = db.execute('SELECT COUNT(DISTINCT ekey) FROM candidates').fetchone()[0]
            raw_matches = db.execute('SELECT COALESCE(SUM(matching_reference_rows),0) FROM candidates').fetchone()[0]
            invalid = db.execute('''SELECT COUNT(*) FROM refs r LEFT JOIN archives a
                ON a.archive_id=r.archive_id WHERE a.archive_id IS NULL OR a.ambiguous=1
                OR r.raw_offset+r.span>a.size''').fetchone()[0]
            result = {'observed_index_files': len(indexes), 'index_files_checksums_verified': verified,
                'all_observed_index_blocks_verified': bool(indexes) and verified == len(indexes),
                'supported_continuous_entries': total, 'observed_verified_buckets': len(buckets),
                'buckets_with_multiple_observed_generations': sum(v > 1 for v in buckets.values()),
                'ambiguous_archive_ids': sum(len(n)>1 for n in archives.values()),
                'references_without_unambiguous_in_bounds_archive': invalid,
                'normalized_candidates': count, 'target_objects_with_candidates': target_count,
                'size_compatible_reference_rows': raw_matches,
                'reference_aliases_collapsed': raw_matches-count,
                'archive_payload_bytes_read': 0, 'active_generation_resolved': False,
                'game_files_modified': False,
                'source_consistency_model': 'file_set_and_stat_fingerprints;not_an_OS_snapshot',
                'required_network_download_bytes': None,
                'installation_ready': False}
            out.metadata('target_binding', binding)
            out.metadata('source_plan_id', _meta(plan, 'plan_id'))
            out.metadata('source_snapshot_id', uuid.uuid4().hex)
            out.metadata('local_storage_snapshot', snapshot)
            out.metadata('inventory_summary', result)
        return result, out.path


def verify_batch(lab, plan_path, inventory_path, previous=None, cancel=None,
                 byte_budget=2*1024**3, max_candidates=4096, notify=lambda _: None):
    """Immutable checkpoint. Completed earlier batches survive cancellation/death.

    On budget pause the first unprocessed candidate remains pending (not missing).
    Interrupted current batch is discarded. Resume requires unchanged storage
    fingerprints, file set, exact plan ID and snapshot ID. No unsafe resume.
    """
    if (type(byte_budget) is not int or byte_budget < 0 or
            type(max_candidates) is not int or not 1 <= max_candidates <= 4096):
        raise core.RepairError('local_verification_batch_limit')
    cancel = cancel or threading.Event()
    core.check(cancel)
    plan_path = store.owned(lab, plan_path)
    inventory_path = store.owned(lab, inventory_path)
    plan_fp = core.fingerprint(plan_path.stat())
    inventory_fp = core.fingerprint(inventory_path.stat())
    with lab.lock(), store.input_db(lab, plan_path) as (plan, binding), \
            store.input_db(lab, inventory_path, binding) as (inv, _):
        snapshot = _meta(inv, 'local_storage_snapshot')
        _stable(snapshot)
        plan_id = _meta(plan, 'plan_id')
        if _meta(inv, 'source_plan_id') != plan_id:
            raise core.RepairError('local_inventory_belongs_to_different_plan')
        snapshot_id = _meta(inv, 'source_snapshot_id')
        if previous is not None:
            previous = store.owned(lab, previous)
        checkpoint_bytes = previous.stat().st_size if previous is not None else 0
        if shutil.disk_usage(lab.root).free < 2*checkpoint_bytes + max_candidates*1024 + 64*1024**2:
            raise core.RepairError('local_checkpoint_insufficient_lab_space')
        with StableWriter(lab, 'local-casc-evidence', cancel, snapshot) as out:
            out.watch(plan_path, plan_fp)
            out.watch(inventory_path, inventory_fp)
            db = out.db
            db.executescript('''CREATE TABLE evidence(ordinal INTEGER PRIMARY KEY,ekey BLOB NOT NULL,
                kind TEXT NOT NULL,state TEXT NOT NULL,bytes_read INTEGER NOT NULL,
                decoded_content_verified INTEGER NOT NULL,encoded_object_verified INTEGER NOT NULL,
                source_path TEXT NOT NULL);
                CREATE INDEX evidence_target ON evidence(ekey,encoded_object_verified);''')
            cursor = 0
            if previous is not None:
                previous = store.owned(lab, previous)
                out.watch(previous)
                with store.input_db(lab, previous, binding) as (prev, _):
                    if (_meta(prev, 'source_plan_id') != plan_id or
                            _meta(prev, 'source_snapshot_id') != snapshot_id):
                        raise core.RepairError('local_checkpoint_binding_conflict')
                    cursor = _meta(prev, 'last_candidate_id')
                    db.execute('ATTACH DATABASE ? AS prev', (previous.as_uri()+'?mode=ro',))
                    db.execute('INSERT INTO evidence SELECT * FROM prev.evidence')
            count = inv.execute('SELECT COUNT(*) FROM candidates').fetchone()[0]
            spent = processed = 0
            reason = None
            # LIMIT gives a bounded cursor; checkpoints retain all prior proofs.
            rows = inv.execute('''SELECT c.id,c.ekey,c.archive_id,c.payload_offset,c.encoded_size,
                c.ckey,c.decoded_size,a.name FROM candidates c JOIN archives a
                ON c.archive_id=a.archive_id WHERE c.id>? ORDER BY c.id LIMIT ?''',
                (cursor, max_candidates))
            for cid, ek, aid, offset, es, ck, ds, name in rows:
                core.check(cancel)
                path = core.regular(Path(snapshot['directory'])/name)
                if list(core.fingerprint(path.stat())) != snapshot['files'][name]:
                    raise core.RepairError('local_storage_snapshot_changed_rescan_required')
                reusable = db.execute('SELECT 1 FROM evidence WHERE ekey=? AND encoded_object_verified=1 LIMIT 1', (ek,)).fetchone()
                if reusable:
                    state, n, content_ok, encoded_ok = 'already_verified_same_target', 0, False, False
                elif spent + es > byte_budget:
                    reason = 'byte_budget_next_candidate_pending'
                    break
                else:
                    notify('Verifying local candidate %d / %d; read-only.' % (cid, count))
                    state, n, content_ok, encoded_ok, fp = cache._verify(
                        path, 'casc_span', offset, es, ek, es, ck, ds, cancel)
                    if list(fp) != snapshot['files'][name]:
                        raise core.RepairError('local_storage_snapshot_changed_rescan_required')
                spent += n
                processed += 1
                cursor = cid
                db.execute('INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)',
                    (cid, ek, 'casc_span', state, n, content_ok, encoded_ok, str(path)))
            if cursor < count and reason is None:
                reason = 'candidate_batch_limit'
            successes = db.execute('SELECT COUNT(DISTINCT ekey) FROM evidence WHERE encoded_object_verified=1').fetchone()[0]
            attempted = db.execute('SELECT COUNT(DISTINCT ekey) FROM evidence').fetchone()[0]
            states = dict(db.execute('SELECT state,COUNT(*) FROM evidence GROUP BY state'))
            result = {'candidate_total': count, 'candidate_rows_completed': cursor,
                'candidate_rows_pending': count-cursor, 'batch_candidate_rows_completed': processed,
                'batch_archive_bytes_read': spent, 'byte_budget': byte_budget,
                'stop_reason': reason, 'all_discovered_candidates_processed': cursor == count,
                'target_objects_with_attempted_candidates': attempted,
                'target_objects_fully_verified_locally': successes, 'evidence_state_counts': states,
                'no_candidate_is_not_proof_of_absence': True,
                'full_game_install_closure_proven': False, 'active_generation_resolved': False,
                'game_files_modified': False,
                'source_consistency_model': 'file_set_and_stat_fingerprints;not_an_OS_snapshot',
                'required_network_download_bytes': None,
                'installation_ready': False}
            out.metadata('target_binding', binding)
            out.metadata('source_plan_id', plan_id)
            out.metadata('source_snapshot_id', snapshot_id)
            out.metadata('last_candidate_id', cursor)
            out.metadata('local_verification_summary', result)
        return result, out.path


def remaining(lab, plan_path, inventory_path, evidence_path):
    """Conditional transfer remainder, not an exact installation deficit."""
    with store.input_db(lab, inventory_path) as (inv, binding):
        snapshot = _meta(inv, 'local_storage_snapshot')
        _stable(snapshot)
        with store.input_db(lab, evidence_path, binding) as (ev, _):
            if (_meta(inv, 'source_snapshot_id') != _meta(ev, 'source_snapshot_id') or
                    _meta(inv, 'source_plan_id') != _meta(ev, 'source_plan_id')):
                raise core.RepairError('local_checkpoint_binding_conflict')
            report = cache.transfer_summary(lab, plan_path, evidence_path)
            report['local_candidates'] = _meta(ev, 'local_verification_summary')
            report['local_index_inventory'] = _meta(inv, 'inventory_summary')
            report['local_source_fingerprints_rechecked'] = True
            report['local_storage_paths_included'] = False
            _stable(snapshot)
            return report
