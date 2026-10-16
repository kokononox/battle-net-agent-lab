"""Read-only full-content proof for explicitly supplied cache/archive candidates.

No recursive computer search, generation selection or game writes. A decoded CKey
match is NOT treated as possession of the required encoded representation.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import threading
import decoded_payload
import repair_core as core
import plan_storage as store


@dataclass(frozen=True)
class Candidate:
    ekey: bytes
    path: Path
    kind: str  # decoded, encoded, casc_span
    offset: int = 0
    span: object = None  # casc_span total indexed span, may include 30-byte wrapper


class Slice:
    def __init__(self, src, start, length):
        src.seek(start)
        self.src, self.left = src, length

    def read(self, n):
        if type(n) is not int or not 0 <= n <= self.left:
            raise core.RepairError("unbounded_or_outside_candidate_read")
        b = self.src.read(n)
        self.left -= len(b)
        return b


class Discard:
    def write(self, data):
        return len(data)


def _verify(path, kind, offset, span, ek, es, ck, ds, cancel):
    before = core.fingerprint(core.regular(path).stat())
    size = before[2]
    if kind == "decoded":
        if offset != 0 or span is not None:
            raise core.RepairError("decoded_candidate_coordinates")
        if size != ds:
            return "candidate_size_mismatch", 0, False, False, before
        h = core.digest(path, cancel)
        return ("decoded_content_verified" if h["md5"] == ck.hex() else
                "candidate_content_mismatch", size, h["md5"] == ck.hex(), False, before)
    if kind == "encoded":
        if offset != 0 or span is not None:
            raise core.RepairError("encoded_candidate_coordinates")
        if size != es:
            return "candidate_size_mismatch", 0, False, False, before
        offset, span = 0, es
    elif kind != "casc_span":
        raise core.RepairError("unknown_cache_candidate_kind")
    if (type(offset) is not int or offset < 0 or type(span) is not int
            or span not in (es, es + 30) or offset + span > size):
        return "candidate_span_bounds_or_size_mismatch", 0, False, False, before
    with path.open("rb") as src:
        if core.fingerprint(os.fstat(src.fileno())) != before:
            raise core.RepairError("cache_candidate_changed")
        # Exact geometry + complete expected EKey/CKey proof, not wrapper fields.
        start = offset + (30 if span == es + 30 else 0)
        stream = Slice(src, start, es)
        try:
            proof = decoded_payload.extract(src=stream, encoded_size=es, decoded_size=ds,
                ckey=ck, ekey=ek, cancel=cancel, sink=Discard())
            if not proof["encoded_integrity_verified"] or not proof["decoded_ckey_verified"]:
                state = "candidate_not_fully_verified"
                content_ok = encoded_ok = False
            else:
                state, content_ok, encoded_ok = "encoded_and_decoded_content_verified", True, True
        except decoded_payload.PayloadError as e:
            if e.reason == "cancelled":
                raise core.Cancelled("cancelled") from None
            state = ("unsupported_or_encrypted_content" if "unsupported" in e.reason
                     else "candidate_content_mismatch")
            content_ok = encoded_ok = False
        if core.fingerprint(os.fstat(src.fileno())) != before:
            raise core.RepairError("cache_candidate_changed")
    if core.fingerprint(core.regular(path).stat()) != before:
        raise core.RepairError("cache_candidate_changed")
    return state, es - stream.left, content_ok, encoded_ok, before


def build(lab, plan_path, candidates, cancel=None, byte_budget=2 * 1024**3):
    cancel = cancel or threading.Event()
    candidates = list(candidates)
    if not 0 <= len(candidates) <= 4096 or type(byte_budget) is not int or byte_budget < 0:
        raise core.RepairError("cache_evidence_batch_limit")
    plan_path = store.owned(lab, plan_path)
    input_fp = core.fingerprint(plan_path.stat())
    with store.input_db(lab, plan_path) as (plan, binding), \
            store.Writer(lab, "cache-evidence", cancel) as out:
        out.watch(plan_path, input_fp)
        db = out.db
        db.execute("""CREATE TABLE evidence(ordinal INTEGER PRIMARY KEY,ekey BLOB NOT NULL,
            kind TEXT NOT NULL,state TEXT NOT NULL,bytes_read INTEGER NOT NULL,
            decoded_content_verified INTEGER NOT NULL,encoded_object_verified INTEGER NOT NULL,
            source_path TEXT NOT NULL)""")
        spent, seen = 0, {}
        for ordinal, candidate in enumerate(candidates):
            core.check(cancel)
            if candidate.kind not in ("decoded", "encoded", "casc_span"):
                raise core.RepairError("unknown_cache_candidate_kind")
            if not isinstance(candidate.ekey, bytes) or len(candidate.ekey) != 16:
                raise core.RepairError("candidate_full_ekey_required")
            expected = plan.execute(
                "SELECT encoded_size,ckey,decoded_size,mapping_state FROM plan WHERE ekey=?",
                (candidate.ekey,)).fetchone()
            if not expected or expected[3] != "mapped":
                raise core.RepairError("candidate_not_bound_to_unambiguous_target")
            es, ck, ds, _ = expected
            if es > decoded_payload.MAX_ENCODED or ds > decoded_payload.MAX_DECODED:
                state, n, content_ok, encoded_ok = "verification_limit", 0, False, False
            else:
                required = ds if candidate.kind == "decoded" else es
                if spent + required > byte_budget:
                    state, n, content_ok, encoded_ok = "verification_limit", 0, False, False
                else:
                    path = core.regular(candidate.path)
                    state, n, content_ok, encoded_ok, fp = _verify(
                        path, candidate.kind, candidate.offset, candidate.span,
                        candidate.ekey, es, ck, ds, cancel)
                    if path in seen and seen[path] != fp:
                        raise core.RepairError("cache_candidate_changed")
                    seen[path] = fp
            spent += n
            db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)",
                (ordinal, candidate.ekey, candidate.kind, state, n, content_ok,
                 encoded_ok, str(candidate.path)))
        for path, fp in seen.items():
            if core.fingerprint(core.regular(path).stat()) != fp:
                raise core.RepairError("cache_candidate_changed")
        encoded = db.execute(
            "SELECT COUNT(DISTINCT ekey) FROM evidence WHERE encoded_object_verified=1").fetchone()[0]
        contents = db.execute(
            "SELECT COUNT(DISTINCT ekey) FROM evidence WHERE decoded_content_verified=1").fetchone()[0]
        result = {"candidates_checked": len(candidates), "candidate_bytes_read": spent,
            "encoded_target_objects_fully_verified": encoded,
            "objects_with_decoded_target_content_verified": contents,
            "recursive_or_global_cache_search_performed": False,
            "game_inventory_exhaustively_checked": False,
            "required_network_download_bytes": None, "installation_ready": False}
        out.metadata("target_binding", binding)
        out.metadata("cache_summary", result)
        out.metadata("source_plan_id", __import__("json").loads(plan.execute(
            "SELECT value FROM metadata WHERE name='plan_id'").fetchone()[0]))
    return result, out.path


def transfer_summary(lab, plan_path, evidence_path):
    with store.input_db(lab, plan_path) as (plan, binding), \
            store.input_db(lab, evidence_path, binding) as (evidence, _):
        import json
        plan_id = json.loads(plan.execute(
            "SELECT value FROM metadata WHERE name='plan_id'").fetchone()[0])
        evidence_id = json.loads(evidence.execute(
            "SELECT value FROM metadata WHERE name='source_plan_id'").fetchone()[0])
        if evidence_id != plan_id:
            raise core.RepairError("cache_evidence_belongs_to_different_plan")
        # A separate read-only in-memory join, not a rewrite of the plan.
        import sqlite3
        db = sqlite3.connect(":memory:", uri=True)
        try:
            db.execute("ATTACH DATABASE ? AS p", (plan_path.as_uri() + "?mode=ro",))
            db.execute("ATTACH DATABASE ? AS e", (evidence_path.as_uri() + "?mode=ro",))
            checked = evidence.execute("SELECT COUNT(DISTINCT ekey) FROM evidence").fetchone()[0]
            reusable = db.execute("""SELECT COUNT(*),COALESCE(SUM(p.encoded_size),0)
                FROM p.plan p WHERE EXISTS(SELECT 1 FROM e.evidence e
                  WHERE e.ekey=p.ekey AND e.encoded_object_verified=1)""").fetchone()
            candidate = db.execute("""SELECT COUNT(*),COALESCE(SUM(p.encoded_size),0)
                FROM p.plan p WHERE p.mapping_state='mapped' AND p.route_kind IS NOT NULL
                AND p.transfer_supported=1
                AND NOT EXISTS(SELECT 1 FROM e.evidence e WHERE e.ekey=p.ekey AND e.encoded_object_verified=1)
                """).fetchone()
            total = plan.execute("SELECT COUNT(*) FROM plan").fetchone()[0]
            return {"objects_with_explicit_candidates_checked": checked,
                "objects_without_explicit_cache_check": total - checked,
                "verified_encoded_objects_reusable": reusable[0],
                "verified_encoded_bytes_available": reusable[1],
                "remaining_conditional_transfer_candidates": candidate[0],
                "remaining_conditional_encoded_body_bytes": candidate[1],
                "required_network_download_bytes": None,
                "reason_not_exact": "Game archive coverage and complete install policy are not proven.",
                "decoded_cache_alone_not_subtracted_as_encoded_representation": True,
                "installation_ready": False}
        finally:
            db.close()