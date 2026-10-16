"""Join complete DL, Encoding and verified catalog data. Not an installer.

Filtering is an explicit conservative tag model, not a proven vendor install
policy. Cache/game coverage is never inferred from absence in a small cache.
"""
from dataclasses import dataclass
import json
import shutil
import sqlite3
import threading
import repair_core as core
import plan_storage as store


@dataclass(frozen=True)
class Profile:
    locales: tuple
    platform: str = "Windows"
    architecture: str = "x86_64"
    region: str = "EU"

    def validate(self):
        if (self.platform != "Windows" or self.architecture != "x86_64"
                or self.region != "EU" or not isinstance(self.locales, tuple)
                or not self.locales or len(set(self.locales)) != len(self.locales)
                or not set(self.locales) <= {
                    "deDE", "enUS", "esES", "esMX", "frFR", "itIT", "koKR",
                    "ptBR", "ruRU", "zhCN", "zhTW"}):
            raise core.RepairError("unsupported_plan_profile")
        return self


def selection_mask(download_db, profile=None):
    summary = json.loads(download_db.execute(
        "SELECT value FROM metadata WHERE name='inventory_summary'").fetchone()[0])
    n = summary["manifest_records"]
    width = (n + 7) // 8
    padding = (8 - n % 8) % 8
    valid = ((1 << n) - 1) << padding
    if profile is None:
        return valid.to_bytes(width, "big"), {"policy": "all_download_manifest_records",
            "vendor_install_policy_proven": False, "selected_record_bits": n}
    profile.validate()
    required = {1: [profile.platform], 2: [profile.architecture],
                3: list(profile.locales), 4: [profile.region]}
    tags = {}
    for name, kind, bitmap in download_db.execute("SELECT name,kind,bitmap FROM tags"):
        if len(bitmap) != width or (kind, name) in tags:
            raise core.RepairError("plan_tag_bitmap_or_identity_conflict")
        tags[kind, name] = int.from_bytes(bitmap, "big") & valid
    selected = valid
    for kind, choices in required.items():
        union_all, chosen = 0, 0
        for (k, name), mask in tags.items():
            if k == kind:
                union_all |= mask
        for name in choices:
            if (kind, name) not in tags:
                raise core.RepairError("requested_profile_tag_missing_no_fallback")
            chosen |= tags[kind, name]
        # Shared/unclassified records must not disappear simply because no
        # member tag for this dimension was present. OR locales, AND dimensions.
        selected &= chosen | (valid ^ union_all)
    return selected.to_bytes(width, "big"), {
        "policy": "matching_or_unclassified_per_dimension;OR_locales;AND_dimensions",
        "profile": {"platform": profile.platform, "architecture": profile.architecture,
                    "region": profile.region, "locales": list(profile.locales)},
        "optional_category_and_alternate_tags_not_excluded": True,
        "vendor_install_policy_proven": False,
        "selected_record_bits": bin(selected).count("1")}


def build(lab, download_path, encoding_path, catalog_path, profile=None,
          cancel=None, notify=lambda _: None):
    cancel = cancel or threading.Event()
    download_path, encoding_path, catalog_path = (
        store.owned(lab, p) for p in (download_path, encoding_path, catalog_path))
    inputs = {p: core.fingerprint(p.stat()) for p in
              (download_path, encoding_path, catalog_path)}
    needed = sum(p.stat().st_size for p in (download_path, encoding_path, catalog_path))
    if shutil.disk_usage(lab.root).free < needed + 64 * 1024**2:
        raise core.RepairError("content_plan_space")
    with store.input_db(lab, download_path) as (download, binding), \
            store.input_db(lab, encoding_path, binding), \
            store.input_db(lab, catalog_path, binding), \
            store.Writer(lab, "content-plan", cancel) as out:
        for p, before in inputs.items():
            out.watch(p, before)
        mask, policy = selection_mask(download, profile)
        db = out.db
        for alias, path in (("d", download_path), ("e", encoding_path), ("r", catalog_path)):
            db.execute("ATTACH DATABASE ? AS " + alias, (path.as_uri() + "?mode=ro",))
        db.executescript("""
          CREATE TABLE selected(ekey BLOB PRIMARY KEY,encoded_size INTEGER NOT NULL) WITHOUT ROWID;
          CREATE TABLE plan(ekey BLOB PRIMARY KEY,encoded_size INTEGER NOT NULL,
            ckey BLOB,decoded_size INTEGER,mapping_state TEXT NOT NULL,
            route_kind TEXT,archive_key TEXT,archive_offset INTEGER,index_key TEXT,
            route_options INTEGER NOT NULL DEFAULT 0,
            transfer_supported INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
        """)
        pending, selected_rows = [], 0
        for ordinal, ek, size in download.execute(
                "SELECT ordinal,ekey,encoded_size FROM entries ORDER BY ordinal"):
            if ordinal % 4096 == 0:
                core.check(cancel)
                notify("Selecting Download records: " + str(ordinal))
            if mask[ordinal // 8] & (0x80 >> (ordinal % 8)):
                pending.append((ek, size))
                selected_rows += 1
            if len(pending) >= 4096:
                db.executemany("INSERT OR IGNORE INTO selected VALUES (?,?)", pending)
                pending.clear()
        if pending:
            db.executemany("INSERT OR IGNORE INTO selected VALUES (?,?)", pending)
        if selected_rows != policy["selected_record_bits"]:
            raise core.RepairError("plan_selection_count_mismatch")
        core.check(cancel)
        db.execute("""INSERT INTO plan(ekey,encoded_size,ckey,decoded_size,mapping_state)
          SELECT s.ekey,s.encoded_size,
            CASE WHEN COUNT(DISTINCT l.ckey)=1 THEN MIN(l.ckey) END,
            CASE WHEN COUNT(DISTINCT l.ckey)=1 THEN MIN(c.decoded_size) END,
            CASE WHEN z.ekey IS NULL THEN 'encoding_size_not_found'
                 WHEN z.encoded_size<>s.encoded_size THEN 'download_encoding_size_conflict'
                 WHEN COUNT(DISTINCT l.ckey)=0 THEN 'ckey_not_mapped'
                 WHEN COUNT(DISTINCT l.ckey)>1 THEN 'ambiguous_ckey_mapping'
                 ELSE 'mapped' END
          FROM selected s LEFT JOIN e.encoded z USING(ekey)
          LEFT JOIN e.links l USING(ekey)
          LEFT JOIN e.contents c ON c.ckey=l.ckey
          GROUP BY s.ekey""")
        db.execute("""UPDATE plan SET transfer_supported=1
          WHERE mapping_state='mapped' AND encoded_size>0 AND encoded_size<=?
          AND decoded_size<=?""",
          (core.decoded_payload.MAX_ENCODED, core.decoded_payload.MAX_DECODED))
        # Preserve every route in the verified input DB. Choose a deterministic
        # transfer candidate only; this is NOT an active local CASC generation.
        db.executescript("""
          CREATE TEMP TABLE chosen AS
            SELECT ekey,route_kind,archive_key,archive_offset,index_key,options FROM (
              SELECT p.ekey,r.route_kind,r.archive_key,r.archive_offset,r.index_key,
                     COUNT(*) OVER (PARTITION BY p.ekey) AS options,
                     ROW_NUMBER() OVER (PARTITION BY p.ekey ORDER BY
                       r.route_kind='archive_range' DESC,r.archive_key,r.archive_offset,r.index_key) AS rn
              FROM plan p JOIN r.routes r USING(ekey,encoded_size)) WHERE rn=1;
          CREATE UNIQUE INDEX chosen_key ON chosen(ekey);
          UPDATE plan SET
            (route_kind,archive_key,archive_offset,index_key,route_options)=
            (SELECT route_kind,archive_key,archive_offset,index_key,options
             FROM chosen c WHERE c.ekey=plan.ekey)
          WHERE ekey IN (SELECT ekey FROM chosen);
        """)
        states = dict(db.execute("SELECT mapping_state,COUNT(*) FROM plan GROUP BY mapping_state"))
        total = db.execute("SELECT COUNT(*) FROM selected").fetchone()[0]
        assert sum(states.values()) == total
        routable, route_bytes = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(encoded_size),0) FROM plan "
            "WHERE mapping_state='mapped' AND route_kind IS NOT NULL AND transfer_supported=1").fetchone()
        missing_routes = db.execute(
            "SELECT COUNT(*) FROM plan WHERE mapping_state='mapped' AND route_kind IS NULL").fetchone()[0]
        result = {
            "selected_manifest_records": selected_rows, "selected_unique_objects": total,
            "mapping_states": states, "mapped_objects_with_verified_candidate_route": routable,
            "mapped_objects_without_route_in_checked_catalogs": missing_routes,
            "mapped_objects_outside_current_transfer_limits": db.execute(
                "SELECT COUNT(*) FROM plan WHERE mapping_state='mapped' AND transfer_supported=0").fetchone()[0],
            "candidate_encoded_body_bytes_before_local_reuse": route_bytes,
            "cache_checked_objects": 0, "game_archive_payloads_checked": 0,
            "required_network_download_bytes": None,
            "current_route_http_availability_tested": False,
            "tag_selection": policy, "full_game_install_closure_proven": False,
            "installation_ready": False}
        out.metadata("target_binding", binding)
        out.metadata("plan_summary", result)
        out.metadata("plan_id", out.path.stem)
    return result, out.path