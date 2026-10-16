"""Owned disk-backed planning outputs. No writes to source DBs or game storage."""
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import uuid
import repair_core as core


def owned(lab, path):
    path = core.regular(path)
    if path.parent != lab.root / "objects":
        raise core.RepairError("owned_planning_input_required")
    return path


def binding_id(binding):
    fields = ("product", "region", "version", "build_config", "cdn_config")
    if any(not isinstance(binding.get(k), str) or not binding[k] for k in fields):
        raise core.RepairError("incomplete_plan_target_binding")
    return tuple(binding[k] for k in fields)


@contextlib.contextmanager
def input_db(lab, path, expected_binding=None):
    path = owned(lab, path)
    before = core.fingerprint(path.stat())
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("PRAGMA query_only=ON")
        binding = json.loads(db.execute(
            "SELECT value FROM metadata WHERE name='target_binding'").fetchone()[0])
        binding_id(binding)
        if expected_binding is not None and binding_id(binding) != binding_id(expected_binding):
            raise core.RepairError("planning_target_binding_conflict")
        yield db, binding
    finally:
        db.close()
        if core.fingerprint(core.regular(path).stat()) != before:
            raise core.RepairError("planning_input_database_changed")


class Writer:
    def __init__(self, lab, label, cancel):
        token = uuid.uuid4().hex
        self.temp = core.safe(lab.root / "objects" / (label + "-" + token + ".sqlite.part"))
        self.path = self.temp.with_suffix("")
        self.cancel = cancel
        self.db = None
        self.watched = {}

    def __enter__(self):
        with self.temp.open("xb"):
            pass
        self.db = sqlite3.connect(self.temp.as_uri(), uri=True)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA cache_size=-8192")
        self.db.set_progress_handler(lambda: int(self.cancel.is_set()), 10000)
        self.db.execute("CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL)")
        return self

    def metadata(self, name, value):
        self.db.execute("INSERT INTO metadata VALUES (?,?)",
                        (name, json.dumps(value, sort_keys=True)))

    def watch(self, path, expected=None):
        path = core.regular(path)
        current = core.fingerprint(path.stat())
        if expected is not None and current != expected:
            raise core.RepairError("planning_input_changed_before_publication")
        self.watched[path] = current

    def _check_sources(self):
        for path, before in self.watched.items():
            if core.fingerprint(core.regular(path).stat()) != before:
                raise core.RepairError("planning_input_changed_before_publication")

    def __exit__(self, typ, exc, tb):
        try:
            if typ is None:
                core.check(self.cancel)
                self._check_sources()
                self.db.commit()
                if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise core.RepairError("planning_output_database_invalid")
                self.db.close()
                self.db = None
                self._check_sources()
                os.replace(self.temp, self.path)
                core.sync_dir(self.path.parent)
        finally:
            if self.db:
                self.db.close()
            for suffix in ("", "-journal", "-wal", "-shm"):
                p = core.safe(Path(str(self.temp) + suffix))
                if p.exists():
                    core.regular(p).unlink()
        return False