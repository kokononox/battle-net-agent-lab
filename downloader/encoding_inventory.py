"""All verified Encoding CKey/EKey pages -> owned SQLite. No asset extraction."""
import mmap
import shutil
import threading
import repair_core as core
import encoding_readonly as reference
import plan_storage as store


def e_records(table, cancel):
    d, last = table.map, None
    for i in range(table.en):
        core.check(cancel)
        page = d[table.epages + i * table.eps:table.epages + (i + 1) * table.eps]
        index = d[table.eindex + i * 32:table.eindex + (i + 1) * 32]
        import hashlib
        if hashlib.md5(page).digest() != index[16:]:
            raise core.RepairError("encoding_ekey_page_checksum")
        first, consumed = True, 0
        for pos in range(0, len(page) - 24, 25):
            ek = page[pos:pos + 16]
            if ek == bytes(16):
                if page[pos + 16:pos + 20] not in (bytes(4), b"\xff" * 4) or any(page[pos + 20:]):
                    raise core.RepairError("encoding_ekey_page_terminator")
                consumed = len(page)
                break
            if first and ek != index[:16]:
                raise core.RepairError("encoding_ekey_page_first_key")
            if last is not None and ek <= last:
                raise core.RepairError("encoding_ekey_order")
            first, last, consumed = False, ek, pos + 25
            yield ek, int.from_bytes(page[pos + 20:pos + 25], "big"), int.from_bytes(page[pos + 16:pos + 20], "big")
        if any(page[consumed:]):
            raise core.RepairError("encoding_ekey_page_padding")


def build(lab, source, spec, binding, cancel=None, notify=lambda _: None):
    cancel = cancel or threading.Event()
    spec.validate()
    store.binding_id(binding)
    source = store.owned(lab, source)
    if source.stat().st_size > 512 * 1024**2:
        raise core.RepairError("encoding_inventory_source_limit")
    proof = core.digest(source, cancel)
    if proof["size"] != spec.decoded_size or proof["md5"] != spec.ckey:
        raise core.RepairError("encoding_inventory_ckey_or_size_mismatch")
    before = core.fingerprint(source.stat())
    if shutil.disk_usage(source.parent).free < 8 * proof["size"] + 64 * 1024**2:
        raise core.RepairError("encoding_inventory_space")
    with store.Writer(lab, "encoding", cancel) as out:
        out.watch(source, before)
        db = out.db
        db.executescript("""
          CREATE TABLE contents(ckey BLOB PRIMARY KEY,decoded_size INTEGER NOT NULL) WITHOUT ROWID;
          CREATE TABLE links(ckey BLOB NOT NULL,ordinal INTEGER NOT NULL,ekey BLOB NOT NULL,
                             PRIMARY KEY(ckey,ordinal),UNIQUE(ckey,ekey)) WITHOUT ROWID;
          CREATE TABLE encoded(ekey BLOB PRIMARY KEY,encoded_size INTEGER NOT NULL,
                               espec_index INTEGER NOT NULL) WITHOUT ROWID;
        """)
        cn = ln = en = 0
        cp, lp, ep = [], [], []
        with source.open("rb") as src, mmap.mmap(src.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if core.fingerprint(__import__("os").fstat(src.fileno())) != before:
                raise core.RepairError("encoding_source_changed")
            with reference.EncodingTable(data) as table:
                for ck, size, keys in table.c_records(cancel, notify):
                    if ck == bytes(16) or any(k == bytes(16) for k in keys):
                        raise core.RepairError("encoding_zero_content_or_encoding_key")
                    cn += 1
                    ln += len(keys)
                    if cn > 10_000_000 or ln > 20_000_000:
                        raise core.RepairError("encoding_inventory_record_limit")
                    cp.append((ck, size))
                    lp.extend((ck, ek, i) for i, ek in enumerate(keys))
                    if len(cp) >= 4096:
                        db.executemany("INSERT INTO contents VALUES (?,?)", cp)
                        db.executemany("INSERT INTO links(ckey,ekey,ordinal) VALUES (?,?,?)", lp)
                        cp.clear()
                        lp.clear()
                if cp:
                    db.executemany("INSERT INTO contents VALUES (?,?)", cp)
                    db.executemany("INSERT INTO links(ckey,ekey,ordinal) VALUES (?,?,?)", lp)
                for row in e_records(table, cancel):
                    en += 1
                    if en > 10_000_000:
                        raise core.RepairError("encoding_inventory_record_limit")
                    ep.append(row)
                    if len(ep) == 4096:
                        db.executemany("INSERT INTO encoded VALUES (?,?,?)", ep)
                        ep.clear()
                if ep:
                    db.executemany("INSERT INTO encoded VALUES (?,?,?)", ep)
            if core.fingerprint(__import__("os").fstat(src.fileno())) != before:
                raise core.RepairError("encoding_source_changed")
        if core.fingerprint(core.regular(source).stat()) != before:
            raise core.RepairError("encoding_source_changed")
        db.execute("CREATE INDEX links_ekey ON links(ekey)")
        missing = db.execute(
            "SELECT COUNT(*) FROM links l LEFT JOIN encoded e USING(ekey) WHERE e.ekey IS NULL"
        ).fetchone()[0]
        result = {
            "content_records": cn, "content_encoding_links": ln, "encoded_size_records": en,
            "links_without_encoded_size": missing,
            "all_ckey_and_ekey_page_checksums_verified": True,
            "decoded_encoding_ckey_verified": True, "installation_ready": False}
        assert db.execute("SELECT COUNT(*) FROM contents").fetchone()[0] == cn
        assert db.execute("SELECT COUNT(*) FROM links").fetchone()[0] == ln
        assert db.execute("SELECT COUNT(*) FROM encoded").fetchone()[0] == en
        out.metadata("target_binding", binding)
        out.metadata("encoding_summary", result)
        out.metadata("source_sha256", proof["sha256"])
    return result, out.path