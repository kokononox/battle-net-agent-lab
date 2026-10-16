"""OFFLINE demonstration; all payloads are generated synthetic bytes, NOT WoW.

Usage: python demo.py --new-lab NEW_EMPTY_PATH
The path must NOT exist. No game path, report or private manifest is accepted.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import threading
import zlib
import repair_core as core


class OfflineResponse(io.BytesIO):
    def __init__(self, body, url, status, headers):
        super().__init__(body)
        self.url, self.status, self.headers = url, status, headers

    def geturl(self):
        return self.url


class OfflineServer:
    def __init__(self, blob):
        self.blob = blob
        self.cut = True
        self.requests = []

    def open(self, url, headers):
        start = int(headers["Range"][6:].split("-")[0]) if headers else 0
        self.requests.append({"range": headers.get("Range"), "start": start})
        h = {"Content-Length": str(len(self.blob) - start)}
        if start:
            h["Content-Range"] = "bytes %d-%d/%d" % (
                start, len(self.blob) - 1, len(self.blob))
        body = self.blob[start:]
        if self.cut:
            body = body[:11]
            self.cut = False
        return OfflineResponse(body, url, 206 if start else 200, h)


def demo(new_lab):
    lab = core.Lab.create(new_lab)
    original = b"SYNTHETIC damaged file"
    desired = b"SYNTHETIC repaired file - NOT a game executable\n" * 100
    blob = b"BLTE\0\0\0\0Z" + zlib.compress(desired)
    ekey, ckey = hashlib.md5(blob).hexdigest(), hashlib.md5(desired).hexdigest()
    spec = core.Spec("_retail_/Demo/example.dat", ckey, len(desired),
                     ekey, len(blob), "https://offline.invalid/tpr/wow/data/" +
                     ekey[:2] + "/" + ekey[2:4] + "/" + ekey)
    target = lab.target(spec.path)
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    personal = lab.root / "target" / "_retail_" / "WTF" / "config.wtf"
    personal.parent.mkdir()
    personal.write_bytes(b"SYNTHETIC user settings: keep me")
    server = OfflineServer(blob)
    # 1. Interruption retains an encoded prefix and does not touch the target.
    try:
        core.repair(lab, [spec], server)
        raise AssertionError("interruption was expected")
    except core.RepairError as e:
        assert str(e) == "download_interrupted_prefix_retained"
    assert target.read_bytes() == original
    # 2. Resume, then fail after replacement; automatic rollback restores original.
    def fail(stage):
        if stage == "replaced:0":
            raise OSError("injected test failure")
    try:
        core.repair(lab, [spec], server, failpoint=fail)
        raise AssertionError("replacement failure was expected")
    except OSError:
        pass
    assert target.read_bytes() == original
    # 3. Reuse verified cached data, apply successfully, then idempotent repair.
    successful = core.repair(lab, [spec], server)
    assert target.read_bytes() == desired
    no_work = core.repair(lab, [spec], server)
    assert no_work["status"] == "already_healthy"
    assert personal.read_bytes() == b"SYNTHETIC user settings: keep me"
    result = {
        "scope": "synthetic_offline_lab_only",
        "real_network_requests": 0,
        "real_game_files_read_or_modified": 0,
        "interruption_preserved_original": True,
        "download_resumed_at_byte": server.requests[1]["start"],
        "failure_restored_original": True,
        "repair_status": successful["status"],
        "second_repair_status": no_work["status"],
        "synthetic_user_settings_unchanged": True,
        "full_WoW_update_proven": False,
    }
    core.atomic_json(lab.root / "DEMO-RESULT.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--new-lab", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(demo(args.new_lab), ensure_ascii=False, indent=2))