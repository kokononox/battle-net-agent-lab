import base64
import collections
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import threading
import time

def bounded(frida, operation):
    cancel = frida.Cancellable()
    timer = threading.Timer(8, cancel.cancel)
    timer.daemon = True
    timer.start()
    try:
        with cancel:
            return operation()
    finally:
        timer.cancel()

class Manager:
    def __init__(self, frida, verifier):
        self.frida = frida
        self.device = frida.get_local_device()
        self.verifier = verifier
        self.rows = {}
        self.owned = set()
        self.sessions = []
        self.scripts = []
        self.inputs = []
        self.total_bytes = 0
        self.dropped = 0
        self.fatal = False
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.device.on("child-added", self.child)
        self.device.on("output", self.discard_output)
        self.thread = threading.Thread(target=self.worker, daemon=True)
        self.thread.start()

    def discard_output(self, *args):
        pass

    def child(self, child):
        if child.parent_pid in self.owned:
            self.owned.add(child.pid)
            self.events.put((child.pid, child.parent_pid))

    def worker(self):
        while not self.stop.is_set():
            try:
                pid, parent = self.events.get(timeout=.1)
            except queue.Empty:
                continue
            self.prepare(pid, parent)

    def message(self, row, msg, data):
        with self.lock:
            if msg.get("type") != "send" or type(msg.get("payload")) is not dict:
                row["script_errors"] += 1
                return
            event = msg["payload"]
            kind = event.get("kind")
            if kind == "ready":
                row["hook_ready"] = True
            elif kind == "installed":
                if event.get("api") in {"send", "WSASend", "connect", "WSAConnect", "closesocket"}:
                    if event["api"] not in row["installed_hooks"]:
                        row["installed_hooks"].append(event["api"])
            elif kind in ("install_error", "read_error"):
                row["script_errors"] += 1
            elif kind == "input":
                raw = bytes(data or b"")
                if len(self.inputs) >= 512 or self.total_bytes + len(raw) > 1048576:
                    self.dropped += 1
                    return
                if not (re.fullmatch("s[0-9]{1,6}", str(event.get("socket", "")))
                        and event.get("api") in ("send", "WSASend")
                        and type(event.get("sequence")) is int
                        and type(event.get("declared_bytes")) is int
                        and 0 <= event["declared_bytes"] <= 16777216
                        and len(raw) <= 16384):
                    row["script_errors"] += 1
                    return
                accepted = event.get("accepted_bytes")
                if accepted is not None and (type(accepted) is not int or not 0 <= accepted <= event["declared_bytes"]):
                    row["script_errors"] += 1
                    return
                self.total_bytes += len(raw)
                self.inputs.append({
                    "pid": row["pid"], "process_sha256": row["sha256"],
                    "socket": event["socket"], "api": event["api"],
                    "sequence": event["sequence"], "declared_bytes": event["declared_bytes"],
                    "accepted_bytes": accepted, "return_code": event.get("return_code"),
                    "truncated": event.get("truncated") is True, "raw": raw,
                })
                row["input_events"] += 1

    def prepare(self, pid, parent):
        row = {
            "pid": pid, "parent_pid": parent, "process_name": None, "sha256": None,
            "image_bytes": 0, "authenticode_valid": False,
            "expected_blizzard_publisher": False,
            "status": "paused", "phase": "verify", "error_kind": None,
            "hook_ready": False, "child_gating_enabled": False,
            "instrumented_before_resume": False, "installed_hooks": [],
            "input_events": 0, "script_errors": 0,
        }
        self.rows[pid] = row
        session = None
        try:
            if len(self.rows) > 8 or self.stop.is_set():
                raise RuntimeError("process_limit")
            row.update(self.verifier(pid))
            row["phase"] = "attach"
            session = bounded(self.frida, lambda: self.device.attach(pid))
            self.sessions.append(session)
            row["phase"] = "child_gating"
            bounded(self.frida, session.enable_child_gating)
            row["child_gating_enabled"] = True
            row["phase"] = "script_load"
            script = bounded(self.frida, lambda: session.create_script(Path(__file__).with_name("hook.js").read_text()))
            self.scripts.append(script)
            script.on("message", lambda msg, data: self.message(row, msg, data))
            bounded(self.frida, script.load)
            deadline = time.monotonic() + 3
            while not row["hook_ready"] and time.monotonic() < deadline:
                time.sleep(.01)
            if not row["hook_ready"] or row["script_errors"]:
                raise RuntimeError("hook_not_ready")
            # Verify live image identity again before letting original code run.
            self.verifier(pid, recheck=True)
            if self.stop.is_set():
                raise RuntimeError("stopping_before_resume")
            row["phase"] = "resume"
            bounded(self.frida, lambda: self.device.resume(pid))
            row["instrumented_before_resume"] = True
            row["status"] = "resumed"
            row["phase"] = "observing"
        except Exception as exc:
            row["status"] = "refused_or_failed"
            name = type(exc).__name__
            row["error_kind"] = name if re.fullmatch("[A-Za-z_]{1,64}", name) else "other"
            self.fatal = True
            try:
                bounded(self.frida, lambda: self.device.kill(pid))
            except Exception:
                pass
        return row

    def spawn(self, argv, env, cwd):
        pid = bounded(self.frida, lambda: self.device.spawn(
            str(argv[0]), argv=[str(x) for x in argv], envp=env, cwd=str(cwd), stdio="pipe",
        ))
        self.owned.add(pid)
        row = self.prepare(pid, None)
        if row["status"] != "resumed":
            raise RuntimeError("root_instrumentation_failed")
        return pid

    def close(self):
        self.stop.set()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            self.fatal = True
        for pid in list(self.owned):
            try:
                bounded(self.frida, lambda p=pid: self.device.kill(p))
            except Exception:
                pass
        for session in reversed(self.sessions):
            try:
                bounded(self.frida, session.detach)
            except Exception:
                pass
        self.device.off("child-added", self.child)
        self.device.off("output", self.discard_output)

    def report(self):
        return {
            "processes": list(self.rows.values()), "input_events": len(self.inputs),
            "dropped_events": self.dropped, "fatal": self.fatal,
        }

def reconstruct(inputs):
    from http_capture import parse_requests
    groups = collections.defaultdict(list)
    for item in inputs:
        groups[(item["pid"], item["process_sha256"], item["socket"])].append(item)
    requests, streams = [], []
    for (pid, sha, socket), items in groups.items():
        stream = bytearray()
        incomplete = False
        for item in sorted(items, key=lambda x: x["sequence"]):
            accepted = item["accepted_bytes"]
            if accepted is None or accepted > len(item["raw"]) or item["truncated"] or (accepted == 0 and item["declared_bytes"] > 0):
                incomplete = True
                break
            stream.extend(item["raw"][:accepted])
        rows, status = parse_requests(bytes(stream))
        streams.append({"pid": pid, "socket": socket, "parse_status": status, "api_input_gap": incomplete})
        for row in rows:
            if len(requests) >= 128:
                break
            requests.append({"pid": pid, "process_sha256": sha, "socket": socket, **row})
    return requests, streams