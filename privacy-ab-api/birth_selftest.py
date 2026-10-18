"""Owned localhost-only root/child workers. Nothing in this file is real evidence."""
import ctypes
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from birth_manager import Manager, reconstruct

BODY = b'{"fixture":"SYNTHETIC_ONLY_NOT_REAL_CPU"}'

def packet(path, body=b""):
    return (f"POST {path} HTTP/1.1\r\nHost: us.cdn.blizzard.com\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)

def worker(port, child):
    address = ("127.0.0.1", port)
    with socket.create_connection(address, timeout=3) as connection:
        connection.sendall(packet("/owned-child-first" if child else "/owned-root-first"))
        connection.recv(512)
    if child:
        # Owned invalid-context SSPI call: validates layout and hook bytes, not encryption.
        u=ctypes.c_uint32;ptr=ctypes.c_void_p
        class SecBuffer(ctypes.Structure):
            _fields_=[('size',u),('kind',u),('data',ptr)]
        class Desc(ctypes.Structure):
            _fields_=[('version',u),('count',u),('buffers',ctypes.POINTER(SecBuffer))]
        raw=packet('/owned-sspi-negative',BODY);buf=ctypes.create_string_buffer(raw)
        sb=SecBuffer(len(raw),1,ctypes.cast(buf,ptr));desc=Desc(0,1,ctypes.pointer(sb))
        context=(ctypes.c_size_t*2)();sec=ctypes.WinDLL('secur32').EncryptMessage
        sec.argtypes=[ptr,u,ptr,u];sec.restype=ctypes.c_int32
        sec(ctypes.byref(context),0,ctypes.byref(desc),0)
        with socket.create_connection(address, timeout=3) as connection:
            raw = packet("/owned-split", BODY)
            connection.sendall(raw[:7])
            connection.sendall(raw[7:41])
            connection.sendall(raw[41:])
            connection.recv(512)
        with socket.create_connection(address, timeout=3) as connection:
            raw = packet("/owned-vectors", BODY)
            class WSABUF(ctypes.Structure):
                _fields_ = [("length", ctypes.c_uint32), ("buffer", ctypes.c_void_p)]
            chunks = [ctypes.create_string_buffer(raw[:17]), ctypes.create_string_buffer(raw[17:])]
            array = (WSABUF * 2)(*[WSABUF(len(c.value), ctypes.cast(c, ctypes.c_void_p)) for c in chunks])
            api = ctypes.WinDLL("ws2_32").WSASend
            api.argtypes = [ctypes.c_size_t, ctypes.POINTER(WSABUF), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
            api.restype = ctypes.c_int
            sent = ctypes.c_uint32()
            if api(connection.fileno(), array, 2, ctypes.byref(sent), 0, None, None) != 0 or sent.value != len(raw):
                raise RuntimeError("owned_wsa_send_failed")
            connection.recv(512)
    else:
        subprocess.run([sys.executable, str(Path(__file__).resolve()), "--child", str(port)], env=dict(os.environ), check=True, timeout=20)

def run_selftest(frida, env):
    from native_identity import identity
    result = {
        "passed": False, "stage": "not_started", "loopback_only": True,
        "synthetic_events_excluded_from_real_evidence": True,
        "root_first_request": False, "child_first_request": False,
        "split_request": False, "vector_request": False,
        "send_observed": False, "wsasend_observed": False,
        "child_gating_proven": False, "sspi_negative_input_observed": False, "processes": [],
    }
    accepted = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            accepted.append((self.path, body))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    path = Path(sys.executable).resolve()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    identities = {}
    def verify(pid, recheck=False):
        info = identity(pid)
        if Path(info["path"]).resolve() != path:
            raise RuntimeError("owned_worker_image_mismatch")
        if recheck:
            if identities[pid] != info["creation"]:
                raise RuntimeError("owned_pid_changed")
            return {}
        identities[pid] = info["creation"]
        return {"process_name": path.name.lower(), "sha256": digest, "image_bytes": path.stat().st_size}
    manager = None
    try:
        manager = Manager(frida, verify)
        result["stage"] = "spawn_owned_root"
        manager.spawn([sys.executable, str(Path(__file__).resolve()), "--root", str(server.server_port)], env, Path(__file__).parent)
        result["stage"] = "await_owned_requests"
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and len(accepted) < 4 and not manager.fatal:
            time.sleep(.05)
        time.sleep(.3)
        requests, streams = reconstruct(manager.inputs)
        captured = {r["target"]: r for r in requests}
        for key, target in [
            ("root_first_request", "/owned-root-first"),
            ("child_first_request", "/owned-child-first"),
            ("split_request", "/owned-split"), ("vector_request", "/owned-vectors"),
        ]:
            expected = BODY if key in ("split_request", "vector_request") else b""
            import base64
            result[key] = target in captured and captured[target]["body_complete"] and base64.b64decode(captured[target]["body_sample_base64"]) == expected and (target, expected) in accepted
        apis = {x["api"] for x in manager.inputs}
        result["send_observed"] = "send" in apis
        result["wsasend_observed"] = "WSASend" in apis
        result["child_gating_proven"] = len(manager.rows) == 2 and all(
            x["child_gating_enabled"] and x["instrumented_before_resume"] and x["script_errors"] == 0
            for x in manager.rows.values()
        )
        result["sspi_negative_input_observed"] = any(
            x['api']=='EncryptMessage' and x['raw']==packet('/owned-sspi-negative',BODY)
            and x['return_code']!=0 and x['accepted_bytes'] is None for x in manager.inputs)
        result["passed"] = all(result[k] for k in (
            "root_first_request", "child_first_request", "split_request", "vector_request",
            "send_observed", "wsasend_observed", "child_gating_proven", "sspi_negative_input_observed",
        )) and not manager.fatal
        result["stage"] = "complete" if result["passed"] else "owned_gate_failed"
    except Exception as exc:
        result["stage"] = "owned_gate_exception"
    finally:
        if manager:
            manager.close()
            result["processes"] = list(manager.rows.values())
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    return result

if __name__ == "__main__":
    worker(int(sys.argv[2]), sys.argv[1] == "--child")