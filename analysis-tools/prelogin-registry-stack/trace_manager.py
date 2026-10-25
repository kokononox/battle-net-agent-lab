# Wire manager copied unchanged except explicit registry channel / hook composition.
from registry_events import Events
REGISTRY_MANAGERS=[]
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
        self.registry = Events()
        REGISTRY_MANAGERS.append(self)
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
        self.events = queue.Queue(maxsize=16)
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
            try: self.events.put_nowait((child.pid, child.parent_pid))
            except queue.Full:
                self.fatal = True
                try: self.device.kill(child.pid)
                except Exception: pass

    def worker(self):
        while not self.stop.is_set():
            try:
                pid, parent = self.events.get(timeout=.1)
            except queue.Empty:
                continue
            self.prepare(pid, parent)

    def message(self, row, msg, data):
        with self.lock:
            if msg.get('type')=='send' and isinstance(msg.get('payload'),dict) and str(msg['payload'].get('kind','')).startswith('reg_'):
                self.registry.accept(row,msg['payload'],data)
                return
            if msg.get('type') != 'send' or type(msg.get('payload')) is not dict:
                row['script_errors'] += 1
                return
            event = msg['payload']; kind = event.get('kind')
            if kind == 'ready':
                row['hook_ready'] = True
                row['pointer_bits'] = event.get('pointer_bits') if event.get('pointer_bits') in (32, 64) else None
            elif kind == 'installed':
                if event.get('api') not in row['installed_hooks']:
                    row['installed_hooks'].append(event.get('api'))
            elif kind in ('read_error', 'install_error'):
                row['script_errors'] += 1
                apis = {'EncryptMessage','DecryptMessage','send','recv','WSASend','WSARecv','WSAGetOverlappedResult','connect','WSAConnect','closesocket','BindIoCompletionCallback','CreateThreadpoolIo'}
                phases = {'enter','leave','install','completion'}
                reasons = {'bounded','buffer_count','data_layout','stream_layout','socket_limit','context_limit','accepted_bounds','pending_limit','overlapped_reuse','callback_unsupported','completion_unmatched','memory_access','missing_export','callback_limit','completion_race','completion_ambiguous','callback_origin'}
                key = '|'.join((event.get('api') if event.get('api') in apis else 'other', event.get('phase') if event.get('phase') in phases else 'other', event.get('reason') if event.get('reason') in reasons else 'other'))
                row['diagnostics'][key] = row['diagnostics'].get(key, 0) + 1
            elif kind in ('probe','probe_counts'):
                apis={'send','recv','WSASend','WSARecv','GetQueuedCompletionStatus','GetQueuedCompletionStatusEx','GetOverlappedResult','GetOverlappedResultEx','NtRemoveIoCompletion','NtRemoveIoCompletionEx','BindIoCompletionCallback','CreateThreadpoolIo'}
                phases={'submission','reuse','completion_call','registration'}
                states={'pending','non_pending_error','unknown_error','immediate','synchronous','true','false'}
                if kind == 'probe':
                    values={'|'.join(str(event.get(k,'')) for k in ('api','phase','state')):1}
                else: values=event.get('counts')
                if type(values) is not dict or len(values)>100:
                    row['script_errors'] += 1
                    return
                for key,n in values.items():
                    parts=key.split('|') if type(key) is str else []
                    if (len(parts)!=3 or parts[0] not in apis or parts[1] not in phases or parts[2] not in states
                        or type(n) is not int or not 0<=n<=10000000):
                        row['script_errors'] += 1
                        return
                for key,n in values.items():row['observations'][key]=row['observations'].get(key,0)+n
            elif kind == 'socket_complete':
                op = event.get('operation')
                matches = [x for x in self.inputs if x.get('pid') == row['pid'] and x.get('operation') == op and x.get('asynchronous') is True]
                raw = bytes(data or b''); n = event.get('accepted_bytes')
                if (len(matches) != 1 or type(op) is not str or not re.fullmatch(r'o[1-9][0-9]{0,5}', op)
                    or type(n) is not int or not 0 <= n <= 131072 or n != len(raw)
                    or matches[0].get('completion_proven') or event.get('complete') is not True
                    or event.get('socket') != matches[0].get('socket') or n > matches[0].get('declared_bytes', -1)):
                    row['script_errors'] += 1
                    return
                x = matches[0]
                if self.total_bytes + len(raw) > 16*1024*1024:
                    self.dropped += 1
                    return
                if x['kind'] == 'send' and x['raw'][:n] != raw:
                    row['script_errors'] += 1
                    return
                self.total_bytes += len(raw)
                x.update(raw=raw, accepted_bytes=n, completion_proven=True, return_code=0,
                         ambiguous=x.get('ambiguous') or event.get('ambiguous') is not False)
                row['completed_operations'] += 1
            elif kind == 'limit': self.dropped += 1
            elif kind in ('encrypt', 'decrypt', 'send', 'recv'):
                raw = bytes(data or b'')
                if len(self.inputs) >= 4096 or self.total_bytes + len(raw) > 16*1024*1024:
                    self.dropped += 1
                    return
                if len(raw) > 262144 or type(event.get('order')) is not int:
                    row['script_errors'] += 1
                    return
                self.total_bytes += len(raw)
                item = dict(event, pid=row['pid'], process_sha256=row['sha256'])
                if kind in ('encrypt', 'decrypt'):
                    n=event.get('before_bytes'); m=event.get('after_bytes')
                    if type(n) is not int or type(m) is not int or n<0 or m<0 or n+m != len(raw):
                        row['script_errors'] += 1
                        return
                    item['before'], item['after'] = raw[:n], raw[n:]
                else: item['raw'] = raw
                self.inputs.append(item)
                row['input_events'] += 1

    def prepare(self, pid, parent):
        row = {
            "pid": pid, "parent_pid": parent, "process_name": None, "sha256": None,
            "image_bytes": 0, "authenticode_valid": False,
            "expected_blizzard_publisher": False,
            "status": "paused", "phase": "verify", "error_kind": None,
            "hook_ready": False, "child_gating_enabled": False,
            "instrumented_before_resume": False, "installed_hooks": [],
            "input_events": 0, "script_errors": 0, "pointer_bits": None, "diagnostics": {}, "observations": {}, "completed_operations": 0,
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
            from native_identity import identity
            verified_path = identity(pid)['path']
            prefix = 'globalThis.__LAB_IMAGE_PATH=' + json.dumps(verified_path) + ';\n'
            script = bounded(self.frida, lambda: session.create_script(prefix+(Path(__file__).resolve().parent.parent/"prelogin-wire-h3"/"wire_hook.js").read_text()+"\n"+Path(__file__).with_name("registry_hook.js").read_text()))
            self.scripts.append(script)
            script.on("message", lambda msg, data: self.message(row, msg, data))
            bounded(self.frida, script.load)
            deadline = time.monotonic() + 3
            while not row["hook_ready"] and time.monotonic() < deadline:
                time.sleep(.01)
            if not row["hook_ready"] or row["script_errors"] or pid not in self.registry.ready or self.registry.errors or self.registry.limits:
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
        # Flush diagnostics only; RPC never changes target state or network buffers.
        # A process may already have exited: these diagnostic counters are explicitly partial.
        for script in self.scripts:
            try: bounded(self.frida, lambda s=script: s.exports_sync.flushprobes())
            except Exception: pass
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

