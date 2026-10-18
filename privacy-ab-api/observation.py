"""G1: native root+child fixture gate, then one verified startup from process birth."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

class Process:
    """Minimal Popen-compatible handle for observe_agent's one exact setup launch."""
    def __init__(self, manager, pid):
        self.manager, self.pid = manager, pid
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.api.OpenProcess.restype = ctypes.c_void_p
        self.api.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self.api.CloseHandle.argtypes = [ctypes.c_void_p]
        self.handle = self.api.OpenProcess(0x1000, False, pid)
        if not self.handle:
            raise OSError("process_handle_unavailable")
    def poll(self):
        code = ctypes.c_uint32()
        if not self.api.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            raise OSError("process_status_unavailable")
        return None if code.value == 259 else code.value
    def wait(self, timeout=None):
        deadline = time.monotonic() + (timeout if timeout is not None else 30)
        while time.monotonic() < deadline:
            code = self.poll()
            if code is not None:
                return code
            time.sleep(.05)
        raise subprocess.TimeoutExpired("verified_setup", timeout)
    def kill(self):
        from birth_manager import bounded
        bounded(self.manager.frida, lambda: self.manager.device.kill(self.pid))
    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None

def main():
    if not (sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Windows"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and os.environ.get("PRIVACY_AB_API_ONCE") == "ab-api-h1"):
        raise SystemExit("fresh_hosted_once_required")
    root = Path(__file__).resolve().parents[1]
    for folder in ("scripts", "privacy-network", "privacy-tls", "privacy-http"):
        sys.path.insert(0, str(root / folder))
    # Local gate must win over the older privacy-tls/selftest.py module.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import frida
    import observe_agent as obs
    from native_identity import identity
    from samples import reference
    from birth_manager import Manager, reconstruct, tls_summary
    from birth_selftest import run_selftest
    from validate_observation import validate
    report = {
        "schema": "bnet-process-birth-http-tls-1",
        "source_commit": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
        "scope": "fresh_vm_root_child_gate_no_login_game_install_action",
        "tool_version": frida.__version__, "reference": reference(),
        "selftest": None, "bootstrap_pin_match": None,
        "processes": [], "streams": [], "requests": [], "tls_inputs": [],
        "input_events": 0, "dropped_events": 0, "fatal": False,
        "status": "not_started", "error_code": None,
        "limits": {
            "server_receipt_proven": False, "user_pc_observed": False, "full_update_test": False,
            "known_hosts_only": False, "credential_headers_redacted": True,
            "api_input_not_network_delivery": True, "async_completion_not_observed": True,
            "concurrent_send_order_can_be_ambiguous": True, "instrumentation_changes_timing": True,
            "no_tls_verification_change": True, "no_send_arguments_or_return_values_modified": True,
            "children_not_verified_are_refused": True, "child_network_hard_byte_cap": False,
            "bounded_capture_can_miss_data": True,
            "tls_context_reuse_not_fully_tracked": True, "sspi_success_not_network_send": True,
            "openssl_http2_quic_plaintext_not_captured": True, "sspi_fixture_not_real_tls_session": True,
        },
    }
    out = Path("output")
    out.mkdir(exist_ok=True)
    manager = None
    launched = []
    original_popen, original_fetch = subprocess.Popen, obs.fetch_setup
    setup_path = None
    identities = {}
    def verify(pid, recheck=False):
        info = identity(pid)
        path = Path(info["path"])
        if recheck:
            if identities[pid] != (info["creation"], str(path).lower()):
                raise obs.LabError("pid_identity_changed")
            return {}
        if path.name.lower() not in obs.NAMES or obs.is_reparse(path) or not 0 < path.stat().st_size <= 128*1024**2:
            raise obs.LabError("image_outside_approved_processes")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sig = obs.signature(path, obs.clean_environment(os.environ))
        if not sig.get("accepted_for_execution"):
            raise obs.LabError("live_image_signature_refused")
        identities[pid] = (info["creation"], str(path).lower())
        return {
            "process_name": path.name.lower(), "sha256": digest,
            "image_bytes": path.stat().st_size, "authenticode_valid": sig["authenticode_valid"],
            "expected_blizzard_publisher": sig["expected_blizzard_publisher"],
        }
    def pinned_fetch(destination):
        nonlocal setup_path
        result = original_fetch(destination)
        report["bootstrap_pin_match"] = result["sha256"] == "de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf"
        if not report["bootstrap_pin_match"]:
            destination.unlink(missing_ok=True)
            raise obs.LabError("bootstrap_pin_mismatch_refused")
        setup_path = destination.resolve()
        return result
    def launch(argv, *args, **kwargs):
        if (setup_path is not None and isinstance(argv, (tuple, list))
                and len(argv) == 1 and Path(argv[0]).resolve() == setup_path):
            if launched:
                raise obs.LabError("duplicate_setup_launch_refused")
            pid = manager.spawn(argv, kwargs["env"], kwargs["cwd"])
            process = Process(manager, pid)
            launched.append(process)
            return process
        return original_popen(argv, *args, **kwargs)
    try:
        if frida.__version__ != "17.24.2":
            raise obs.LabError("frida_version")
        report["status"] = "selftest"
        report["selftest"] = run_selftest(frida, obs.clean_environment(os.environ))
        if not report["selftest"]["passed"]:
            raise obs.LabError("owned_root_child_selftest_failed_no_client_launched")
        if obs.snapshot(obs.clean_environment(os.environ)).get("processes"):
            raise obs.LabError("preexisting_processes_refused")
        manager = Manager(frida, verify)
        obs.fetch_setup = pinned_fetch
        subprocess.Popen = launch
        report["status"] = "observing"
        from network_capture import observe
        base = observe(obs, out, 120)
        report["status"] = base["status"]
        report["error_code"] = base["error_code"]
    except Exception as exc:
        report["status"] = "stopped"
        report["error_code"] = str(exc) if isinstance(exc, obs.LabError) and re.fullmatch("[a-z0-9_]{1,100}", str(exc)) else "bounded_api_observation_failed"
    finally:
        subprocess.Popen = original_popen
        obs.fetch_setup = original_fetch
        if manager:
            manager.close()
            report.update(manager.report())
            report["requests"], report["streams"] = reconstruct(manager.inputs)
            report["tls_inputs"] = tls_summary(manager.inputs,report["reference"]["cpu_model"])
        for process in launched:
            process.close()
        validate(report)
        data = json.dumps(report, indent=2).encode()
        if len(data) > 2*1024**2:
            raise SystemExit("report_limit")
        (out / "process-birth-http-tls.json").write_bytes(data)
    print(json.dumps({"status": report["status"], "request_count": len(report["requests"]), "selftest_passed": bool(report["selftest"] and report["selftest"]["passed"])}))

if __name__ == "__main__":
    main()