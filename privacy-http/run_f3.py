"""One-shot fresh hosted Windows startup. No paid/larger runner selection."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading

def main():
    if not (
        sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_OS") == "Windows"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
        and os.environ.get("PRIVACY_HTTP_ONCE") == "http-f3"
    ):
        raise SystemExit("fresh_hosted_once_required")
    root = Path(__file__).resolve().parents[1]
    for name in ("scripts", "privacy-network", "privacy-tls"):
        sys.path.insert(0, str(root / name))
    import observe_agent as obs
    import native_tcp
    import collect
    from samples import reference
    from capture_diagnostic import analyze_capture as parse_capture
    from validate_http import validate_capture_bounds as validate
    source, run = os.environ.get("GITHUB_SHA", ""), os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch("[0-9a-f]{40}", source) or not run.isdigit():
        raise SystemExit("identity")
    env = obs.clean_environment(os.environ)
    if obs.snapshot(env).get("processes"):
        raise SystemExit("preexisting_processes_refused")
    out = Path("output")
    out.mkdir(exist_ok=True)
    report = {
        "schema": "bnet-outgoing-http-3", "source_commit": source, "run_id": run,
        "scope": "fresh_vm_startup_language_only_no_account_game_install_action",
        "reference": reference(),
        "bootstrap_pin_match": None,
        "capture": {
            "start_code": None, "stop_code": None, "convert_code": None,
            "etl_bytes": 0, "pcapng_bytes": 0,
            "packet_size_requested": 0, "raw_packet_files_exported": False,
        },
        "sampler": {"samples": 0, "errors": 0, "flow_limit_hit": False},
        "status": "not_started", "bootstrap_status": None, "error_code": None,
        "packet_stats": {}, "flows": [], "requests": [],
        "diagnostics": {"counts": {}, "stream_statuses": {}, "parse_statuses": {}},
        "limits": {
            "server_receipt_proven": False, "user_pc_observed": False,
            "full_game_update_test": False, "responses_exported": False,
            "outgoing_known_hosts_only": True, "credential_headers_redacted": True,
            "tuple_pid_link_not_cryptographic_proof": True,
            "circular_capture_and_sampling_can_miss_data": True,
            "child_network_hard_byte_cap": False,
            "unattributed_known_host_requests_included": True,
            "zero_ip_length_capture_bounds_inference": True,
        },
    }
    original_fetch = obs.fetch_setup
    def pinned_fetch(destination):
        result = original_fetch(destination)
        report["bootstrap_pin_match"] = result["sha256"] == "de5d32d4ea5eed5a9e120027fb68b370976dbfecc8f2a8f91305977f0b87fcaf"
        if not report["bootstrap_pin_match"]:
            destination.unlink(missing_ok=True)
            raise obs.LabError("bootstrap_pin_mismatch_refused")
        return result
    obs.fetch_setup = pinned_fetch
    watcher = collect.Watcher(native_tcp.snapshot, obs.NAMES)
    thread = threading.Thread(target=watcher.run, daemon=True)
    capture = report["capture"]
    exe = Path(os.environ["SystemRoot"]) / "System32/pktmon.exe"
    try:
        with tempfile.TemporaryDirectory(prefix="http-private-", dir=os.environ["RUNNER_TEMP"]) as tmp:
            etl, pcap = Path(tmp) / "capture.etl", Path(tmp) / "capture.pcapng"
            capture["start_code"] = collect.run_tool(exe, [
                "start", "--capture", "--comp", "nics", "--pkt-size", "0",
                "--file-size", "32", "--log-mode", "circular", "--file-name", etl,
            ], env)
            if capture["start_code"] != 0:
                raise obs.LabError("capture_start_failed_no_client_launched")
            thread.start()
            try:
                base = obs.observe(out, 120, advance_language=True, advance_install=False)
                report["bootstrap_status"] = base["status"]
                report["error_code"] = base["error_code"]
            finally:
                watcher.stop.set()
                thread.join(timeout=20)
                capture["stop_code"] = collect.run_tool(exe, ["stop"], env)
            if thread.is_alive():
                raise obs.LabError("watcher_stop_timeout")
            if etl.exists():
                capture["etl_bytes"] = etl.stat().st_size
            if capture["stop_code"] != 0 or not 0 < capture["etl_bytes"] <= 64 * 1024**2:
                raise obs.LabError("capture_stop_or_etl_size_failed")
            capture["convert_code"] = collect.run_tool(exe, ["etl2pcap", etl, "--out", pcap], env, 60)
            if pcap.exists():
                capture["pcapng_bytes"] = pcap.stat().st_size
            if capture["convert_code"] != 0 or not 0 < capture["pcapng_bytes"] <= 128 * 1024**2:
                raise obs.LabError("conversion_or_pcap_size_failed")
            report.update(parse_capture(pcap, watcher.watched, allow_zero_length_capture=True))
            report["status"] = "capture_parsed"
    except Exception as exc:
        report["status"] = "stopped"
        report["error_code"] = str(exc) if isinstance(exc, obs.LabError) and re.fullmatch("[a-z0-9_]{1,100}", str(exc)) else "bounded_http_capture_failed"
    finally:
        watcher.stop.set()
        report["sampler"] = {
            "samples": watcher.samples, "errors": watcher.errors, "flow_limit_hit": watcher.limited,
        }
        validate(report)
        payload = json.dumps(report, indent=2).encode()
        if len(payload) > 2 * 1024**2:
            raise SystemExit("report_size")
        (out / "outgoing-http-f3.json").write_bytes(payload)
    print(json.dumps({"status": report["status"], "request_count": len(report["requests"]), "error_code": report["error_code"]}))

if __name__ == "__main__":
    main()