import base64
import hashlib
import json
from pathlib import Path
import re
import sys

HOSTS = {"nydus.battle.net", "us.cdn.blizzard.com", "level3.blizzard.com", "ocsp.digicert.com"}
APIS = {"send", "WSASend", "connect", "WSAConnect", "closesocket"}
NAMES = {"agent.exe", "battle.net.exe", "battle.net launcher.exe", "battle.net-setup.exe", "battle.net helper.exe", "blizzarderror.exe"}

def exact(d, fields):
    if type(d) is not dict or set(d) != set(fields.split()):
        raise ValueError("schema")

def integer(n, maximum=2**40):
    if type(n) is not int or not 0 <= n <= maximum:
        raise ValueError("integer")

def boolean(n):
    if type(n) is not bool:
        raise ValueError("boolean")

def process(row, synthetic=False):
    exact(row, "pid parent_pid process_name sha256 image_bytes authenticode_valid expected_blizzard_publisher status phase error_kind hook_ready child_gating_enabled instrumented_before_resume installed_hooks input_events script_errors")
    integer(row["pid"], 2**32-1)
    if row["parent_pid"] is not None:
        integer(row["parent_pid"], 2**32-1)
    if row["process_name"] is not None and not (
        row["process_name"] in NAMES or synthetic and re.fullmatch("python(?:[0-9.]+)?(?:_d)?\\.exe", row["process_name"])
    ):
        raise ValueError("process_name")
    if row["sha256"] is not None and not re.fullmatch("[a-f0-9]{64}", row["sha256"]):
        raise ValueError("image_hash")
    integer(row["image_bytes"], 128*1024**2)
    for key in ("authenticode_valid", "expected_blizzard_publisher", "hook_ready", "child_gating_enabled", "instrumented_before_resume"):
        boolean(row[key])
    for key in ("input_events", "script_errors"):
        integer(row[key])
    if row["status"] not in ("paused", "resumed", "refused_or_failed"):
        raise ValueError("process_status")
    if row["phase"] not in ("verify", "attach", "child_gating", "script_load", "resume", "observing"):
        raise ValueError("phase")
    if row["error_kind"] is not None and not re.fullmatch("[A-Za-z_]{1,64}", row["error_kind"]):
        raise ValueError("error_kind")
    if type(row["installed_hooks"]) is not list or not set(row["installed_hooks"]) <= APIS:
        raise ValueError("hooks")
    if row["status"] == "resumed":
        if not all(row[k] for k in ("hook_ready", "child_gating_enabled", "instrumented_before_resume")):
            raise ValueError("resumed_without_gate")
        if not synthetic and not (row["authenticode_valid"] and row["expected_blizzard_publisher"] and row["sha256"]):
            raise ValueError("resumed_without_signature")

def validate(r):
    exact(r, "schema source_commit run_id scope tool_version reference selftest bootstrap_pin_match processes streams requests input_events dropped_events fatal status error_code limits")
    if r["schema"] != "bnet-process-birth-http-1" or r["scope"] != "fresh_vm_root_child_gate_no_login_game_install_action" or r["tool_version"] != "17.24.2":
        raise ValueError("scope")
    if not re.fullmatch("[a-f0-9]{40}", r["source_commit"]) or not re.fullmatch("[0-9]{1,30}", r["run_id"]):
        raise ValueError("identity")
    exact(r["reference"], "cpu_model windows_build total_physical_memory_bytes logical_processors")
    cpu = r["reference"]["cpu_model"]
    if cpu is not None and (type(cpu) is not str or len(cpu) > 160 or not all(32 <= ord(x) <= 126 for x in cpu)):
        raise ValueError("cpu")
    for k in ("windows_build", "total_physical_memory_bytes", "logical_processors"):
        if r["reference"][k] is not None:
            integer(r["reference"][k], 2**50)
    if r["selftest"] is not None:
        s = r["selftest"]
        exact(s, "passed stage loopback_only synthetic_events_excluded_from_real_evidence root_first_request child_first_request split_request vector_request send_observed wsasend_observed child_gating_proven processes")
        for k in set(s) - {"stage", "processes"}:
            boolean(s[k])
        if not s["loopback_only"] or not s["synthetic_events_excluded_from_real_evidence"]:
            raise ValueError("synthetic_scope")
        if not re.fullmatch("[a-z_]{1,80}", s["stage"]):
            raise ValueError("selftest_stage")
        if type(s["processes"]) is not list or len(s["processes"]) > 9:
            raise ValueError("test_processes")
        for row in s["processes"]:
            process(row, synthetic=True)
        if s["passed"] and not all(s[k] for k in (
            "root_first_request", "child_first_request", "split_request", "vector_request",
            "send_observed", "wsasend_observed", "child_gating_proven",
        )):
            raise ValueError("selftest_false_pass")
    if r["bootstrap_pin_match"] is not None:
        boolean(r["bootstrap_pin_match"])
    if type(r["processes"]) is not list or len(r["processes"]) > 9:
        raise ValueError("processes")
    processes = {}
    for row in r["processes"]:
        process(row)
        if row["pid"] in processes:
            raise ValueError("duplicate_pid")
        processes[row["pid"]] = row
    if processes and not (r["selftest"] and r["selftest"]["passed"] and r["bootstrap_pin_match"]):
        raise ValueError("real_client_without_selftest")
    for k in ("input_events", "dropped_events"):
        integer(r[k])
    boolean(r["fatal"])
    if r["status"] not in ("not_started", "selftest", "observing", "stopped", "agent_process_observed", "bootstrapper_observed_agent_not_observed"):
        raise ValueError("status")
    if r["error_code"] is not None and not re.fullmatch("[a-z0-9_]{1,100}", r["error_code"]):
        raise ValueError("error_code")
    if type(r["streams"]) is not list or len(r["streams"]) > 512:
        raise ValueError("streams")
    for row in r["streams"]:
        exact(row, "pid socket parse_status api_input_gap")
        if row["pid"] not in processes or not re.fullmatch("s[0-9]{1,6}", row["socket"]):
            raise ValueError("stream_identity")
        if not re.fullmatch("[a-z_]{1,80}", row["parse_status"]):
            raise ValueError("parser")
        boolean(row["api_input_gap"])
    if type(r["requests"]) is not list or len(r["requests"]) > 128:
        raise ValueError("requests")
    total = 0
    for row in r["requests"]:
        exact(row, "pid process_sha256 socket host method target headers body_declared_bytes body_observed_bytes body_complete body_sample_truncated body_sample_base64 body_sample_sha256 observed_body_sha256")
        p = processes.get(row["pid"])
        if not p or p["status"] != "resumed" or row["process_sha256"] != p["sha256"] or row["host"] not in HOSTS or not re.fullmatch("s[0-9]{1,6}", row["socket"]):
            raise ValueError("request_source")
        if row["method"] not in {"GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"}:
            raise ValueError("method")
        if type(row["target"]) is not str or not 0 < len(row["target"]) <= 4096 or any(ord(x) <= 32 or ord(x) == 127 for x in row["target"]):
            raise ValueError("target")
        if type(row["headers"]) is not list or len(row["headers"]) > 256:
            raise ValueError("headers")
        for pair in row["headers"]:
            if type(pair) is not list or len(pair) != 2:
                raise ValueError("header")
            k, value = pair
            if not re.fullmatch("[!#$%&'*+.^_`|~0-9a-z-]+", k) or type(value) is not str or len(value) > 16384 or any(ord(x) < 32 and x != "\t" for x in value) or "\x7f" in value:
                raise ValueError("header_value")
            if k in {"authorization", "proxy-authorization", "cookie", "set-cookie"} and value != "[REDACTED]":
                raise ValueError("credential_header")
        for k in ("body_declared_bytes", "body_observed_bytes"):
            if row[k] is not None:
                integer(row[k], 10**10)
        for k in ("body_complete", "body_sample_truncated"):
            boolean(row[k])
        raw = base64.b64decode(row["body_sample_base64"], validate=True)
        total += len(raw) + len(str(row["headers"])) + len(row["target"])
        if len(raw) > 65536 or total > 1048576 or hashlib.sha256(raw).hexdigest() != row["body_sample_sha256"]:
            raise ValueError("body_sample")
        if not re.fullmatch("[a-f0-9]{64}", row["observed_body_sha256"]):
            raise ValueError("body_hash")
    expected = {
        "server_receipt_proven": False, "user_pc_observed": False, "full_update_test": False,
        "known_hosts_only": True, "credential_headers_redacted": True,
        "api_input_not_network_delivery": True, "async_completion_not_observed": True,
        "concurrent_send_order_can_be_ambiguous": True, "instrumentation_changes_timing": True,
        "no_tls_verification_change": True, "no_send_arguments_or_return_values_modified": True,
        "children_not_verified_are_refused": True, "child_network_hard_byte_cap": False,
        "bounded_capture_can_miss_data": True,
    }
    if r["limits"] != expected:
        raise ValueError("limits")
    return r

if __name__ == "__main__":
    src, dst = map(Path, sys.argv[1:])
    if src.stat().st_size > 2*1024**2:
        raise SystemExit("report_size")
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate_key")
            d[k] = v
        return d
    data = validate(json.loads(src.read_text(encoding="utf-8"), object_pairs_hook=unique))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")