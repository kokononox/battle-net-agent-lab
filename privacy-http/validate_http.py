"""Strict value-capable schema; export only designated disposable-VM HTTP."""
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from http_capture import HOSTS, SECRET_HEADERS

def exact(value, names):
    if type(value) is not dict or set(value) != set(names.split()):
        raise ValueError("schema")

def number(v, maximum=2**40):
    if type(v) is not int or not 0 <= v <= maximum:
        raise ValueError("number")

def validate(r, diagnostic=False):
    exact(r, "schema source_commit run_id scope reference bootstrap_pin_match capture sampler status bootstrap_status error_code packet_stats flows requests limits" + (" diagnostics" if diagnostic else ""))
    if r["schema"] != ("bnet-outgoing-http-2" if diagnostic else "bnet-outgoing-http-1") or r["scope"] != "fresh_vm_startup_language_only_no_account_game_install_action":
        raise ValueError("scope")
    if not re.fullmatch("[a-f0-9]{40}", r["source_commit"]) or not re.fullmatch("[0-9]{1,30}", r["run_id"]):
        raise ValueError("identity")
    exact(r["reference"], "cpu_model windows_build total_physical_memory_bytes logical_processors")
    cpu = r["reference"]["cpu_model"]
    if cpu is not None and (type(cpu) is not str or len(cpu) > 160 or not all(32 <= ord(c) <= 126 for c in cpu)):
        raise ValueError("cpu")
    for k in ("windows_build", "total_physical_memory_bytes", "logical_processors"):
        if r["reference"][k] is not None:
            number(r["reference"][k], 2**50)
    if r["bootstrap_pin_match"] is not None and type(r["bootstrap_pin_match"]) is not bool:
        raise ValueError("pin")
    c = r["capture"]
    exact(c, "start_code stop_code convert_code etl_bytes pcapng_bytes packet_size_requested raw_packet_files_exported")
    for k in ("start_code", "stop_code", "convert_code"):
        if c[k] is not None and (type(c[k]) is not int or not -2**31 <= c[k] <= 2**32):
            raise ValueError("code")
    for k in ("etl_bytes", "pcapng_bytes"):
        number(c[k])
    if c["packet_size_requested"] != 0 or c["raw_packet_files_exported"] is not False:
        raise ValueError("capture")
    if r["status"] not in ("not_started", "stopped", "capture_parsed"):
        raise ValueError("status")
    if r["bootstrap_status"] not in (None, "stopped", "agent_process_observed", "bootstrapper_observed_agent_not_observed"):
        raise ValueError("bootstrap_status")
    if r["error_code"] is not None and not re.fullmatch("[a-z0-9_]{1,100}", r["error_code"]):
        raise ValueError("error")
    exact(r["sampler"], "samples errors flow_limit_hit")
    for k in ("samples", "errors"):
        number(r["sampler"][k])
    if type(r["sampler"]["flow_limit_hit"]) is not bool:
        raise ValueError("sampler")
    if type(r["packet_stats"]) is not dict or not set(r["packet_stats"]) <= {
        "packets", "truncated_packets", "unparsed_block_types", "tcp_parse_errors",
        "flow_limit_hit", "memory_limit_hit", "export_limit_hit",
    }:
        raise ValueError("stats")
    for value in r["packet_stats"].values():
        number(value)
    if type(r["flows"]) is not list or len(r["flows"]) > 128:
        raise ValueError("flows")
    ids = set()
    for f in r["flows"]:
        exact(f, "flow_id process_name pid remote_address stream_status parse_status" + (" attribution" if diagnostic else ""))
        number(f["flow_id"], 128)
        if f["flow_id"] in ids:
            raise ValueError("duplicate_flow")
        ids.add(f["flow_id"])
        unattributed = diagnostic and f["attribution"] == "unattributed"
        if diagnostic and f["attribution"] not in ("unattributed", "sampled_tcp_tuple"):
            raise ValueError("attribution")
        if unattributed:
            if f["pid"] is not None or f["process_name"] is not None:
                raise ValueError("unknown_process_identity")
        else:
            number(f["pid"], 2**32-1)
            if f["process_name"] not in {"agent.exe", "battle.net.exe", "battle.net launcher.exe", "battle.net-setup.exe", "battle.net helper.exe", "blizzarderror.exe"}:
                raise ValueError("process")
        if not ipaddress.ip_address(f["remote_address"]).is_global:
            raise ValueError("address")
        for k in ("stream_status", "parse_status"):
            if not re.fullmatch("[a-z_]{1,80}", f[k]):
                raise ValueError("parse_status")
    if type(r["requests"]) is not list or len(r["requests"]) > 64:
        raise ValueError("requests")
    total = 0
    for row in r["requests"]:
        exact(row, "flow_id host method target headers body_declared_bytes body_observed_bytes body_complete body_sample_truncated body_sample_base64 body_sample_sha256 observed_body_sha256")
        if row["flow_id"] not in ids or row["host"] not in HOSTS:
            raise ValueError("request_identity")
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
            if type(k) is not str or not re.fullmatch("[!#$%&'*+.^_`|~0-9a-z-]+", k):
                raise ValueError("header_name")
            if type(value) is not str or len(value) > 16384 or any(ord(x) < 32 and x != "\t" for x in value) or "\x7f" in value:
                raise ValueError("header_value")
            if k in SECRET_HEADERS and value != "[REDACTED]":
                raise ValueError("credential_header")
        if len(str(row["headers"])) > 32768:
            raise ValueError("headers_size")
        for k in ("body_declared_bytes", "body_observed_bytes"):
            if row[k] is not None:
                number(row[k], 10**10)
        for k in ("body_complete", "body_sample_truncated"):
            if type(row[k]) is not bool:
                raise ValueError("flag")
        raw = base64.b64decode(row["body_sample_base64"], validate=True)
        total += len(raw) + len(str(row["headers"])) + len(row["target"])
        if len(raw) > 65536 or total > 524288 or hashlib.sha256(raw).hexdigest() != row["body_sample_sha256"]:
            raise ValueError("sample")
        if not re.fullmatch("[a-f0-9]{64}", row["observed_body_sha256"]):
            raise ValueError("body_hash")
        if len(raw) == row["body_observed_bytes"] and row["observed_body_sha256"] != row["body_sample_sha256"]:
            raise ValueError("body_hash_mismatch")
    expected = {
        "server_receipt_proven": False, "user_pc_observed": False,
        "full_game_update_test": False, "responses_exported": False,
        "outgoing_known_hosts_only": True, "credential_headers_redacted": True,
        "tuple_pid_link_not_cryptographic_proof": True,
        "circular_capture_and_sampling_can_miss_data": True, "child_network_hard_byte_cap": False,
    }
    if diagnostic:
        expected["unattributed_known_host_requests_included"] = True
        from capture_diagnostic import DIAG_KEYS
        exact(r["diagnostics"], "counts stream_statuses parse_statuses")
        d = r["diagnostics"]
        if type(d["counts"]) is not dict or not set(d["counts"]) <= DIAG_KEYS:
            raise ValueError("diagnostic_counts")
        for value in d["counts"].values():
            number(value)
        for category in ("stream_statuses", "parse_statuses"):
            if type(d[category]) is not dict or len(d[category]) > 64:
                raise ValueError("diagnostic_status")
            for key, value in d[category].items():
                if not re.fullmatch("[a-z_]{1,80}", key):
                    raise ValueError("diagnostic_key")
                number(value)
        if d["counts"].get("known_host_requests", 0) != len(r["requests"]):
            raise ValueError("diagnostic_request_count")
        if d["counts"].get("known_host_requests_with_pid", 0) + d["counts"].get("known_host_requests_without_pid", 0) != len(r["requests"]):
            raise ValueError("diagnostic_attribution_count")
    if r["limits"] != expected:
        raise ValueError("limits")
    return r

def validate_diagnostic(r):
    return validate(r, diagnostic=True)

if __name__ == "__main__":
    src, dst = map(Path, sys.argv[1:])
    if src.stat().st_size > 2 * 1024**2:
        raise SystemExit("report_size")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("duplicate_key")
            result[k] = v
        return result
    parsed = json.loads(src.read_text(encoding="utf-8"), object_pairs_hook=unique)
    data = validate(parsed, diagnostic=parsed.get("schema") == "bnet-outgoing-http-2")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")