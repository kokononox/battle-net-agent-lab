"""Offline analysis only: separate fixture metadata, VM reference and actual requests."""
import base64
import collections
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
sys.path.append(str(Path(__file__).resolve().parents[1] / "privacy-http"))
from analyze_recovered import decode_ocsp_get
from validate_api import validate

def main():
    src, out = map(Path, sys.argv[1:3])
    report = validate(json.loads(src.read_text()))
    out.mkdir(parents=True, exist_ok=True)
    processes = {row["pid"]: row for row in report["processes"]}
    fixture_pids = {row["pid"] for row in report["selftest"]["processes"]}
    assert report["selftest"]["passed"] and not report["fatal"]
    assert not fixture_pids.intersection(processes)
    rows, decoded_ocsp = [], []
    cpu = report["reference"]["cpu_model"]
    for index, request in enumerate(report["requests"], 1):
        assert request["pid"] not in fixture_pids
        process = processes[request["pid"]]
        assert process["authenticode_valid"] and process["expected_blizzard_publisher"]
        assert process["instrumented_before_resume"]
        body = base64.b64decode(request["body_sample_base64"], validate=True)
        headers = "\n".join(k + ": " + v for k, v in request["headers"])
        material = request["target"].encode("latin1") + headers.encode("latin1") + body
        row = {
            "request_index": index, "host": request["host"], "method": request["method"],
            "target": request["target"], "pid": request["pid"],
            "process_name": process["process_name"], "process_sha256": process["sha256"],
            "headers": json.dumps(request["headers"]),
            "body_bytes": len(body), "body_complete": request["body_complete"],
            "cpu_literal_found": bool(cpu and cpu.encode() in material),
        }
        rows.append(row)
        if request["host"] == "ocsp.digicert.com":
            der, decoded = decode_ocsp_get(request["target"])
            path = out / f"request-{index:03d}-ocsp.der"
            path.write_bytes(der)
            checked = False
            if shutil.which("openssl"):
                text = subprocess.run(["openssl", "ocsp", "-reqin", str(path), "-req_text"],
                                      capture_output=True, text=True, check=True, timeout=5).stdout
                for label, field in (
                    ("Issuer Name Hash", "issuer_name_hash_hex"),
                    ("Issuer Key Hash", "issuer_key_hash_hex"),
                    ("Serial Number", "certificate_serial_number_hex"),
                ):
                    actual = re.search(re.escape(label) + r": ([0-9A-F]+)", text)
                    assert actual and actual[1].lower() == decoded[field]
                checked = True
            decoded_ocsp.append({
                "request_index": index, "pid": request["pid"], "process_name": process["process_name"],
                **decoded, "independent_openssl_match": checked,
            })
    with (out / "requests.csv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    counts = collections.Counter(row["host"] for row in rows)
    raw = json.loads(src.read_text())
    # Independent raw checks, no reference/fixture CPU values searched as traffic.
    assert sum(counts.values()) == len(raw["requests"])
    assert all(x["method"] == "GET" for x in raw["requests"])
    assert all(x["body_observed_bytes"] == x["body_declared_bytes"] == 0 and x["body_sample_base64"] == "" for x in raw["requests"])
    assert all(x["body_complete"] and not x["body_sample_truncated"] for x in raw["requests"])
    assert not any(row["cpu_literal_found"] for row in rows)
    nydus = [r for r in rows if r["host"] == "nydus.battle.net"]
    cdn = [r for r in rows if r["host"] == "us.cdn.blizzard.com"]
    assert len(nydus) == sum(1 for x in raw["requests"] if x["host"] == "nydus.battle.net")
    assert all(row["target"] == "/geoip" for row in nydus)
    result = {
        "run_id": report["run_id"], "source_commit": report["source_commit"],
        "receipt_commit": "eb2e0c235abb13806b90f7fa0bc97fc022bc2265",
        "raw_report_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
        "native_gate_passed": report["selftest"]["passed"],
        "all_live_processes_instrumented_before_resume": all(p["instrumented_before_resume"] for p in processes.values()),
        "all_live_processes_blizzard_signed": all(p["authenticode_valid"] and p["expected_blizzard_publisher"] for p in processes.values()),
        "live_process_count": len(processes), "input_event_count": report["input_events"],
        "dropped_events": report["dropped_events"],
        "api_input_gaps": sum(row["api_input_gap"] for row in report["streams"]),
        "script_errors": sum(row["script_errors"] for row in processes.values()),
        "request_count": len(rows), "by_host": dict(counts), "request_body_bytes_total": 0,
        "cpu_literal_found_in_captured_requests": False,
        "nydus_requests": nydus, "cdn_requests": cdn,
        "ocsp_requests": decoded_ocsp,
        "all_four_preselected_http_hosts_have_captured_requests": set(counts) == {"nydus.battle.net", "level3.blizzard.com", "us.cdn.blizzard.com", "ocsp.digicert.com"},
        "limitations": [
            "Signed Setup/Agent startup only, not a full installed-client or WoW update.",
            "No response content, server delivery/storage, downloaded-file fingerprint or A-to-B test.",
            "GeoIP path indicates the requested operation; actual response and necessity for update not measured.",
            "No CPU literal/obvious hardware fields in sampled requests does not exclude opaque identifiers, other endpoints or later stages.",
            "Certificate identity and chain of the attributed OCSP request have not been determined.",
            "Async completion and concurrent send ordering can be incomplete; API observation is not server receipt.",
            "Instrumentation and child gating change timing; rejected children would alter behavior.",
            "All selected-host requests captured by this method are not a guarantee all network requests were captured.",
        ],
        "comparison_plan": [{
            "grain": "process-attributed request content and protocol classification",
            "disposition": "table",
            "reason": "Coverage counts, not a measured traffic-volume or temporal comparison.",
        }],
    }
    (out / "evidence.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k not in ("nydus_requests", "cdn_requests", "ocsp_requests", "limitations", "comparison_plan")}, indent=2))

if __name__ == "__main__":
    main()