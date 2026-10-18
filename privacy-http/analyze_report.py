"""Offline, value-aware analysis of F1. Never search hardware reference as traffic."""
import base64
import csv
import hashlib
import json
from pathlib import Path
import sys
from validate_http import validate

def main():
    src, out = map(Path, sys.argv[1:])
    raw = src.read_bytes()
    report = validate(json.loads(raw))
    out.mkdir(parents=True, exist_ok=True)
    flows = {f["flow_id"]: f for f in report["flows"]}
    rows = []
    reference_cpu = report["reference"]["cpu_model"]
    for r in report["requests"]:
        body = base64.b64decode(r["body_sample_base64"], validate=True)
        # Only recorded request target, headers and body, NOT VM reference/metadata.
        material = r["target"].encode("latin1") + b"\n"
        material += "\n".join(k + ": " + v for k, v in r["headers"]).encode("latin1") + b"\n" + body
        rows.append({
            "flow_id": r["flow_id"],
            "process_name": flows[r["flow_id"]]["process_name"],
            "host": r["host"], "method": r["method"], "target": r["target"],
            "headers": json.dumps(r["headers"]),
            "body_observed_bytes": r["body_observed_bytes"],
            "body_complete": r["body_complete"],
            "cpu_model_found_in_recorded_request": bool(reference_cpu and reference_cpu.encode() in material),
        })
    # Independent raw JSON checks against derived rows.
    raw_requests = json.loads(raw)["requests"]
    assert len(rows) == len(raw_requests)
    assert sum(x["body_observed_bytes"] for x in rows) == sum(len(base64.b64decode(x["body_sample_base64"])) for x in raw_requests)
    assert all(hashlib.sha256(base64.b64decode(x["body_sample_base64"])).hexdigest() == x["body_sample_sha256"] for x in raw_requests)
    assert all(x["body_complete"] and not x["body_sample_truncated"] for x in raw_requests)
    with (out / "requests.csv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["host"])
        writer.writeheader()
        writer.writerows(rows)
    finding = {
        "run_id": report["run_id"], "source_commit": report["source_commit"],
        "receipt_commit": "411d9f0125a477284f8ca1ef318ca3435f32df52",
        "raw_report_sha256": hashlib.sha256(raw).hexdigest(),
        "status": report["status"], "error_code": report["error_code"],
        "captured_request_count": len(rows),
        "hosts_with_complete_request_evidence": sorted({x["host"] for x in rows}),
        "no_complete_request_evidence": sorted({
            "nydus.battle.net", "us.cdn.blizzard.com", "ocsp.digicert.com",
        } - {x["host"] for x in rows}),
        "requests": rows,
        "recorded_request_body_bytes_total": sum(x["body_observed_bytes"] for x in rows),
        "cpu_model_found_in_recorded_requests": any(x["cpu_model_found_in_recorded_request"] for x in rows),
        "important_caveats": [
            "Only observed requests, not all requests or destinations are covered.",
            "Resource paths and byte ranges describe requested content, not necessarily unique hardware IDs.",
            "Opaque 32-hex path values are not proof of per-machine fingerprinting or proof against it.",
            "No response payload or server-side storage analysis.",
            "No game update, A-to-B test or user-PC observation.",
            "Empty captured streams do not prove an endpoint was silent or clean.",
        ],
        "comparison_plan": [{
            "disposition": "prose",
            "reason": "Three diagnostic requests, no comparable traffic-volume population.",
        }],
    }
    (out / "evidence.json").write_text(json.dumps(finding, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in finding.items() if k not in ("requests", "important_caveats", "comparison_plan")}, indent=2))

if __name__ == "__main__":
    main()