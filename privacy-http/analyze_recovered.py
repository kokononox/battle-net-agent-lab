"""Offline F4 request analysis and strict decoding of the observed OCSP GET form."""
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
import urllib.parse
from validate_http import validate_prefix_capture

def children(raw):
    values = []
    pos = 0
    while pos < len(raw):
        if pos + 2 > len(raw):
            raise ValueError("der_header")
        tag, length = raw[pos:pos+2]
        pos += 2
        if length & 128:
            width = length & 127
            if not 1 <= width <= 4 or pos + width > len(raw):
                raise ValueError("der_length")
            length = int.from_bytes(raw[pos:pos+width], "big")
            pos += width
        if pos + length > len(raw):
            raise ValueError("der_bounds")
        values.append((tag, raw[pos:pos+length]))
        pos += length
    return values

def one_sequence(raw):
    result = children(raw)
    if len(result) != 1 or result[0][0] != 0x30:
        raise ValueError("unexpected_sequence")
    return result[0][1]

def decode_ocsp_get(target):
    # Match the simple request shape actually seen, rejecting optional/unknown fields.
    der = base64.b64decode(urllib.parse.unquote(target[1:]), validate=True)
    if not 0 < len(der) <= 4096:
        raise ValueError("request_size")
    ocsp = one_sequence(der)
    tbs = one_sequence(ocsp)  # only tbsRequest; optionalSignature is absent
    request_list = one_sequence(tbs)  # version, requestorName, extensions are absent
    request = one_sequence(request_list)  # one Request
    cert_id = one_sequence(request)  # only reqCert, no singleRequestExtensions
    fields = children(cert_id)
    if [tag for tag, _ in fields] != [0x30, 0x04, 0x04, 0x02]:
        raise ValueError("not_simple_cert_id")
    algorithm = children(fields[0][1])
    if algorithm != [(0x06, bytes.fromhex("2b0e03021a")), (0x05, b"")]:
        raise ValueError("unexpected_hash_algorithm")
    if len(fields[1][1]) != 20 or len(fields[2][1]) != 20 or not 1 <= len(fields[3][1]) <= 32:
        raise ValueError("cert_id_lengths")
    return der, {
        "der_bytes": len(der), "der_sha256": hashlib.sha256(der).hexdigest(),
        "hash_algorithm_oid": "1.3.14.3.2.26",
        "issuer_name_hash_hex": fields[1][1].hex(),
        "issuer_key_hash_hex": fields[2][1].hex(),
        "certificate_serial_number_hex": fields[3][1].hex(),
        "requestor_name_present": False, "signature_present": False,
        "request_extensions_present": False, "single_request_extensions_present": False,
        "decoded_schema": "OCSPRequest/TBSRequest/requestList/Request/CertID",
    }

def main():
    src, out = map(Path, sys.argv[1:])
    report = validate_prefix_capture(json.loads(src.read_text()))
    out.mkdir(parents=True, exist_ok=True)
    flows = {f["flow_id"]: f for f in report["flows"]}
    records, ocsp = [], []
    openssl_checks = []
    cpu = report["reference"]["cpu_model"]
    header_names = collections.defaultdict(set)
    for index, request in enumerate(report["requests"], 1):
        flow = flows[request["flow_id"]]
        body = base64.b64decode(request["body_sample_base64"], validate=True)
        raw = request["target"].encode("latin1")
        raw += b"\n" + "\n".join(k + ": " + v for k, v in request["headers"]).encode("latin1") + body
        header_names[request["host"]].update(k for k, _ in request["headers"])
        records.append({
            "request_index": index, "host": request["host"],
            "method": request["method"], "target": request["target"],
            "flow_id": request["flow_id"], "attribution": flow["attribution"],
            "process_name": flow["process_name"], "stream_status": flow["stream_status"],
            "body_bytes": len(body), "body_complete": request["body_complete"],
            "cpu_literal_match": bool(cpu and cpu.encode() in raw),
        })
        if request["host"] == "ocsp.digicert.com":
            der, decoded = decode_ocsp_get(request["target"])
            der_path = out / f"request-{index:02d}-ocsp.der"
            der_path.write_bytes(der)
            if shutil.which("openssl"):
                text = subprocess.run(
                    ["openssl", "ocsp", "-reqin", str(der_path), "-req_text"],
                    check=True, capture_output=True, text=True, timeout=5,
                ).stdout
                for label, field in [
                    ("Issuer Name Hash", "issuer_name_hash_hex"),
                    ("Issuer Key Hash", "issuer_key_hash_hex"),
                    ("Serial Number", "certificate_serial_number_hex"),
                ]:
                    value = re.search(re.escape(label) + r": ([0-9A-F]+)", text)
                    assert value and value[1].lower() == decoded[field]
                assert "Hash Algorithm: sha1" in text
                openssl_checks.append(index)
            ocsp.append({
                "request_index": index, "attribution": flow["attribution"],
                "process_name": flow["process_name"],
                **decoded,
            })
    counts = collections.Counter(x["host"] for x in records)
    # Independent raw checks; do not search hardware reference JSON as network payload.
    raw_rows = json.loads(src.read_text())["requests"]
    assert sum(counts.values()) == len(raw_rows)
    assert all(x["method"] == "GET" for x in raw_rows)
    assert all(x["body_complete"] and not x["body_sample_truncated"] for x in raw_rows)
    assert all(x["body_declared_bytes"] == x["body_observed_bytes"] == 0 and x["body_sample_base64"] == "" for x in raw_rows)
    assert len(ocsp) == sum(x["host"] == "ocsp.digicert.com" for x in raw_rows)
    assert all(not x["cpu_literal_match"] for x in records)
    assert all(not f["stream_status"].endswith("_capture_bounds") for f in flows.values())
    attribution = collections.Counter(x["attribution"] for x in records)
    assert attribution["sampled_tcp_tuple"] == report["diagnostics"]["counts"]["known_host_requests_with_pid"]
    assert attribution["unattributed"] == report["diagnostics"]["counts"]["known_host_requests_without_pid"]
    with (out / "requests.csv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    result = {
        "run_id": report["run_id"], "source_commit": report["source_commit"],
        "receipt_commit": "1f2bdbda9c25a8ee1d644a85b822ff2b168d1cc2",
        "raw_report_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
        "request_count": len(records), "by_host": dict(counts),
        "by_attribution": dict(attribution), "body_bytes_total": sum(x["body_bytes"] for x in records),
        "cpu_literal_found_in_recorded_requests": any(x["cpu_literal_match"] for x in records),
        "hardware_schema_in_simple_ocsp_requests": False,
        "header_names_by_host": {h: sorted(v) for h, v in header_names.items()},
        "ocsp_requests": ocsp,
        "requests": records,
        "remaining_without_complete_request": ["nydus.battle.net", "us.cdn.blizzard.com"],
        "no_known_host_request_depended_on_zero_ip_length_inference": True,
        "ocsp_process_attribution_unknown": all(x["attribution"] == "unattributed" for x in ocsp),
        "independent_openssl_decoding": {"available": bool(shutil.which("openssl")), "verified_request_indices": openssl_checks},
        "certificate_chain_identity_not_established": True,
        "caveats": [
            "All requests are VM observations, not a full WoW update or user-PC test.",
            "OCSP may have originated from observer signature verification or other Windows processes; sender not proven.",
            "Certificate identities/chains and whether the certificates are shared or device-specific have not been established.",
            "Zero HTTP body does not mean zero information sent; OCSP CertID is encoded in URL.",
            "No CPU literal match is not proof against opaque identifiers or telemetry elsewhere.",
            "No server delivery/storage, response-content, downloaded-file personalization, or A-to-B conclusion.",
            "Two streams have later gaps; complete HTTP requests before a gap are not a complete flow.",
            "Per-packet prefix truncation and sampling leave coverage gaps.",
        ],
        "standard_used": "https://www.rfc-editor.org/rfc/rfc6960",
        "comparison_plan": [{
            "grain": "captured request content and protocol classification",
            "disposition": "prose",
            "reason": "Coverage counts are diagnostic, not comparable destination traffic volumes.",
        }],
    }
    (out / "evidence.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k not in ("requests", "ocsp_requests", "caveats", "comparison_plan")}, indent=2))

if __name__ == "__main__":
    main()