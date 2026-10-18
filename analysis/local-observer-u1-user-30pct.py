import collections
import hashlib
import json
from pathlib import Path

base = Path("/data/raw/user-u1-30pct")
out = Path("/data/analysis/user-u1-30pct")
raw = base / "report-20261018T224239Z.json"
r = json.loads(raw.read_text())
o = r["observation"]
events = o["events"]
grouped = collections.Counter(
    (e["host_hint"], e["api"], e["local_api_success"],
     e["reference_cpu_literal_match"] is True) for e in events
)
reported = collections.Counter()
for a in o["aggregate_inputs"]:
    reported[(a["host_hint"], a["api"], a["local_api_success"],
              a["cpu_literal_match"])] += a["input_events"]
assert grouped == reported
assert len(events) == sum(p["input_events"] for p in o["processes"])
cpu_hits = sum(e["reference_cpu_literal_match"] is True for e in events)
assert cpu_hits == sum(a["input_events"] for a in o["aggregate_inputs"]
                       if a["cpu_literal_match"])
assert len(events) == 1407
hosts = sorted({e["host_hint"] for e in events if e["host_hint"]})
evidence = {
    "source": {"report_filename": raw.name,
               "report_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
               "console_sha256": hashlib.sha256((base / "console.txt").read_bytes()).hexdigest(),
               "provenance": "user-uploaded, not independently observed or signed",
               "reported_started_utc": r["started_utc"]},
    "user_statement": {"download_progress_percent": 30,
                       "independently_measured": False},
    "report_status": r["status"],
    "user_final_state": r["user_final_state"],
    "mode": r["mode"],
    "ready": r["ready_was_announced"],
    "initial_versions": r["initial_versions"],
    "final_versions": r["final_versions"],
    "hosts": r["hosts"],
    "events": len(events),
    "cpu_reference_available": r["cpu_reference_available"],
    "cpu_literal_hits": cpu_hits,
    "telemetry_host_hint_events": sum(e["host_hint"] == "telemetry-in.battle.net" for e in events),
    "host_hints": hosts,
    "phase_counts": dict(collections.Counter(e["phase"] for e in events)),
    "successful_sspi_inputs": sum(e["api"] == "EncryptMessage" and e["local_api_success"] for e in events),
    "elapsed_event_range_seconds": [min(e["elapsed_seconds"] for e in events), max(e["elapsed_seconds"] for e in events)],
    "aggregate_inputs": o["aggregate_inputs"],
    "attached_processes": sum(p["status"] == "attached" for p in o["processes"]),
    "agent_processes": [p for p in o["processes"] if p["process_name"] == "agent.exe"],
    "script_errors": sum(p["script_errors"] for p in o["processes"]),
    "sampler_errors": o["sampler_errors"],
    "limits_hit": o["limits_hit"],
    "all_late_attach": all(p["late_attach"] for p in o["processes"]),
    "cpu_negative_not_zero_telemetry": True,
    "whole_update_completion_proven": False,
    "checks": {"schema_validator": "VALID",
               "event_aggregate_counts_reconciled": True,
               "process_event_counts_reconciled": True,
               "cpu_count_independently_reconciled": True},
    "profile_warning_resolution": "Nested single-report JSON was incorrectly flattened into 42 pseudo-rows by general profiler. Analysis uses explicit observation.events / processes arrays. Flattening duplicate/null/constant warnings are not missing samples or records to deduplicate. No events dropped or deduplicated.",
    "visual_plan": {"disposition": "prose", "reason": "Diagnostic gate result, coverage limitations and version markers, not a quantitative comparative or trend question. Host counts are API-input observations, not traffic volumes or uploads."},
}
(out / "evidence.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({k: evidence[k] for k in (
    "events", "cpu_literal_hits", "telemetry_host_hint_events",
    "successful_sspi_inputs", "attached_processes", "script_errors", "sampler_errors",
    "phase_counts", "checks")}, indent=2))