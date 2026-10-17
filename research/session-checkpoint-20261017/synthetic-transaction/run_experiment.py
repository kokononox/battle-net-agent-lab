"""Run the isolated synthetic transaction lab; output must be a NEW directory."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import platform
import sys
import time
import unittest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-new", type=Path, required=True,
                        help="New evidence directory; NEVER a game or Lab directory")
    args = parser.parse_args()
    out = args.out_new
    if not out.is_absolute() or out.parent.resolve() != out.parent:
        parser.error("Use an absolute physical path with an existing parent")
    out.mkdir(mode=0o700, exist_ok=False)
    os.environ["SYNTHETIC_OUT_NEW"] = str(out)
    sys.dont_write_bytecode = True
    counters = {"network_audit_events": 0, "forbidden_archive_opens": 0}

    def audit(event, values):
        if event.startswith("socket."):
            counters["network_audit_events"] += 1
            raise RuntimeError("Network forbidden")
        if event == "open" and isinstance(values[0], (str, bytes)):
            path = Path(os.fsdecode(values[0])).resolve()
            mode, flags = values[1], values[2]
            write = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
            )
            if write and not path.is_relative_to(out):
                raise RuntimeError("Write outside the new experiment output forbidden")
            if path.suffix.lower() in (".zip", ".mpq", ".archive") or path.name.startswith("data."):
                counters["forbidden_archive_opens"] += 1
                raise RuntimeError("Archive opens forbidden")

    sys.addaudithook(audit)
    import test_transactions as tests
    import transaction_fixture as tx
    start = time.monotonic()
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(tests.TransactionTests)
    )
    (out / "TESTS.log").write_text(stream.getvalue())
    evidence = {
        "format": "synthetic-multifile-transaction-evidence-1",
        "success": result.wasSuccessful() and not result.skipped,
        "tests_run": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "runtime": platform.python_version(), "platform": sys.platform,
        "elapsed_seconds_observed": time.monotonic() - start,
        "fixture_files_per_generation": len(tx.NAMES),
        "fixture_bytes_per_generation": sum(map(len, tx.payloads("g1").values())),
        "crash_mechanism": "real child-process os._exit(91), NOT physical power loss",
        "storage_model": "Synthetic immutable directories and single atomic pointer; NOT CASC",
        "io_failures": "Explicit injected ENOSPC, short writes and fsync/rename errors; NOT a physically full disk or torn sector test",
        "events": tests.EVIDENCE,
        "tripwire_counters_parent_only": counters,
        "scope": {
            "archive_payload_bytes_read": 0, "network_used": False,
            "game_or_user_Lab_read_or_written": False,
            "temporary_fixtures_removed": not any(out.glob("case-*")),
            "worker_scope": "same generated fixture paths, stdlib and local experiment code only",
            "audit_hooks_are_NOT_OS_sandbox": True,
        },
        "source_sha256": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in Path(__file__).parent.glob("*.py")
        },
        "installation_ready": False, "real_install_authorized": False,
        "vendor_required_set_proven": False, "fresh_local_game_content_proven": False,
        "native_Windows_tested": False,
        "limits": [
            "Only cooperative writers are locked. This is not a sandbox against hostile processes or concurrent hostile path replacement.",
            "Linux file fsync and directory fsync were called; storage hardware power-loss behavior was not tested.",
            "Readers must capture the pointer once and retain old immutable generations. No garbage collection is implemented.",
            "A directory fsync error after pointer replace can leave g1 visible. It is NOT reported as successful or rolled back automatically.",
            "No game metadata activation, CASC archive writing, patching, downloading, vendor policy or production rollback is implemented.",
            "Full process/system crashes can have effects not represented by these selected process-exit cut points.",
        ],
    }
    if evidence["success"]:
        assert len(tests.EVIDENCE["advance_crashes"]) == len(tx.PHASES)
        assert len(tests.EVIDENCE["rollback_crashes"]) == len(tx.ROLLBACK_PHASES)
        assert len(tests.EVIDENCE["injected_io_failures"]) == 12
        assert evidence["scope"]["temporary_fixtures_removed"]
    (out / "EVIDENCE.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({key: evidence[key] for key in
                      ("success", "tests_run", "failures", "errors", "skipped",
                       "installation_ready")}))
    if not evidence["success"]:
        print(stream.getvalue())
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())