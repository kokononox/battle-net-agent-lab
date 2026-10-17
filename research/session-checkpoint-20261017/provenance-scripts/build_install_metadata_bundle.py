"""Build/test the bounded Install observation bundle without real user inputs."""
from pathlib import Path
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

SOURCE = Path("/data/install-metadata-review-1")
LAB = Path("/data/lab")
AUDIT = Path("/data/retail-release-extracted/Portable-Retail-Sample/pinned_metadata")
OUT = Path("/data/install-metadata-delivery-1")


def main():
    OUT.mkdir(exist_ok=False)
    tests_out = OUT / "private-synthetic-tests"
    tests_out.mkdir()
    os.environ["INSTALL_TEST_OUT"] = str(tests_out)
    sys.dont_write_bytecode = True
    for path in (LAB, LAB / "local_review_tests", SOURCE):
        sys.path.insert(0, str(path))
    import test_saved_install_review as tests
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(tests))
    log = stream.getvalue()
    (OUT / "TESTS.log").write_text(log)
    assert result.wasSuccessful() and not result.skipped
    assert result.testsRun == 36
    assert list(tests_out.iterdir()) == []
    tests_out.rmdir()

    members = {}
    for name in ("saved_install_review.py", "saved_install_launcher.py", "CHECK-SAVED-INSTALL.cmd", "README-fa.md"):
        members[name] = (SOURCE / name).read_bytes()
    members["CHECK-SAVED-INSTALL.cmd"] = members["CHECK-SAVED-INSTALL.cmd"].replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    for name in ("source_binding.py", "installed_profile_probe.py", "patch_audit.py", "cdn_catalog.py"):
        members[name] = (LAB / name).read_bytes()
    for name in ("build.config", *(f"manifest.pa.base64.part{i}" for i in range(3))):
        members["pinned_metadata/" + name] = (AUDIT / name).read_bytes()

    isolated = OUT / "isolated-runtime"
    isolated.mkdir()
    for name, raw in members.items():
        path = isolated / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    help_run = subprocess.run(
        [sys.executable, "-B", str(isolated / "saved_install_review.py"), "--help"],
        cwd=isolated, env=env, capture_output=True, text=True, timeout=20)
    assert help_run.returncode == 0 and not help_run.stderr and "--out-new" in help_run.stdout

    # Standalone production-pin CLI with generated Lab/game and absent Install.
    # No repository PYTHONPATH, no real user cache or archive contents.
    fixture_out = OUT / "private-isolated-fixture"
    fixture_out.mkdir()
    os.environ["INSTALL_TEST_OUT"] = str(fixture_out)
    fixture = tests.Integration("test_production_missing_cache_bound_report")
    tests.Integration.setUpClass()
    fixture.setUp()
    try:
        before = tests.source_snapshot(fixture.f.lab), tests.source_snapshot(fixture.game)
        report_out = OUT / "isolated-report"
        run = subprocess.run(
            [sys.executable, "-B", str(isolated / "saved_install_review.py"),
             "--lab", str(fixture.f.lab), "--audit-dir", str(isolated / "pinned_metadata"),
             "--game-root", str(fixture.game), "--out-new", str(report_out)],
            cwd=isolated, env=env, capture_output=True, text=True, timeout=120)
        report = json.loads(run.stdout)
        assert run.returncode == 0 and not run.stderr
        assert report["status"] == "bound_install_metadata_unavailable"
        assert report["scope"]["saved_install_metadata_bytes_read"] == 0
        assert report["scope"]["archive_payload_bytes_read"] == 0
        assert json.loads((report_out / "INSTALL-REVIEW-to-share.json").read_text()) == report
        assert before == (tests.source_snapshot(fixture.f.lab), tests.source_snapshot(fixture.game))
        assert str(fixture.root) not in run.stdout and "PRIVATE" not in run.stdout
        (OUT / "ISOLATED-CLI.json").write_text(run.stdout)
    finally:
        fixture.tearDown()
    assert list(fixture_out.iterdir()) == []
    fixture_out.rmdir()

    results = {
        "format": "saved-install-review-test-results-1",
        "version": "saved-install-review-1",
        "tests_run": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "tests_are_new_suite_NOT_reexecution_of_historical_568": True,
        "runtime": sys.version.split()[0], "platform": sys.platform,
        "successful_cache_tests": "explicit synthetic descriptor substitutions only; NOT real user Install bytes",
        "production_pin_rejects_synthetic_24078_byte_file": True,
        "production_pin_absent_cache_standalone_CLI": True,
        "isolated_CLI_repository_PYTHONPATH_removed": True,
        "isolated_runtime_files_match_bundle_members": True,
        "CLI_help_passed": True,
        "raw_install_max_bytes": 24078, "raw_install_max_passes": 1,
        "observed_exact_read_size_test": [24078],
        "Download_or_Encoding_raw_cache_read": False,
        "archive_payload_bytes_read_by_tool": 0, "network_requests": 0,
        "user_game_or_Lab_accessed": False, "synthetic_inputs_unchanged": True,
        "private_synthetic_fixtures_removed": True,
        "no_existing_sources_modified": True,
        "Windows_publication_branch_modeled_only": True,
        "native_Windows_executed": False, "actual_user_Install_tested_here": False,
        "Install_semantic_parser_validated": False, "vendor_install_policy_proven": False,
        "installation_ready": False, "required_network_download_bytes": None,
        "test_source_sha256": hashlib.sha256((SOURCE / "test_saved_install_review.py").read_bytes()).hexdigest(),
        "runtime_files_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()},
    }
    results_raw = (json.dumps(results, ensure_ascii=False, indent=2) + "\n").encode()
    (OUT / "TEST-RESULTS.json").write_bytes(results_raw)
    members["TEST-RESULTS.json"] = results_raw
    members["TESTS.log"] = log.encode()
    manifest = {
        "format": "readonly-saved-install-bundle-1", "version": "saved-install-review-1",
        "only_exact_install_cache_content": True, "raw_install_max_bytes": 24078,
        "network_or_archive_payload_allowed": False, "installation_ready": False,
        "files": {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                  for name, raw in members.items()},
    }
    members["BUNDLE-MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    bundle = OUT / "Saved-Install-Review-v1.zip"
    with zipfile.ZipFile(bundle, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(members.items()):
            archive.writestr("Saved-Install-Review-v1/" + name, raw)
    checksum = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (OUT / "BUNDLE-SHA256.txt").write_text(checksum + "  " + bundle.name + "\n")
    print(json.dumps({"tests_run": result.testsRun, "isolated_CLI": "passed_missing_cache",
                      "bundle_bytes": bundle.stat().st_size, "bundle_sha256": checksum,
                      "installation_ready": False}))


if __name__ == "__main__":
    main()