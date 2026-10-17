"""Local readiness evidence audit, not an installer or a permission grant.

Reads one shared diagnostic report and source-code/test evidence only.
No archive contents, network, user game or saved Lab are inputs.
"""
from pathlib import Path
from decimal import Decimal
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from copy import deepcopy

ROOT = Path(os.environ.get("READINESS_OUT_NEW", "/data/readiness-audit-1")).resolve()
LAB = Path("/data/lab")
RAW = Path("/data/raw/object-review-user-v3.json")
HISTORICAL = LAB / "research/saved-object-sizes-9824/TEST-RESULTS.json"
PROHIBITED_PROMOTIONS = (
    "actual_required_install_set_known", "fresh_local_content_verified",
    "installed_files_health_proven", "active_CASC_generation_proven",
    "publisher_authentication_proven", "vendor_install_policy_proven",
    "apply_authorized", "installation_ready",
)


def check_report(d):
    """Consistency checks on reported claims, NOT independent raw-input proof."""
    assert d["scope_review_version"] == "saved-object-review-3"
    assert d["status"] == "bound_selected_unique_objects_inventory_projection_complete"
    for key in PROHIBITED_PROMOTIONS:
        assert d[key] is False, key
    assert d["required_network_download_bytes"] is None
    assert d["network_requests"] == 0
    assert d["game_files_modified"] is d["lab_files_modified"] is False
    assert d["unknown_is_not_missing_or_corrupt"] is True
    assert d["old_success_flags_used_for_content_proof"] is False
    scope = d["scope"]
    assert scope["archive_payload_bytes_read"] == scope["archive_payload_read_calls"] == 0
    assert scope["archive_scan_restarted"] is scope["inventory_database_rebuilt"] is False
    assert scope["game_metadata_files_read"] == 2
    assert scope["private_work_removed_before_publication"] is True
    assert scope["saved_download_metadata_bytes_read"] == 2 * 74562151
    assert scope["saved_download_metadata_bytes_read"] <= scope["saved_download_metadata_total_read_max_bytes"] == 268435456
    import pinned_download_model as model
    pin = model.PINNED_MODEL
    assert d["download_metadata"]["expected_ckey"] == pin.ckey
    assert d["download_metadata"]["sha256"] == pin.sha256
    assert d["download_metadata"]["content_identity_revalidated"] is True
    q = d["object_projection"]
    z = q["encoded_size_projection"]
    assert q["selected_records"] == q["unique_ekeys"] + q["duplicate_selected_records"]
    assert q["selected_records"] == d["diagnostic_projection"]["diagnostic_selected_records"]
    assert sum(q["unique_ekeys_by_metadata_state"].values()) == q["unique_ekeys"]
    assert q["unique_ekeys_with_conflicting_manifest_sizes"] == q["unique_ekeys_with_zero_manifest_size"] == 0
    assert z["complete_for_selected_unique_ekeys"] is True
    assert z["unresolved_unique_ekeys"] == 0
    assert z["known_consistent_positive_size_unique_ekeys"] == q["unique_ekeys"]
    assert z["total_selected_unique_encoded_bytes"] == z["known_consistent_positive_size_encoded_bytes"]
    assert sum(z["metadata_encoded_bytes_by_inventory_state"].values()) == z["total_selected_unique_encoded_bytes"]
    assert q["required_network_download_bytes"] is None
    assert q["encoded_bytes_verified"] is False
    assert z["not_listed_encoded_bytes_are_NOT_required_download_bytes"] is True
    assert d["diagnostic_projection"]["selected_record_bitmap_sha256"] == "dcbb3ae6d5656e7b8bddd6721deff91808285bd32059a3ad06fcac09d49aadaf"
    return q, z


def run():
    ROOT.mkdir(exist_ok=False)
    os.environ["TMPDIR"] = str(ROOT)
    tempfile.tempdir = str(ROOT)
    sys.dont_write_bytecode = True
    for p in (LAB, LAB / "object_review_tests", LAB / "scope_review_tests", LAB / "planner_tests"):
        sys.path.insert(0, str(p))

    # This is a regression tripwire, not an OS security sandbox. SQLite paths
    # are separately checked because its native file opens do not use Python open.
    def tripwire(event, args):
        if event.startswith("socket."):
            raise AssertionError("Network operation forbidden in this audit")
        if event == "sqlite3.connect" and args[0] != ":memory:":
            assert Path(args[0]).resolve().is_relative_to(ROOT)
        if event == "open" and isinstance(args[0], (str, bytes)):
            p = Path(os.fsdecode(args[0])).resolve()
            mode, flags = args[1], args[2]
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
            )
            if writing:
                assert p.is_relative_to(ROOT), "Write outside fresh audit output forbidden"
            if re.fullmatch(r"data\.\d+", p.name) or p.suffix.lower() in {".zip", ".mpq", ".archive"}:
                raise AssertionError("Archive file access forbidden in this audit")
    sys.addaudithook(tripwire)

    raw = RAW.read_bytes()
    d = json.loads(raw)
    q, z = check_report(d)
    # Independent numeric path: extract scalar values from raw JSON text.
    def scalar(name, last=False):
        values = re.findall(r'"' + re.escape(name) + r'"\s*:\s*(\d+)', raw.decode())
        return int(values[-1 if last else 0])
    assert scalar("listed_with_size_and_snapshot_coordinates") + scalar("not_listed_in_saved_inventory_unknown") == scalar("unique_ekeys")
    assert scalar("listed_with_size_and_snapshot_coordinates", True) + scalar("not_listed_in_saved_inventory_unknown", True) == scalar("total_selected_unique_encoded_bytes")

    historical = json.loads(HISTORICAL.read_bytes())
    source_results = {
        name: hashlib.sha256((LAB / name).read_bytes()).hexdigest() == digest
        for name, digest in historical["sources_sha256"].items()
    }
    assert all(source_results.values()), "Historical source evidence no longer matches"

    from test_saved_object_review import Collector, Coordinates
    from test_encoded_size_projection import ExactSizes
    from test_build_update_plan import Decisions

    class ReportAntiPromotion(unittest.TestCase):
        pass

    # Each distinct mutation is a separately counted negative regression.
    mutations = [(key, True) for key in PROHIBITED_PROMOTIONS] + [
        ("required_network_download_bytes", 0), ("network_requests", 1),
        ("game_files_modified", True), ("lab_files_modified", True),
    ]
    for key, value in mutations:
        def case(self, key=key, value=value):
            changed = deepcopy(d)
            changed[key] = value
            with self.assertRaises(AssertionError):
                check_report(changed)
        setattr(ReportAntiPromotion, "test_reject_" + key, case)

    suite = unittest.TestSuite()
    for cls in (Collector, Coordinates, ExactSizes, Decisions, ReportAntiPromotion):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    (ROOT / "SAFE-REGRESSION.log").write_text(log.getvalue())
    assert result.wasSuccessful() and not result.skipped

    evidence = {
        "format": "offline-readiness-audit-1",
        "decision": "research_only_NOT_installation_ready",
        "input_report_sha256": hashlib.sha256(raw).hexdigest(),
        "grain": "one nested diagnostic report, not independent flattened rows",
        "profiler_warnings": {
            "resolution": "Flattening creates repeated constants, structural nulls and mixed types. No records dropped. Null network bytes is unknown, not zero.",
            "synthetic_flattened_rows": 85,
            "synthetic_flattened_duplicate_rows": 31,
        },
        "trust_limit": "Internal consistency and source-pin agreement of a user-shared report only. Raw user Download, inventory, game and Windows runtime were NOT independently inspected here. Report claims are not a signature or authorization.",
        "selected_unique_ekeys": q["unique_ekeys"],
        "total_selected_unique_encoded_bytes": z["total_selected_unique_encoded_bytes"],
        "total_selected_unique_encoded_GB_display": str((Decimal(z["total_selected_unique_encoded_bytes"]) / Decimal(10**9)).quantize(Decimal("0.01"))),
        "unique_ekeys_by_metadata_state": q["unique_ekeys_by_metadata_state"],
        "metadata_encoded_bytes_by_inventory_state": z["metadata_encoded_bytes_by_inventory_state"],
        "independent_raw_numeric_reconciliation": True,
        "new_tests_run": result.testsRun,
        "existing_metadata_and_planner_tests_rerun": result.testsRun - len(mutations),
        "new_report_anti_promotion_cases": len(mutations),
        "new_test_failures": len(result.failures),
        "new_test_errors": len(result.errors),
        "new_test_skipped": len(result.skipped),
        "new_test_scope": "Synthetic in-memory manifests, disposable private SQLite, coordinate checks, exact size arithmetic, planner decisions, report anti-promotion; NOT installer, actual payload, power loss or Windows tests.",
        "historical_tests_recorded_NOT_rerun_today": historical["tests_run"],
        "historical_source_hashes_match": source_results,
        "runtime": sys.version.split()[0],
        "platform": sys.platform,
        "audit_scope": {
            "network_operations": 0, "archive_payload_bytes_read": 0,
            "user_game_or_Lab_accessed": False, "source_code_modified": False,
            "outputs": "fresh " + str(ROOT) + " only",
            "tripwire_is_NOT_OS_sandbox": True,
        },
        "gates": [
            {"id": "diagnostic_consistency", "status": "pass_limited", "evidence": "Report accounting, expected pins and preserved unknown states reconcile; raw user inputs not independently revalidated here."},
            {"id": "vendor_required_install_set", "status": "blocked", "evidence": "Diagnostic matching-or-unclassified projection is not proven vendor policy or install closure."},
            {"id": "fresh_local_content", "status": "not_tested", "evidence": "Inventory coordinates and sizes are not content proof. Current archive read budget is zero."},
            {"id": "synthetic_install_fault_matrix", "status": "not_established_end_to_end", "evidence": "Existing single-pair owned sample is not a full updater. No general installer crash/disk-full/rollback result established by this audit."},
            {"id": "native_windows", "status": "not_tested_here", "evidence": "User report is useful execution evidence, not independent native Windows regression coverage."},
            {"id": "live_install_permission", "status": "not_granted", "evidence": "No network/archive/game-write authorization inferred."},
        ],
        "comparison_plan": [{
            "question": "Which readiness claims are justified?",
            "grain": "evidence gate", "population": "current diagnostic and local source tests",
            "unit": "proof status", "finding": "Diagnostic consistency passes with limits; installation gates remain open.",
            "derivation": "Exact reconciliation and negative tests, not project completion percentage",
            "disposition": "prose", "reason": "Safety/readiness assessment, not a volume comparison or time series. No numeric chart would establish missing proof.",
        }],
        "next_permitted_work": "Design and test a strictly sandbox-only synthetic transaction/failure harness. Keep it non-production, disconnected, with no user paths or archive inputs. This does not solve vendor selection or authorize real install.",
        "installation_ready": False,
        "required_network_download_bytes": None,
    }
    (ROOT / "EVIDENCE.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    report = f"""# ممیزی آمادگی اپدیتر — مرحلهٔ اول

## نتیجه
بررسی تشخیصی متادیتا سازگار است؛ **مجوز یا آمادگی نصب واقعی حاصل نشده است**.

- گزارش ارسالی برای {q['unique_ekeys']:,} شیء منتخب یکتا از نظر جمع شمارش‌ها و اندازه‌ها سازگار است.
- جمع اندازهٔ encoded ثبت‌شده در متادیتای این انتخاب {evidence['total_selected_unique_encoded_GB_display']} GB است؛ GB یعنی ۱۰⁹ بایت. این حجم دانلود لازم یا اندازهٔ نصب decoded نیست.
- تطابق CKey و SHA256 در این ممیزی، تطابق ادعای گزارش با pin کد است؛ بایت‌های خام متادیتای کاربر در این محیط در دسترس نیست و مستقلاً دوباره هش نشده‌اند.
- فهرست ذخیره‌شده سلامت فعلی محتوا را اثبات نمی‌کند. ثبت‌نشده یعنی نامشخص، نه مفقود یا خراب.

## آزمون همین مرحله
{result.testsRun} آزمون، بدون شکست، خطا یا skip؛ روی Linux و Python {evidence['runtime']}.
آزمون‌ها فقط انتخاب و یکتاسازی متادیتای مصنوعی، مختصات مصنوعی، محاسبهٔ دقیق حجم، تصمیم‌های برنامه‌ریز و رد ارتقای نادرست ادعاهای گزارش را پوشش می‌دهند.
این تعداد، آزمون نصب یا قطع برق نیست. رکورد قبلی {historical['tests_run']} آزمون مجدداً اجرا نشده؛ هش فایل‌های منبع ثبت‌شده با فایل‌های فعلی تطبیق داده شد.

## دروازه‌های باز
۱. سیاست معتبر انتخاب اشیای لازم و کلوزر نصب هنوز اثبات نشده است.
۲. بایت‌های محلی، نسل فعال CASC و اصالت ناشر هنوز اثبات نشده‌اند.
۳. آزمون انتها‌به‌انتهای نصب عمومی با خطای نوشتن، کمبود فضا، قطع عملیات و بازیابی هنوز برقرار نشده است؛ نمونهٔ تک‌جفتی موجود جای آن را نمی‌گیرد.
۴. آزمون Windows بومی در این محیط انجام نشده است؛ موفقیت گزارش شما صرفاً شاهد اجرای همان مرحله است.
۵. مجوز شبکه، خواندن محتوای آرشیو یا نوشتن بازی داده نشده است.

## ادامهٔ مجاز
ساخت و آزمودن هارنس تراکنش **صرفاً مصنوعی** در پوشهٔ موقت متعلق به آزمون، بدون مسیر بازی/Lab، بدون آرشیو و بدون شبکه.
این هارنس نباید قابلیت نصب واقعی داشته باشد و موفقیتش به معنی حل سیاست نصب فروشنده نیست.
پس از آن باید شواهد و محدودیت‌ها دوباره جمع‌بندی شود؛ هیچ مجوزی خودکار صادر نمی‌شود.

## دامنه و قابلیت بازتولید
این ممیزی فقط گزارش عمومی ارسالی، فایل‌های کد و شواهد آزمون قبلی را خواند.
خروجی‌ها فقط در پوشه‌ای تازه و جدا ساخته شدند؛ نه شبکه‌ای استفاده شد و نه آرشیو، بازی یا Lab کاربر خوانده/تغییر داده شد.
کنترل‌های audit پایتون برای تشخیص خروج ناخواسته از دامنه‌اند، نه sandbox امنیتی سیستم‌عامل.
شواهد ماشین‌خوان و لاگ آزمون کنار این فایل نگه‌داری شده‌اند.

SHA256 گزارش ورودی: `{evidence['input_report_sha256']}`
"""
    (ROOT / "READINESS-fa.md").write_text(report)
    print(json.dumps({k: evidence[k] for k in ("decision", "new_tests_run", "new_test_failures", "new_test_errors", "historical_tests_recorded_NOT_rerun_today")}))


if __name__ == "__main__":
    run()