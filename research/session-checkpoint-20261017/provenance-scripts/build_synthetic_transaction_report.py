"""Package the final synthetic software-test evidence, not game artifacts."""
from pathlib import Path
import hashlib
import json
import zipfile

source = Path("/data/synthetic-transaction-lab-1")
out = Path("/data/synthetic-transaction-delivery-1")
out.mkdir(exist_ok=False)
runs = [json.loads(Path(f"/data/synthetic-transaction-results-{n}/EVIDENCE.json").read_text())
        for n in (3, 4, 5)]
for run in runs:
    assert run["success"] and run["tests_run"] == 45
    assert run["failures"] == run["errors"] == run["skipped"] == 0
    assert run["source_sha256"] == runs[0]["source_sha256"]
    assert run["scope"]["temporary_fixtures_removed"]
    assert run["tripwire_counters_parent_only"] == {
        "network_audit_events": 0, "forbidden_archive_opens": 0,
    }
    assert len(run["events"]["advance_crashes"]) == 11
    assert len(run["events"]["rollback_crashes"]) == 4
    assert len(run["events"]["injected_io_failures"]) == 12
for name, digest in runs[0]["source_sha256"].items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest

initial = json.loads(Path("/data/synthetic-transaction-results-1/EVIDENCE.json").read_text())
assert not initial["success"] and initial["errors"] == 1
summary = {
    "format": "synthetic-transaction-milestone-1",
    "decision": "synthetic_multifile_recovery_milestone_passed_NOT_game_installer",
    "distinct_final_tests": 45,
    "consecutive_final_suite_runs": 3,
    "final_test_executions": 135,
    "final_failures": 0, "final_errors": 0, "final_skipped": 0,
    "process_exit_cut_points_update": 11,
    "process_exit_cut_points_rollback": 4,
    "injected_io_failure_cases": 12,
    "files_per_generation": 3,
    "initial_failure_preserved": {
        "tests": initial["tests_run"], "errors": initial["errors"],
        "cause": "A pointer inode opened just before atomic replacement may have nlink=0; the original pathname/link check incorrectly rejected a valid retained old pointer.",
        "correction": "Descriptor-based checks; nlink=0 allowed only for the retained pointer; immutable payloads still require nlink=1. Added deterministic replacement-after-open regression.",
    },
    "additional_review_correction": "Retry directory fsyncs after a post-commit fsync error and before publishing a previously renamed generation; two explicit regression tests.",
    "final_runs": runs,
    "scope": {
        "network_used": False, "archive_payload_bytes_read": 0,
        "game_or_user_Lab_accessed": False, "existing_project_sources_modified": False,
        "only_new_standalone_research_source_and_private_test_outputs_written": True,
    },
    "milestone_limit": "Real generated loose files with atomic pointer switching on Linux. This is not a CASC updater and is not integrated into the existing installer/research CLI.",
    "installation_ready": False, "game_write_authorization": False,
    "vendor_install_selection_proven": False, "fresh_game_content_proven": False,
    "native_Windows_tested": False, "physical_power_loss_tested": False,
    "physically_full_disk_tested": False,
}
(out / "MILESTONE-EVIDENCE.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
report = """# نقطهٔ عطف پژوهشی: تراکنش چندفایلی و بازیابی

## نتیجه
یک نمونهٔ مستقل و کاملاً مصنوعی ساخته و آزمایش شد که سه فایل تولیدشده توسط خود آزمون را به‌صورت یک نسل جدید آماده می‌کند و با یک اشاره‌گر اتمی فعال می‌کند.
در سناریوهای آزموده‌شده، خوانندهٔ دارای اشاره‌گر ثبت‌شده فقط نسل کامل قدیمی یا نسل کامل جدید را مشاهده کرد؛ نسل نیمه‌کاره فعال نشد.
این یک موفقیت در زیرساخت آزمایشی است، **نه ساخته‌شدن اپدیتر بازی یا تأیید نصب واقعی**.

## شواهد نهایی
- ۴۵ آزمون متمایز، در سه اجرای مستقل و متوالی، بدون شکست، خطا یا skip گذشت.
- قطع واقعی فرایند فرزند با `os._exit(91)` در ۱۱ نقطهٔ پیشروی و ۴ نقطهٔ بازگشت آزموده شد.
- در تمام این موارد، ادامهٔ آزمون به نسل کامل مورد انتظار رسید و محتوای نسل قدیمی حفظ شد.
- ۱۲ حالت تزریق خطا: کمبود فضای گزارش‌شده توسط نوشتن، نوشتن کوتاه، خطای fsync فایل/پوشه و خطای rename/replace، در مراحل مختلف.
- آزمون خوانندهٔ هم‌زمان در هر اجرا، ۴۰ چرخهٔ رفت‌وبرگشت اشاره‌گر را مشاهده کرد؛ هیچ محتوای نیمه‌کاره یا ترکیبی در خواندن‌های انجام‌شده پذیرفته نشد.
- فایل ناشناس، محتوای دست‌کاری‌شده، اشاره‌گر نامعتبر، symlink/hardlink و نویسندهٔ رقیب باعث توقف شدند، نه حذف یا بازنویسی دادهٔ ناشناس.
- اجرای دوبارهٔ پیشروی بعد از تکمیل، محتوای فایل‌ها را تغییر نداد.

## ایرادی که واقعاً پیدا و اصلاح شد
اجرای اولیه در آزمون خوانندهٔ هم‌زمان متوقف شد: اشاره‌گر قدیمی ممکن است پس از تعویض اتمی، هنوز از طریق descriptor معتبر قابل خواندن باشد ولی شمار لینک آن صفر شده باشد.
کنترل قبلی این حالت مجاز را به‌اشتباه رد می‌کرد.
کنترل به descriptor بازشده منتقل شد؛ شمار لینک صفر فقط برای اشاره‌گرِ نگه‌داشته‌شده مجاز است، نه فایل‌های محتوا.
یک آزمون قطعی اضافه شد که تعویض را دقیقاً بین بازکردن و خواندن اشاره‌گر انجام می‌دهد. این اصلاح مربوط به **همین نمونهٔ تازهٔ مصنوعی** است، نه ادعای کشف ایراد در بازی یا ابزار قبلی.

در بازبینی همچنین مسیر ادامه پس از خطای fsync تقویت شد: همگام‌سازی پوشه‌ها باید دوباره انجام شود، حتی اگر اشاره‌گر قبلاً تعویض شده باشد. دو آزمون مشخص این مسیر را بررسی می‌کنند.

## مرز مهم خطا پس از فعال‌سازی
اگر تعویض اشاره‌گر انجام شده ولی fsync پوشه خطا بدهد، ممکن است نسل جدید از قبل قابل مشاهده باشد. برنامه این وضعیت را موفقیت اعلام نمی‌کند و ادعا نمی‌کند نسخهٔ قبلی هنوز فعال است.
ادامهٔ عملیات، نسل قابل مشاهده را بازاعتبارسنجی کرده و همگام‌سازی پوشه‌ها را دوباره انجام می‌دهد.

## چه چیزی هنوز ثابت نشده؟
- این مدل، پوشه‌های immutable و یک اشاره‌گر سفارشی دارد؛ ساختار CASC یا فعال‌سازی متادیتای بازی را پیاده نمی‌کند.
- مجموعهٔ واقعاً لازم برای نصب، سلامت محتوای بازی و صحت پچ‌های واقعی در این مرحله اثبات نشده‌اند.
- قطع فرایند با قطع برق، سکتور پاره‌شده یا رفتار cache سخت‌افزار یکسان نیست.
- ENOSPC و سایر خطاهای I/O تزریق شده‌اند؛ دیسک واقعاً پر نشده است.
- این آزمون فقط روی Linux انجام شده؛ آزمون Windows بومی انجام نشده است.
- نمونه فقط نویسنده‌های همکار را با قفل کنترل می‌کند؛ sandbox امنیتی در برابر فرایند مهاجم نیست.
- نسل قدیمی نگه داشته می‌شود؛ پاک‌سازی نسل‌های قدیمی و هم‌زمانی آن با خواننده‌ها پیاده نشده است.
- این کد به مسیر نصب واقعی یا CLI قبلی متصل نشده و هیچ مجوزی صادر نمی‌کند.

## حدود دسترسی
همهٔ بایت‌های آزمون توسط خود نمونه تولید شدند. شبکه، محتوای آرشیو و بازی یا Lab کاربر ورودی نیستند.
تمام fixtureهای موقت آزمون‌های نهایی حذف شدند؛ کد، گزارش و لاگ‌ها در خروجی پژوهشی جدا باقی مانده‌اند.

## ادامه
این دروازهٔ آزمایشی اکنون برای مدل مصنوعی پوشش دارد. دو مانع اصلی پیش از آزمون نصب واقعی همچنان باقی‌اند:
۱. اثبات سیاست انتخاب و کلوزر اشیای لازم برای نصب.
۲. طراحی و سپس، فقط با مجوز محدود و صریح، اثبات تازهٔ محتوای محلی.
موفقیت این نمونه به‌تنهایی هیچ‌کدام را حل نمی‌کند و دلیل کافی برای نوشتن روی بازی نیست.
"""
(out / "RESULT-fa.md").write_text(report)
readme = """# Synthetic Transaction Research — offline, Linux only

این بسته گزارش و کد پژوهشی است؛ نصب‌کننده یا اپدیتر بازی نیست.
هیچ مسیر بازی، Lab، آرشیو، URL، دانلود یا patch واقعی از کاربر نمی‌گیرد.
فعلاً لازم نیست کاربر این بسته را اجرا کند. گزارش RESULT-fa.md برای مطالعه است.

## بازتولید پژوهش (Linux، Python 3.10+، فقط استاندارد پایتون)
در محیط آزمایشی جدا، خارج از بازی/Lab و تمام ورودی‌ها:

```text
python3 -B code/run_experiment.py --out-new /ABSOLUTE/NEW/SEPARATE/OUTPUT
```

پوشهٔ خروجی نباید از قبل وجود داشته باشد. تنها ورودی خط فرمان، مکان خروجی تازه است، نه فایل بازی.
رانر، fixtureهای خصوصی خودش را در خروجی تولید و در پایان آزمون حذف می‌کند؛ عملیات تراکنش با دیدن فایل ناشناس متوقف می‌شود و آن را پاک نمی‌کند.
فایل worker.py رانر داخلی آزمون است و برای استفادهٔ مستقل نیست.
درون بسته، شواهد هر سه اجرای نهایی، لاگ شکست اولیه و لاگ‌های نهایی نگه‌داری شده‌اند.

موفقیت آزمون یعنی رفتار مدل مصنوعی در حالت‌های ثبت‌شده، نه آمادگی نصب واقعی.
هرگونه شبکه، خواندن آرشیو یا تغییر بازی همچنان خارج از مجوز فعلی است.
"""
(out / "README-fa.md").write_text(readme)
members = {
    **{"code/" + name: (source / name).read_bytes() for name in runs[0]["source_sha256"]},
    "RESULT-fa.md": (out / "RESULT-fa.md").read_bytes(),
    "README-fa.md": (out / "README-fa.md").read_bytes(),
    "MILESTONE-EVIDENCE.json": (out / "MILESTONE-EVIDENCE.json").read_bytes(),
    "evidence/INITIAL-FAILURE.log": Path("/data/synthetic-transaction-results-1/TESTS.log").read_bytes(),
}
for index, run_id in enumerate((3, 4, 5), 1):
    for name in ("EVIDENCE.json", "TESTS.log"):
        members[f"evidence/final-run-{index}/{name}"] = Path(
            f"/data/synthetic-transaction-results-{run_id}/{name}").read_bytes()
manifest = {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in sorted(members.items())}
members["FILES.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
bundle = out / "Synthetic-Transaction-Research-v1.zip"
with zipfile.ZipFile(bundle, "x", compression=zipfile.ZIP_DEFLATED) as archive:
    for name, raw in sorted(members.items()):
        archive.writestr("Synthetic-Transaction-Research-v1/" + name, raw)
# Hash the generated ZIP bytes, not any input archive payload.
digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
(out / "BUNDLE-SHA256.txt").write_text(digest + "  " + bundle.name + "\n")
print(json.dumps({
    "distinct_tests": summary["distinct_final_tests"],
    "final_runs": summary["consecutive_final_suite_runs"],
    "bundle_bytes": bundle.stat().st_size, "bundle_sha256": digest,
    "installation_ready": False,
}))