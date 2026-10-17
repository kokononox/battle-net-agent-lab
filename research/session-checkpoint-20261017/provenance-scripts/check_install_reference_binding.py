"""Verify existing local target config; NEVER open Install/archive/game/cache.

This extracts a bound next-evidence request, not a vendor-selection policy.
"""
from pathlib import Path
import hashlib
import json
import re
import unittest
import io

CONFIG = Path("/data/retail-release-extracted/Portable-Retail-Sample/pinned_metadata/build.config")
EXPECTED_MD5 = "334a36cf5f3c32a5f7a167405487fa14"
EXPECTED_SHA256 = "f30cdd30bcbb613795557606c0015411640ffa4a2710f7419ea75dae345c964d"
OUT = Path("/data/install-selection-reference-1")
INTEREST = {"root", "install", "install-size", "download", "download-size", "encoding", "encoding-size", "build-name", "build-uid"}


class ReferenceError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ReferenceError(code)


def parse_references(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 4 * 1024**2, "config_bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise ReferenceError("encoding") from None
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        require("=" in line, "config_syntax")
        name, value = (part.strip() for part in line.split("=", 1))
        if name not in INTEREST:
            continue
        require(name not in result, "duplicate_reference")
        result[name] = value.split()
    require(set(result) == INTEREST, "missing_reference")
    require(result["build-name"] == ["WOW-70391patch12.1.5_Retail"] and
            result["build-uid"] == ["wow"], "wrong_target")
    for name in ("root", "install", "download", "encoding"):
        require(len(result[name]) == (1 if name == "root" else 2), "reference_width")
        require(all(re.fullmatch("[0-9a-f]{32}", key) is not None for key in result[name]), "reference_key")
        if name != "root":
            sizes = result[name + "-size"]
            require(len(sizes) == 2, "size_width")
            require(all(re.fullmatch("[1-9][0-9]{0,11}", size) is not None for size in sizes), "reference_size")
            result[name + "-size"] = [int(size) for size in sizes]
    return result


def verify_pinned(raw):
    require(hashlib.md5(raw).hexdigest() == EXPECTED_MD5, "build_ckey_mismatch")
    require(hashlib.sha256(raw).hexdigest() == EXPECTED_SHA256, "build_sha256_mismatch")
    return parse_references(raw)


def main():
    OUT.mkdir(exist_ok=False)
    raw = CONFIG.read_bytes()
    refs = verify_pinned(raw)
    # Independent extraction, separate from the key/value parser.
    line = re.search(rb"(?m)^install = ([0-9a-f]{32}) ([0-9a-f]{32})\s*$", raw)
    size = re.search(rb"(?m)^install-size = ([0-9]+) ([0-9]+)\s*$", raw)
    require(line is not None and size is not None, "independent_reference_not_found")
    require([item.decode() for item in line.groups()] == refs["install"], "independent_key_check")
    require([int(item) for item in size.groups()] == refs["install-size"], "independent_size_check")

    def replace(line, new):
        require(line in raw, "test_fixture_line_missing")
        return raw.replace(line, new, 1)

    invalid = {
        "wrong_build_bytes": (lambda: verify_pinned(raw + b"\n")),
        "changed_target": (lambda: parse_references(replace(b"build-uid = wow", b"build-uid = wow_classic"))),
        "duplicate_install": (lambda: parse_references(raw + b"\ninstall = " + b"a" * 32 + b" " + b"b" * 32)),
        "missing_install": (lambda: parse_references(replace(line.group(0), b""))),
        "uppercase_key": (lambda: parse_references(replace(line.group(1), line.group(1).upper()))),
        "short_key": (lambda: parse_references(replace(line.group(1), b"a" * 31))),
        "too_many_keys": (lambda: parse_references(replace(line.group(0), line.group(0) + b" " + b"a" * 32))),
        "zero_size": (lambda: parse_references(replace(b"install-size = 24078 23106", b"install-size = 0 23106"))),
        "negative_size": (lambda: parse_references(replace(b"install-size = 24078 23106", b"install-size = -1 23106"))),
        "float_size": (lambda: parse_references(replace(b"install-size = 24078 23106", b"install-size = 24078.0 23106"))),
        "missing_size": (lambda: parse_references(replace(b"install-size = 24078 23106", b"install-size = 24078"))),
        "invalid_utf8": (lambda: parse_references(raw + b"\xff")),
        "oversize": (lambda: parse_references(b" " * (4 * 1024**2 + 1))),
    }
    class ReferenceTests(unittest.TestCase):
        def test_existing_pin(self):
            self.assertEqual(verify_pinned(raw), refs)
        def test_pin_is_not_publisher_signature(self):
            # Admission of config identity never emits a vendor-policy proof.
            self.assertNotIn("vendor_install_policy_proven", refs)
            self.assertNotIn("installation_ready", refs)
    for name, function in invalid.items():
        def case(self, function=function):
            with self.assertRaises(ReferenceError):
                function()
        setattr(ReferenceTests, "test_reject_" + name, case)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ReferenceTests))
    (OUT / "TESTS.log").write_text(stream.getvalue())
    require(result.wasSuccessful(), "tests_failed")

    # This only examines file membership in the supplied Portable manifest.
    # It does NOT search the user's saved Lab, other caches or the network.
    portable = json.loads((CONFIG.parent.parent / "PORTABLE-MANIFEST.json").read_bytes())
    named_members = sorted(portable["files"])
    evidence = {
        "format": "install-selection-reference-audit-1",
        "decision": "blocked_missing_independent_install_selection_evidence",
        "local_target_config": {
            "bytes": len(raw), "md5": hashlib.md5(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(), "pins_revalidated": True,
            "publisher_signature_verified": False,
        },
        "references": refs,
        "independent_reference_extraction_matches": True,
        "existing_portable_manifest_member_names": named_members,
        "portable_manifest_includes_install_manifest": False,
        "membership_limit": "Only the supplied Portable file list was checked. Absence here is NOT absence from the user's saved Lab or other locations.",
        "what_the_install_reference_proves": "The exact decoded Install identity and size named by this target config; NOT its bytes, current local availability, tag semantics or full game install closure.",
        "proposed_next_input_NOT_yet_authorized": {
            "kind": "decoded target Install metadata from an already existing cache or explicit user upload",
            "ckey": refs["install"][0], "expected_decoded_bytes": refs["install-size"][0],
            "encoded_ekey_NOT_a_decoded_ckey": refs["install"][1],
            "encoded_size_NOT_the_decoded_read_budget": refs["install-size"][1],
            "candidate_name_by_existing_cache_convention_NOT_existence_proof":
                "objects/" + refs["install"][0] + "-" + str(refs["install-size"][0]) + ".decoded",
            "approval_required_reason": "Current approved raw-cache reads cover exact saved Download metadata only. Install is a new metadata input type.",
            "if_exact_existing_input_absent": "Stop and report unknown; no search, extraction, download, game access or fallback.",
            "acceptance_if_approved": "One bounded read; exact byte count and MD5/CKey, observe header/structure without guessing tag policy; no success or install closure inferred from hash identity.",
            "no_network": True, "no_archive_payload_reads": True,
            "no_game_or_Lab_writes": True,
        },
        "tests_run": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "new_Install_input_read": False, "new_Download_input_read": False,
        "encoding_payload_read": False, "archive_payload_bytes_read": 0,
        "network_requests": 0, "user_game_or_Lab_accessed": False,
        "actual_required_install_set_known": False, "installation_ready": False,
        "required_network_download_bytes": None,
        "root_or_encoding_reference_is_NOT_full_closure_evidence": True,
    }
    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    report = f"""# بررسی مرجع بعدی برای اثبات انتخاب نصب

## یافتهٔ قطعی، با دامنهٔ محدود
هویت build-config هدف از فایل محلی موجود دوباره کنترل شد:
MD5/CKey برابر `{EXPECTED_MD5}` و SHA256 برابر `{EXPECTED_SHA256}` است.
این تطابق محتواست، نه تأیید امضای ناشر.

همین config برای متادیتای Install این مرجع را اعلام می‌کند:
- CKey محتوای decoded: `{refs['install'][0]}`
- اندازهٔ decoded: **{refs['install-size'][0]:,} بایت**
- EKey نمایش encoded: `{refs['install'][1]}`
- اندازهٔ encoded: {refs['install-size'][1]:,} بایت

مرجع Install با Download متفاوت است. مدل فعلی فقط bitmapهای Download را با فرض تشخیصی matching-or-unclassified انتخاب می‌کند.
وجود تگ‌های Windows/x86_64/EU/enUS و تطابق hash، سیاست نصب فروشنده یا مجموعهٔ کامل لازم را اثبات نمی‌کند.
همچنین Install به‌تنهایی ممکن است کافی نباشد؛ نسبت آن با Root، Encoding و محتوای مورد نیاز بازی باید جداگانه روشن شود.

## کمبود داده دقیقاً کجاست؟
فهرست فایل‌های Portable ارسالی شامل فایل Install نیست.
این فقط دربارهٔ همان بسته است؛ Lab کاربر، کش‌های دیگر و شبکه جست‌وجو نشده‌اند و نبودن در آن‌ها ادعا نمی‌شود.
بنابراین از دادهٔ در دسترس فعلی نمی‌توان سیاست معتبر نصب یا حتی ابرمجموعه‌بودن انتخاب فعلی را نتیجه گرفت.

## آزمون همین مرحله
{result.testsRun} آزمون بدون شکست/خطا/skip گذشت: اتصال به pin موجود، رد تغییر هویت، کلید ناقص/تکراری، اندازهٔ صفر/منفی/غیرصحیح و ساختار مرجع نامعتبر.
این آزمون‌ها parser فایل Install یا سیاست نصب واقعی را اعتبارسنجی نمی‌کنند؛ خود فایل Install هنوز خوانده نشده است.

## توقف مجوز
مجوز فعلیِ raw-cache فقط برای Download دقیق است؛ Install نوع تازه‌ای از ورودی است.
گام پیشنهادی، پس از اجازهٔ صریح: فقط فایل decoded Install از قبل موجود با CKey بالا و اندازهٔ دقیق {refs['install-size'][0]:,} بایت بررسی شود.
نام مورد انتظار با قرارداد کش فعلی:
`objects/{refs['install'][0]}-{refs['install-size'][0]}.decoded`
این نام، اثبات وجود فایل نیست. اگر موجود نباشد، توقف؛ بدون جست‌وجو، استخراج آرشیو، دانلود یا جایگزین‌سازی.
ارسال مستقیم همین فایل عمومی توسط کاربر نیز می‌تواند ورودی مرحلهٔ بعد باشد.

در این مرحله فقط config محلی موجود و فهرست فایل‌های Portable خوانده شدند.
هیچ Install، Download تازه، Encoding، آرشیو، بازی یا Lab کاربر خوانده/تغییر داده نشد؛ شبکه استفاده نشد.
"""
    (OUT / "RESULT-fa.md").write_text(report)
    print(json.dumps({"tests_run": result.testsRun, "decision": evidence["decision"],
                      "next_decoded_metadata_bytes": refs["install-size"][0],
                      "installation_ready": False}))


if __name__ == "__main__":
    main()