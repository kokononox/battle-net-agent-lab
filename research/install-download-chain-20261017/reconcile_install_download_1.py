"""Offline report reconciliation only. No Lab, game, archive or network access."""
from collections import defaultdict, Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import zipfile
import pandas as pd

sys.path.insert(0, "/data/install-reference-review-2")
import install_structure as parser
sys.path.insert(0, "/data/install-download-coverage-1")
from install_download_coverage import diagnostic_match
from reconcile_install_encoding_2 import reconcile

OUT = Path("/data/install-download-chain-checkpoint-1")
SOURCE = Path("/data/raw/install-download-coverage-user-1.json")
ENCODING = Path("/data/raw/install-encoding-links-user-2.json")
INSTALL = Path("/data/install-reference-review-2/target-install.metadata")


def need(ok, label):
    if not ok:
        raise ValueError(label)


def validate(report, layout, links):
    need(report["version"] == "install-download-coverage-1", "version")
    need(report["status"] == "pinned_install_download_reference_coverage_reviewed", "status")
    need(report["target_build_config"] == "334a36cf5f3c32a5f7a167405487fa14", "build pin")
    need(report["pinned_target_version"] == "12.1.5.70391", "target version")
    need(report["reference_source_report_sha256"] == hashlib.sha256(ENCODING.read_bytes()).hexdigest(), "Encoding provenance")
    need(report["download_ckey"] == "5beff4cf8122da27a6788d9062c8d3c2", "Download pin")
    need(report["download_sha256_expected"] == "02f0ccb262e1a202e8beaf89ee9011a800b37f29cb34edbc36fe600204686ce1", "Download SHA pin")
    need(report["download_whole_file_ckey_and_sha256_verified"] is True, "reported hash verification")
    need(report["saved_download_metadata_bytes_read"] == report["saved_download_metadata_max_bytes"] == 74562151, "read budget")
    need(report["download_metadata_passes_max"] == 1, "pass budget")
    for key in ("encoding_bytes_read", "game_bytes_read", "archive_payload_bytes_read", "inventory_bytes_read", "network_requests"):
        need(report[key] == 0, "zero scope " + key)
    for key in ("game_or_lab_writes", "inventory_rebuilt", "scan_restart", "saved_lab_snapshot_binding_checked",
                "installed_profile_revalidated", "encoding_identity_revalidated_this_run"):
        need(report[key] is False, "scope " + key)
    coverage = report["coverage"]
    for record in (report, coverage):
        for key in ("vendor_install_policy_proven", "actual_required_install_set_known", "installation_ready", "apply_authorized"):
            need(record[key] is False, "closed gate " + key)
        need(record["required_network_download_bytes"] is None, "unknown network amount")
    need(coverage["fresh_local_content_verified"] is False, "payload unknown")
    need(coverage["alternative_ekey_chosen"] is False, "no alternative selection")
    expected = {ek for link in links.values() for ek in link["encoding_ekeys"]}
    grouped_tags = defaultdict(set)
    exploratory = set()
    for i, entry in enumerate(layout.entries):
        tags = {(tag.name, tag.kind) for tag in layout.tags if tag.bitmap[i // 8] & (128 >> (i % 8))}
        grouped_tags[entry.digest.hex()].update(tags)
        if {"Windows", "x86_64", "EU", "enUS"} <= {name for name, _ in tags}:
            exploratory.update(links[entry.digest.hex()]["encoding_ekeys"])
    rows = []
    seen = set()
    catalogue = {(t.name, t.kind) for t in layout.tags}
    for ref in coverage["references"]:
        ek = ref["ekey"]
        need(ek in expected and ek not in seen, "exact unique EKey")
        seen.add(ek)
        need(ref["state"] == "listed_metadata_reference_NOT_payload_proof", "reference state")
        need(ref["local_payload_state"] == "unknown_NOT_missing_or_corrupt", "unknown payload")
        need(ref["network_download_required"] is None, "no download decision")
        records = ref["matching_download_records"]
        need(len(records) == 1, "single serialized reference")
        record = records[0]
        need(type(record["record_index"]) is int and 0 <= record["record_index"] < 2881619, "ordinal")
        need(type(record["declared_encoded_bytes"]) is int and record["declared_encoded_bytes"] > 0, "encoded size")
        need(type(record["priority_metadata_only"]) is int and 0 <= record["priority_metadata_only"] <= 255, "priority")
        tags = {(t["name"], t["kind"]) for t in record["download_tags"]}
        need(len(tags) == len(record["download_tags"]) and tags <= catalogue, "tag catalogue")
        need(record["matches_prior_diagnostic_profile_NOT_vendor_selection"] is diagnostic_match(record["download_tags"]), "recomputed diagnostic")
        ckeys = [ck for ck, link in links.items() if ek in link["encoding_ekeys"]]
        need(all(grouped_tags[ck] == tags for ck in ckeys), "Install union / Download tags")
        rows.append({"ekey": ek, "download_record_index": record["record_index"],
                     "declared_encoded_bytes_NOT_download_requirement": record["declared_encoded_bytes"],
                     "tag_union_matches": True,
                     "historical_diagnostic_only": record["matches_prior_diagnostic_profile_NOT_vendor_selection"],
                     "ckeys": ";".join(ckeys)})
    need(seen == expected, "exact set closure")
    need(coverage["unique_referenced_ekeys"] == len(seen), "reported EKey count")
    need(coverage["unique_install_ckeys"] == len(links), "reported CKey count")
    need(coverage["ekeys_by_reference_state"] == dict(Counter(x["state"] for x in coverage["references"])), "state totals")
    frame = pd.DataFrame(rows)
    need(not frame.isna().any().any() and not frame["ekey"].duplicated().any(), "normalized actual grain")
    need(not frame["download_record_index"].duplicated().any(), "unique ordinals")
    # Independent path, direct raw JSON loop and equality of full EKey sets.
    independent = {r["ekey"] for r in report["coverage"]["references"]
                   if r["state"] == "listed_metadata_reference_NOT_payload_proof"
                   and len(r["matching_download_records"]) == 1}
    need(len(independent) == int(frame["ekey"].nunique()) == len(expected), "independent count")
    diagnostic = set(frame.loc[frame["historical_diagnostic_only"], "ekey"])
    need(exploratory == diagnostic, "exploratory exact intersection")
    return frame, len(exploratory)


def main():
    raw = SOURCE.read_bytes()
    report = json.loads(raw)
    install = INSTALL.read_bytes()
    parser.pinned_observation(install)
    layout = parser.parse_candidate(install)
    links, _, _ = reconcile(json.loads(ENCODING.read_bytes()), layout)
    frame, exploratory = validate(report, layout, links)
    bad = []
    for key in ("installation_ready", "apply_authorized", "vendor_install_policy_proven"):
        x = deepcopy(report)
        x[key] = True
        bad.append(x)
    x = deepcopy(report); x["coverage"]["references"].pop(); bad.append(x)
    x = deepcopy(report); x["coverage"]["references"].append(deepcopy(x["coverage"]["references"][0])); bad.append(x)
    x = deepcopy(report); x["coverage"]["references"][0]["matching_download_records"][0]["download_tags"].pop(); bad.append(x)
    x = deepcopy(report); x["reference_source_report_sha256"] = "0" * 64; bad.append(x)
    for x in bad:
        try:
            validate(x, layout, links)
        except ValueError:
            continue
        raise ValueError("tampered report accepted")
    OUT.mkdir(exist_ok=True)
    frame.to_csv(OUT / "metadata-chain.csv", index=False)
    evidence = {
        "format": "offline-install-download-chain-checkpoint-1",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "encoding_report_sha256": hashlib.sha256(ENCODING.read_bytes()).hexdigest(),
        "pinned_target": report["pinned_target_version"],
        "serialized_install_records_preserved": len(layout.entries),
        "unique_ckeys": len(links), "unique_ekeys": len(frame),
        "single_download_record_per_ekey": True,
        "install_ckey_group_tag_union_matches_download": int(frame["tag_union_matches"].sum()),
        "exploratory_historical_profile_intersection_NOT_required_install_set": exploratory,
        "negative_validation_cases_rejected": len(bad),
        "profile_resolution": "Generic nested-JSON profiler rows/duplicates are containers, not records. Normalized grain: one unique EKey; no nulls/duplicates.",
        "comparison_plan": [{"finding": "All pinned metadata references close and their tag unions agree",
                             "disposition": "prose", "reason": "One exact coverage result, not a numeric trend or progress percentage."}],
        "assistant_activity": "Uploaded reports plus existing pinned Install metadata only. No game/Lab/archive/network access.",
        "hash_verification_limit": "Download and Encoding raw caches were not available here; their successful hash checks are user-report observations, not independently repeated reads.",
        "installation_ready": False, "apply_authorized": False,
        "vendor_install_policy_proven": False, "fresh_local_content_verified": False,
        "required_network_download_bytes": None,
    }
    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n")
    result = """# تطبیق آفلاین زنجیرهٔ متادیتا

هدف ثابت: 12.1.5.70391؛ نه ادعای آخرین نسخهٔ آنلاین.

- هر ۱۸۰ ارجاع یکتای EKey دقیقاً یک رکورد در گزارش Download دارد.
- برای تمام ۱۸۰ گروه CKey، اجتماع تگ‌های گونه‌های Install با تگ‌های Download برابر است.
- تمام ۲۷۴ رکورد گونه‌های Install در تطبیق حفظ شدند؛ نام‌های تکراری حذف نشدند.
- اشتراک آزمایشی Windows/x86_64/EU/enUS برابر ۳۹ کلید است؛ این مجموعهٔ رسمی یا کامل نصب نیست.
- ۷ دست‌کاری منفی گزارش، از جمله حذف ارجاع و تغییر تگ، رد شدند.

این کنترل روی گزارش‌های ارسالی و Install ثابت انجام شد. صحت هش کل فایل‌های
Download و Encoding در سیستم کاربر گزارش شده است؛ اینجا دوباره آن فایل‌ها خوانده نشدند.
وجود یا سلامت محتوای محلی، پروفایل فعلی، سیاست رسمی انتخاب نصب و حجم دانلود لازم
هنوز اثبات نشده‌اند. وضعیت نامعلوم، مفقود یا خراب محسوب نمی‌شود.

## مرز اقدام بعدی
مجوز فعلی برای خواندن محتوای آرشیو صفر است. گام بعدی معنادار می‌تواند آزمایش
فقط‌خواندنی یک شیء کوچک باشد، تنها با اجازهٔ جداگانه، اتصال تازه به snapshot ذخیره‌شده،
تأیید مختصات موجود و سقف خواندن صریح. اگر کاندیدای معتبر موجود نباشد، توقف؛
بدون جست‌وجوی تازه، شبکه، دانلود یا تغییر بازی.
نصب و فعال‌سازی همچنان مجاز یا آماده نیست.
"""
    (OUT / "RESULT-fa.md").write_text(result)
    (OUT / Path(__file__).name).write_text(Path(__file__).read_text())
    with zipfile.ZipFile("/data/Install-Download-Chain-Checkpoint-1.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(OUT.iterdir()):
            z.write(p, p.name)
    print(json.dumps({k: v for k, v in evidence.items() if isinstance(v, (int, bool))}, ensure_ascii=False))


if __name__ == "__main__":
    main()