"""Offline reconciliation of the user report with already pinned Install metadata.

Never opens Encoding, game, Lab, archives, network or executable payloads.
Names in the output are metadata labels, never filesystem destinations.
"""
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import zipfile

import pandas as pd

SOURCE = Path("/data/raw/install-encoding-links-user-2.json")
INSTALL = Path("/data/install-reference-review-2/target-install.metadata")
PARSER = Path("/data/install-reference-review-2/install_structure.py")
OUT = Path("/data/install-metadata-reference-checkpoint-1")
OUT.mkdir(exist_ok=True)
AGREE = "metadata_link_and_declared_size_agree_NOT_payload_proof"


def require(ok, label):
    if not ok:
        raise ValueError(label)


def reconcile(report, layout):
    mapping = report["mapping"]
    links = mapping["links"]
    require(report["version"] == "install-encoding-links-2", "version")
    require(report["status"] == "pinned_install_encoding_metadata_links_reviewed", "status")
    require(report["install_ckey"] == "d7c8cd9845e2b5d39821678f481324da", "Install pin")
    require(report["encoding_ckey"] == "8d0576391f8e80ce55940381fc3f674a", "Encoding pin")
    require(report["target_build_config"] == "334a36cf5f3c32a5f7a167405487fa14", "build pin")
    require(report["encoding_whole_file_ckey_verified"] is True, "reported hash")
    require(report["selected_content_page_checksums_verified"] is True, "reported page checksums")
    require(report["encoding_hash_bytes_read"] == 200255318, "hash bytes")
    require(0 <= report["encoding_lookup_bytes_read"] <= 33554432, "lookup budget")
    require(
        report["total_encoding_metadata_bytes_read"]
        == report["encoding_hash_bytes_read"] + report["encoding_lookup_bytes_read"]
        <= report["total_encoding_metadata_max_bytes"] == 233809750,
        "total budget",
    )
    for key in (
        "network_requests", "archive_payload_bytes_read",
        "raw_download_metadata_bytes_read", "game_metadata_bytes_read",
    ):
        require(report[key] == 0, "scope " + key)
    for record in (report, mapping):
        for key in (
            "installation_ready", "apply_authorized", "vendor_install_policy_proven",
            "actual_required_install_set_known",
        ):
            require(record[key] is False, "closed gate " + key)
        require(record["required_network_download_bytes"] is None, "unknown download size")
    require(report["game_or_lab_writes"] is False, "no source writes")
    require(report["cache_search_or_scan_restart"] is False, "no scan")
    require(report["saved_lab_snapshot_binding_checked"] is False, "no fresh snapshot claim")
    require(report["installed_profile_revalidated"] is False, "no fresh profile claim")
    require(mapping["fresh_local_content_verified"] is False, "no payload claim")
    require(mapping["all_install_variants_checked_without_profile_selection"] is True, "all variants")
    require(mapping["records_deduplicated_for_install"] is False, "no install dedup")
    require(all(v is True for v in report["identity_guard"].values()), "Windows dual identity guard")
    require(re.fullmatch("[0-9a-f]{64}", report["encoding_sha256"]) is not None, "hash shape")
    require(report["encoding_other_pages_semantically_parsed"] is False, "partial semantic review")

    expected = defaultdict(set)
    for entry in layout.entries:
        expected[entry.digest.hex()].add(entry.declared_size)
    seen = {}
    for row in links:
        ck = row["ckey"]
        require(re.fullmatch("[0-9a-f]{32}", ck) is not None, "CKey shape")
        require(ck not in seen, "duplicate CKey")
        require(ck in expected, "unrequested CKey")
        require(row["state"] == AGREE, "unresolved link")
        sizes = row["install_declared_sizes"]
        require(set(sizes) == expected[ck] and len(sizes) == 1, "Install declared sizes")
        require(type(row["encoding_declared_decoded_size"]) is int, "size type")
        require(row["encoding_declared_decoded_size"] == sizes[0], "Encoding declared size")
        ekeys = row["encoding_ekeys"]
        require(isinstance(ekeys, list) and len(ekeys) > 0, "EKey list")
        require(
            len(ekeys) == len(set(ekeys))
            and all(re.fullmatch("[0-9a-f]{32}", k) and int(k, 16) > 0 for k in ekeys),
            "EKey shape and uniqueness",
        )
        require(row["ekeys_are_metadata_references_NOT_payload_validation"] is True, "reference only")
        seen[ck] = row
    require(set(seen) == set(expected), "exact CKey closure")
    require(mapping["serialized_install_records"] == len(layout.entries), "serialized record count")
    require(mapping["unique_install_ckeys"] == len(expected) == len(links), "unique count")
    require(mapping["unique_ckeys_by_state"] == dict(Counter(x["state"] for x in links)), "state totals")
    # Normalize the nested report to its actual grain, one row per distinct CKey.
    frame = pd.DataFrame([
        {"ckey": x["ckey"], "state": x["state"],
         "declared_decoded_bytes": x["encoding_declared_decoded_size"],
         "ekey_count": len(x["encoding_ekeys"])}
        for x in links
    ])
    require(not frame.isna().any().any(), "normalized nulls")
    require(not frame["ckey"].duplicated().any(), "normalized duplicate CKeys")
    count = int(frame.loc[frame["state"].eq(AGREE), "ckey"].nunique())
    # Independent path: direct raw nested JSON count, not pandas groupby/totals.
    independent = sum(
        x["state"] == AGREE
        and x["ckey"] in expected
        and x["install_declared_sizes"] == [x["encoding_declared_decoded_size"]]
        for x in report["mapping"]["links"]
    )
    require(count == independent == len(expected), "independent headline reconciliation")
    return seen, frame, count


def main():
    source_bytes = SOURCE.read_bytes()
    report = json.loads(source_bytes)
    spec = importlib.util.spec_from_file_location("pinned_install_structure", PARSER)
    parser = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = parser
    spec.loader.exec_module(parser)
    install_bytes = INSTALL.read_bytes()
    parser.pinned_observation(install_bytes)
    layout = parser.parse_candidate(install_bytes)
    bykey, frame, count = reconcile(report, layout)
    n = len(layout.entries)
    references = []
    for index, entry in enumerate(layout.entries):
        ck = entry.digest.hex()
        references.append({
            "serialized_install_record_index": index,
            "metadata_name_NOT_extraction_destination": entry.name,
            "ckey": ck,
            "declared_decoded_bytes": entry.declared_size,
            "encoding_ekeys_metadata_only": bykey[ck]["encoding_ekeys"],
            "tags_under_community_supported_MSB_interpretation": [
                {"name": tag.name, "type": tag.kind}
                for tag in layout.tags
                if tag.bitmap[index // 8] & (0x80 >> (index % 8))
            ],
            "selected_for_install": None,
            "local_payload_state": "unknown_NOT_missing_or_corrupt",
            "write_or_download_action": None,
        })
    require(len(references) == n, "all variants preserved")
    # Fail-closed validation checks: malformed/overclaiming reports must not become plans.
    from copy import deepcopy
    cases = []
    for label in ("installation_ready", "apply_authorized", "vendor_install_policy_proven"):
        altered = deepcopy(report)
        altered[label] = True
        cases.append(altered)
    altered = deepcopy(report)
    altered["mapping"]["links"].pop()
    cases.append(altered)
    altered = deepcopy(report)
    altered["mapping"]["links"][0]["encoding_declared_decoded_size"] += 1
    cases.append(altered)
    altered = deepcopy(report)
    altered["mapping"]["links"].append(deepcopy(altered["mapping"]["links"][0]))
    cases.append(altered)
    altered = deepcopy(report)
    altered["total_encoding_metadata_bytes_read"] += 1
    cases.append(altered)
    for altered in cases:
        try:
            reconcile(altered, layout)
        except ValueError:
            continue
        raise ValueError("malformed report accepted")

    evidence = {
        "format": "offline-install-metadata-reference-checkpoint-1",
        "source": {
            "user_attachment_filename": "INSTALL-ENCODING-LINKS-to-share.json",
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
            "report_version": report["version"],
            "provenance_limit": "User-reported run; not signed remote attestation.",
        },
        "checks": {
            "matched_serialized_install_records": n,
            "matched_unique_install_ckeys": count,
            "unresolved_reported_metadata_links": 0,
            "independent_raw_json_headline_count": count,
            "all_variant_records_preserved": True,
            "mutation_rejection_tests_passed": len(cases),
        },
        "observed_encoding_sha256_NOT_independently_rehashed_here": report["encoding_sha256"],
        "reported_encoding_read_bytes": report["total_encoding_metadata_bytes_read"],
        "reported_encoding_read_budget": report["total_encoding_metadata_max_bytes"],
        "unparsed_encoding_tail_bytes": report["unparsed_encoding_tail_bytes"],
        "semantic_review_limit": "Only selected CKey pages parsed; other pages and tail NOT semantically validated. Tail is not declared corrupt.",
        "profiler_resolution": (
            "The generic JSON profiler expanded the single nested report into 17 "
            "artificial rows; its duplicate/null/constant/mixed warnings are not "
            "evidence about the link records. Actual grain normalized to 180 "
            "unique CKey records; no nulls or duplicate CKeys. Required network "
            "bytes intentionally null (unknown), not zero."
        ),
        "comparison_plan": [{
            "grain": "distinct Install CKey", "population": "all pinned Install variants",
            "unit": "validated metadata references", "finding": "All unique references reconcile",
            "derivation": "Exact key-set equality and declared-size agreement, independently recounted",
            "disposition": "prose", "reason": "Single pass/fail coverage finding; not a temporal or group comparison",
        }],
        "scope_of_this_analysis": {
            "input": "Attached JSON and already pinned small Install metadata only",
            "network_requests": 0, "encoding_payload_bytes_read": 0,
            "archive_payload_bytes_read": 0, "user_game_or_lab_accessed": False,
            "game_or_lab_writes": False,
        },
        "next_gates": [
            "Prove product-specific tag combination, default and optional selection policy without silently treating an exploratory tag intersection as complete.",
            "Bind a future plan to a freshly validated installed profile and saved snapshot.",
            "Resolve selected target records against saved Download/availability metadata; unknown is not missing or corrupt.",
            "Design and test payload verification, safe destination handling, staging, rollback and interruption recovery before any real installation.",
            "Obtain explicit user permission before network, archive reads or game writes; none is authorized by this report.",
        ],
        "actual_required_install_set_known": False,
        "fresh_local_content_verified": False,
        "installation_ready": False,
        "apply_authorized": False,
        "required_network_download_bytes": None,
        "record_references": references,
    }
    (OUT / "CHECKPOINT.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    frame.to_csv(OUT / "metadata-links.csv", index=False)
    (OUT / "SOURCE-REPORT.json").write_bytes(source_bytes)
    text = f"""# نتیجهٔ تطبیق مستقل گزارش Install → Encoding

این مرحلهٔ متادیتا موفق است: همهٔ {count} کلید محتوای یکتای گزارش با {n} رکورد فایل Install ثابت تطبیق دارند. مجموعهٔ کلیدها، اندازه‌های اعلام‌شده و جمع وضعیت‌ها مستقلاً کنترل شدند؛ هیچ رکورد منطقه‌ای/هم‌نام حذف نشد.

گزارش کاربر نشان می‌دهد اصلاح Windows از مرحلهٔ قبلی عبور کرده، هویت Encoding ذخیره‌شده و checksum صفحه‌های منتخب تأیید شده‌اند. این‌ها یافته‌های اجرای گزارش‌شده هستند، نه گواهی امضاشده یا هش‌گیری مجدد Encoding در محیط دستیار.

پیوست CHECKPOINT.json برای همهٔ رکوردها مرجع متادیتا نگه می‌دارد؛ نام‌ها مقصد نوشتن نیستند، selected_for_install نامعلوم است و هیچ عمل دانلود/نوشتن ندارد. این سند «پلن نصب قابل اجرا» نیست. metadata-links.csv یک ردیف برای هر CKey یکتا دارد.

مقدار انتهای تفسیرنشدهٔ Encoding در گزارش حفظ شد؛ تفسیر نشدن به معنی خرابی نیست. همهٔ فایل Encoding اینجا از نظر معنا بررسی نشده است.

گام بعدِ حل‌نشده، سیاست دقیق انتخاب مجموعهٔ هدف برای محصول/پلتفرم/منطقه/زبان، سپس اتصال آن به وضعیت محلی معتبر است. توافق متادیتا نه صحت فایل‌های فعلی بازی را ثابت می‌کند، نه اندازهٔ دانلود لازم و نه آمادگی نصب را.

هیچ شبکه، دسترسی به Lab/بازی، خواندن بدنهٔ Encoding/آرشیو یا تغییر منبعی در این تحلیل انجام نشد. تمام مجوزهای نصب و اعمال بسته‌اند. فعلاً اجرای مجدد ابزار یا تغییر دسترسی‌ها لازم نیست.
"""
    (OUT / "RESULT-fa.md").write_text(text)
    (OUT / "reconcile_install_encoding_2.py").write_bytes(Path(__file__).read_bytes())
    members = sorted(p for p in OUT.iterdir() if p.is_file() and p.name != "MANIFEST-SHA256.json")
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in members}
    (OUT / "MANIFEST-SHA256.json").write_text(json.dumps(hashes, indent=2) + "\n")
    target = Path("/data/Install-Metadata-Reference-Checkpoint-1.zip")
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for p in members + [OUT / "MANIFEST-SHA256.json"]:
            archive.write(p, p.name)
    with zipfile.ZipFile(target) as archive:
        require(archive.testzip() is None, "ZIP CRC")
        require(all(hashlib.sha256(archive.read(k)).hexdigest() == v for k, v in hashes.items()), "ZIP hashes")
    print(json.dumps({
        "matched_serialized_records": n, "matched_unique_ckeys": count,
        "unresolved_metadata_links": 0, "mutation_tests": len(cases),
        "reported_encoding_bytes": report["total_encoding_metadata_bytes_read"],
        "budget_respected": True, "installation_ready": False,
        "checkpoint_zip": str(target),
    }, indent=2))


if __name__ == "__main__":
    main()