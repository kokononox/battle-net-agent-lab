# G47: two fixed archive ranges, research only

Read `reports/fixed-range-g47/RESULT.fa.md` for results and limits. Both live requests returned 206 and validated; no install/execution/runtime approval.

- `plan.review-only.json` is an unchanged copy of the unexecuted G46 proposal. Its old executed=false records proposal state; see the separate G47 receipt for actual execution.
- `fetch_ranges.py` is preserved live source; do not rerun to reproduce offline work. Requires preflight and consumes a one-shot private marker.
- `codec.py` is copied unchanged from G44.
- `test_offline.py` exercises contracts with synthetic data, no live network.
- `recheck_saved.py` performs a second offline review of the two privately retained observed Z-format objects, with no network fallback.
- Payload bytes are deliberately not published. A fresh public checkout can run contract tests, not independently reconstruct the real payload checks from hashes alone.

No arbitrary range/URL input and no production broker integration are provided. MD5/CKey matches plus observed SHA256 do not establish a publisher signature or anti-fingerprinting guarantee.
