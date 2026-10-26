# G49: pinned public archive-index footer ranges

Read `reports/index-footer-g49/RESULT.fa.md` for the outcome and limitations.

- 16 live fixed ranges accepted and verified, 448 application-body bytes total.
- No full index, archive body, or payload downloaded; no install/execution/runtime approval.
- `fetch_footers.py`, `http_contract.py`, `footer.py`, `pins.py`: preserved preflight-pinned live sources. Do not rerun the fetcher for offline reproduction.
- `test_offline.py`: 23 offline contract/parser tests, including 29 prior G46 archive footer fixtures. Synthetic success is not live evidence.
- `review.py`: offline recheck of the 16 current public footer fixtures, independent size arithmetic, unchanged catalog check, and unexecuted next-plan generation.
- The copied proposal keeps executed=false; actual execution is recorded separately in the G49 receipt.
- A valid footer is not a validated TOC/block set. Publisher signature and anti-fingerprinting claims remain unproven.
- The next 16 full-index GET proposals are metadata-only, bounded to footer-derived sizes and unexecuted; no arbitrary URL or runtime broker configuration is added.
