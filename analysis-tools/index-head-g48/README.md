# G48: fixed HEAD diagnostics only

Read `reports/index-head-g48/RESULT.fa.md` before interpreting evidence.

- `head_indices.py` is preserved live network source, with no response.read() calls. Do not rerun for offline reproduction.
- All 16 HEAD requests returned 200 and different Content-Length values than the prior expectations; not a body verification or explanation of historical G46 GET headers.
- `plan.review-only.json` is the unchanged old proposal; the separate G48 receipt records actual observations.
- `test_offline.py` tests contracts with network forbidden.
- `analyze.py` reconciles the receipt, original public CDN-config fixture and production catalog hashes with no network fallback. Requires pandas.
- Next footer-only range plan is unexecuted: 16 fixed 28-byte proposals, not approval for full indexes, archive bodies, payloads or runtime policy changes.
