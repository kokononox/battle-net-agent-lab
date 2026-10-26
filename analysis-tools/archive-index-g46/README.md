# G46 public archive-index research

Read `reports/archive-index-g46/RESULT.fa.md` before interpreting results.

- `fetch_indices.py` + `http_contract.py`: preserved live-fetch sources; do not rerun to reproduce the offline analysis.
- `index-plan.review-only.json`: unchanged G45 proposal, hash pinned in `pins.py`.
- `bindings.py`, `index_parser.py`, `locate.py`: offline binding/verification/lookup; never grant runtime approval.
- `test_offline.py`: synthetic and real-fixture checks. Synthetic successes do not represent downloaded payloads.
- Published base64 fixtures contain public index metadata only. No executable/archive payload was fetched in G46.

Actual outcome: 30/46 metadata bodies accepted and verified; 16 rejected before body on response_length. Two sample keys located, one unresolved. Plans for two ranges and 16 HEAD diagnostics are unexecuted proposals, not production configurations.
