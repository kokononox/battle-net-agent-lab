# G50: complete pinned-snapshot index coverage and third-sample location

Read `reports/complete-index-g50/RESULT.fa.md` for scope and caveats.

- 16 footer-bound live metadata GETs received and fully verified, 272368 body bytes.
- Combined with 30 reverified G46 fixtures: all 46 pinned snapshot indexes covered (45 archive, 1 loose). This is not all Battle.net data/builds/patches.
- Third sample located in index_2, archive 11997641538a447ba9b7026a1145da9c, offset 65064708, length 7461. No third-sample payload was fetched in G50.
- `index_parser.py` is copied unchanged from G46.
- `fetch_indices.py`, `http_contract.py`, `pins.py`: preserved preflight-pinned live sources; do not rerun for offline reproduction.
- `test_offline.py`: 19 pre-fetch contract/fixture tests.
- `locate.py`: offline receipt/source/footer bindings, complete fixture revalidation and pinned-sample lookup. No network fallback.
- `test_live_evidence.py`: 4 post-fetch OFFLINE tests, including independent raw aligned-record lookup of sample_3. The filename does not mean live network tests.
- Next third-sample Range proposal is unexecuted. No arbitrary URL/range, installer execution, production broker integration or runtime approval.

Public fixtures contain index metadata only, not executable payloads or private captures. Receipt is separate from unchanged executed=false source proposal. Metadata hashes are not a publisher signature or anti-fingerprinting proof.
