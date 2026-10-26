# G51: privacy-goal acceptance audit, NOT a new downloader

Run `python analysis-tools/privacy-acceptance-g51/audit.py` from the research checkout. Read `reports/privacy-acceptance-g51/RESULT.fa.md` for outcome and limits.

The audit loads existing G37 broker and G41 protocol/quarantine sources. All OS socket creation is forbidden. Windows peer admission is explicitly stubbed for in-memory Handler tests; native security is not tested. No real TLS or Battle.net process is involved.

Expected findings, not an acceptance pass:
- Seven arbitrary allowed-host HTTP marker variants reach the legacy handler's in-memory upstream.
- Quarantine blocks all seven with no upstream, but offers no downloads.
- Fixed offline broker rejects 23 direct and 1000 independently executed variants before fixture fetch and serves one fixed synthetic fixture.
- A trusted but privacy-bad catalog can still bake a marker into a syntactically allowed path.
- Original G37 1000-variant test actually executes download once due to indentation; direct call counting reproduces this. New audit executes every variant, without rewriting historical source/evidence.

A successful exit means these audit observations were reproduced, NOT that the user privacy goal passed. Machine evidence explicitly sets user_goal_met=false. Run without -O, which disables assertions. No integration with a production release gate, Windows launcher, or online broker is claimed.
