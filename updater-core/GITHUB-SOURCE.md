# Source and offline test instructions — 0.22

This is a research core, NOT a game updater release. Do not point it at a game installation. All automated native tests use newly created synthetic temporary fixtures only.

From updater-core/ after cloning the repository:

```sh
python restore_public_fixtures.py
python -m unittest discover
```

The source repository stores five public metadata fixtures in text encoding; the restoration helper checks their exact expected digests. The local source ZIP already includes those small fixtures. Large decoded metadata, SQLite databases and staged game payloads are not shipped.

Linux regression: 595 tests passed. The Windows-only CI suite loads 73 portable parser/selection, 38 native scratch, 10 native candidate admission, 53 bounded transfer, 26 local reconciliation and 33 scope lifecycle cases: 233 passed with zero skips/errors/failures. Actual result and immutable source commit are recorded in reports/WINDOWS-SCOPE-CI-to-share.json. Platform counts overlap and must not be added. Native-only cases are intentionally not in Linux discovery. Earlier directory-sharing failure evidence is preserved in reports/WINDOWS-STAGE-FIRST-FAILURE-to-share.json.

Do not run run_portable_ci.py on Linux expecting success: it is explicitly Windows-only. It produces a new minimal JSON receipt; it never invokes an installer. The existing Agent observation workflow is separate and unchanged.

Synthetic native staging success is not production qualification. Exact-type Windows candidate admission is integrated for verified owned staging input only; official selection policy, active installed generation, full local reuse, production network/recovery qualification, native CASC transaction/rollback/activation and real power-loss recovery remain open. No live apply is authorized. Historical target 12.1.5.70448 is a pinned research snapshot, not a claim about the current newest version. Product resolution must remain version-independent.

The new HTTP adapter is integrated through an explicit bounded grant and durable attempt ledger. All 53 transfer tests use synthetic data; HTTP is mocked. No real game CDN transfer was executed. Ambiguous pending attempts stop and cannot auto-retry. See research/TRANSFER-SAFETY.md.

Explicit local reconciliation (0.21) may accept exactly one already-journaled reserved range after predecessor reconstruction, fresh segment/full-object verification as applicable, and shared-entity checks. It does not fetch, retry, reset budget, break locks, adopt orphans or automatically continue. Uncommitted pending attempts remain blocked. See research/RECONCILIATION-SAFETY.md.

Explicit scope lifecycle: see research/SCOPE-RETIREMENT-SAFETY.md. It never calls fetch/step, refunds a consumed reservation, breaks a lock or authorizes installation.
