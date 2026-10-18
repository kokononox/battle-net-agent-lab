# Source state — 0.24

Latest addition: product_policy_facts.py, 26 tests and a raw content-key-bound public ProductConfig fixture with exact versions bytes. 648 Linux tests passed. 286 actual Windows/Python 3.12.10 tests passed, no failures/errors/skips. Platform counts overlap. Latest receipt/source are QA.json and reports/WINDOWS-PRODUCT-FACTS-CI-to-share.json. This is release-bound configuration facts, NOT complete vendor selection, live installed identity, production transfer or installer qualification.

Owned-copy CLI only (do NOT use the live game folder):
```sh
python product_policy_facts.py --binding-workspace BINDING --objects-workspace OBJECTS --candidate-workspace PLAN --profile-json PROFILE.json --versions-file SAVED_VERSIONS.txt --product-config-file SAVED_PRODUCT_CONFIG.json --output NEW_REPORT.json
```
Input config is capped at 64 KiB. No network or paths from config are used; output creation is exclusive. The candidate's full existing identity gate runs first. No run is currently requested from the user. Refer to research/PRODUCT-CONFIG-AND-SOURCES.md for provenance and limitations.

## Previous source state (historical)

# Source and offline test instructions — 0.23

This is a research core, NOT a game updater release. Do not point it at a game installation. All automated native tests use newly created synthetic temporary fixtures only.

From updater-core/ after cloning the repository:

```sh
python restore_public_fixtures.py
python -m unittest discover
```

The source repository stores five public metadata fixtures in text encoding; the restoration helper checks their exact expected digests. The local source ZIP already includes those small fixtures. Large decoded metadata, SQLite databases and staged game payloads are not shipped.

Linux regression: 622 tests passed. Windows CI explicitly loads the existing 233 cases plus 27 policy ambiguity audit cases (including synthetic integration): 260 passed with zero failures/errors/skips. Actual Windows source/receipt are in reports/WINDOWS-POLICY-AUDIT-CI-to-share.json and QA.json. Platform counts overlap and must not be added. No live game/network/official client is exercised. These tests verify audit logic, not vendor selection policy.

Do not run run_portable_ci.py on Linux expecting success: it is explicitly Windows-only. It produces a new minimal JSON receipt; it never invokes an installer. The existing Agent observation workflow is separate and unchanged.

Synthetic native staging success is not production qualification. Exact-type Windows candidate admission is integrated for verified owned staging input only; official selection policy, active installed generation, full local reuse, production network/recovery qualification, native CASC transaction/rollback/activation and real power-loss recovery remain open. No live apply is authorized. Historical target 12.1.5.70448 is a pinned research snapshot, not a claim about the current newest version. Product resolution must remain version-independent.

The new HTTP adapter is integrated through an explicit bounded grant and durable attempt ledger. All 53 transfer tests use synthetic data; HTTP is mocked. No real game CDN transfer was executed. Ambiguous pending attempts stop and cannot auto-retry. See research/TRANSFER-SAFETY.md.

Explicit local reconciliation (0.21) may accept exactly one already-journaled reserved range after predecessor reconstruction, fresh segment/full-object verification as applicable, and shared-entity checks. It does not fetch, retry, reset budget, break locks, adopt orphans or automatically continue. Uncommitted pending attempts remain blocked. See research/RECONCILIATION-SAFETY.md.

Explicit scope lifecycle: see research/SCOPE-RETIREMENT-SAFETY.md. It never calls fetch/step, refunds a consumed reservation, breaks a lock or authorizes installation.

Policy audit of EXISTING OWNED COPIES only (never game directory):
```sh
python policy_ambiguity_review.py --binding-workspace BINDING --objects-workspace OBJECTS --candidate-workspace PLAN --profile-json PUBLIC_PROFILE.json --output NEW_REPORT.json
```
Output creation is exclusive. Full source/plan hashes are rechecked. Reference protocol: research/POLICY-REFERENCE-PROTOCOL.md. A fresh metadata pair reader was NOT implemented/qualified in this release.
