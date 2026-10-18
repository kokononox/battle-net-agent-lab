# Source and offline test instructions — 0.19

This is a research core, NOT a game updater release. Do not point it at a game installation. All automated native tests use newly created synthetic temporary fixtures only.

From updater-core/ after cloning the repository:

```sh
python restore_public_fixtures.py
python -m unittest discover
```

The source repository stores five public metadata fixtures in text encoding; the restoration helper checks their exact expected digests. The local source ZIP already includes those small fixtures. Large decoded metadata, SQLite databases and staged game payloads are not shipped.

Linux regression: 483 tests passed. On Windows, the separate CI explicitly loads 73 portable parser/selection plus 38 native scratch and 10 native candidate admission tests: 121 passed, zero skips/errors/failures. Native cases are deliberately not part of Linux discovery. See reports/WINDOWS-ADMISSION-CI-to-share.json for the exact source commit and reports/WINDOWS-STAGE-FIRST-FAILURE-to-share.json for the fixed directory-sharing regression.

Do not run run_portable_ci.py on Linux expecting success: it is explicitly Windows-only. It produces a new minimal JSON receipt; it never invokes an installer. The existing Agent observation workflow is separate and unchanged.

Synthetic native staging success is not production qualification. Exact-type Windows candidate admission is integrated for verified owned staging input only; official selection policy, active installed generation, full local reuse, multiobject network transport, native CASC transaction/rollback/activation and real power-loss recovery remain open. No live apply is authorized. Historical target 12.1.5.70448 is a pinned research snapshot, not a claim about the current newest version. Product resolution must remain version-independent.
