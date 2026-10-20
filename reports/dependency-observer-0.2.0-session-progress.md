# Dependency Observer 0.2.0 — storage-safe redesign (experimental)

## Why replaced
The previous system-wide Procmon-to-stack-XML conversion timed out. The user subsequently reported a full Windows drive and a roughly 2.8 GB file; the design plausibly contributed, but the exact causal chain is not established. The original PML was deleted, so recovery from that recording is unavailable. No network/DLL findings have been inferred from a status-only failure JSON.

## Changes
- Keep game normally running at login, no debugger, injection, forced game launch, TLS MITM or account credentials.
- Require extraction to local NTFS non-C and non-system storage; compare actual volume identity to catch mount aliases. Refuse redirected capture folders.
- Put raw capture and optional official-tool download beside the package, not LocalAppData.
- Request 20 seconds capture; monitor a 128 MiB SOFT raw budget and free-space reserves. No hard-cap or zero-system-disk-write claim. Procmon/Windows can still write system files.
- Stop only an identified wrapper-owned Procmon instance; no unidentified global termination or force kill.
- Remove XML conversion entirely. Read supported PML v9 metadata directly in a timeout-isolated worker. Unknown versions, unfinalized files or bounds violations are inconclusive, with no format bypass or XML fallback.
- Selected exact-image processes, explicitly labeled PID/lifetime or game-folder candidates, outgoing endpoints, module basenames and optional stack-range hints. No DLL causality, plaintext, domain exclusivity or CPU/BIOS-upload claim.
- Startup events and helper-service IPC outside the short sample may be missed. Capture-category completeness is not certified. No observed traffic does NOT mean no transmission.
- Do not upload PML/XML/game binaries/private logs/hardware values. Share only minimized JSON.

## Validation
38 synthetic-unit/static-guard tests and 2 isolated analysis-worker smoke tests passed; Python syntax checks passed. 34 runtime files matched prior verified manifest. No native Windows end-to-end test or native Procmon 4.12-generated PML test was available. Therefore this is an experimental replacement, not a certified fix or guarantee of game compatibility.

Standalone ZIP: WoW-Dependency-Observer-0.2.0-Full.zip
SHA256: 992afda096e3b1c131d616572acb9f39ab781e7d7ef37a2ac3d2b2e0371e10fa
Source-only files are under tools/wow-dependency-observer-0.2.0/. No raw user captures or runtime/game binaries were committed.
