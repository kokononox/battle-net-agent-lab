# Observer 0.2.1 — user-approved 1 GiB soft budget and raw cleanup

Supersedes 0.2.0 for the next test. User approved increasing the raw-file allowance and eventual deletion.

- Soft capture budget raised from 128 MiB to 1 GiB; still polled, not a hard cap. Runtime request remains 20 seconds. Reserve checks unchanged; starting capture requires 3 GiB on the non-system capture drive and 1 GiB on Windows drive.
- Direct PML reader allows up to 2 GiB to accommodate finalization/soft-budget overshoot; event/time/structure bounds remain, with 3 million event read ceiling and 120-second analysis worker timeout. No XML conversion or debugger/injection.
- Save minimized JSON first. Then delete ONLY own raw capture PML and numbered split files in the fresh UUID session folder, including on analysis failure. Raw evidence will therefore not be available for later reanalysis after successful deletion.
- Never delete arbitrary directories, old sessions, game files, or unrelated PML files. Retain raw files if report save failed, Procmon presence cannot be ruled out, path is redirected/untrusted, or deletion is denied. Actual cleanup status is appended atomically to JSON; initial report survives update failure.
- Deletion uses filesystem unlink, not Recycle Bin; space may remain allocated until existing handles close. No secure-erasure claim and no direct remote access to the user PC.
- 52 synthetic-unit/filesystem/static-guard tests and 2 isolated worker smoke tests passed. Windows native capture, Windows lock behavior and Procmon 4.12 PML end-to-end compatibility remain unvalidated.
- No firewall/hosts/VPN/whitelist/certificates/game settings changes. No raw user logs, captures, hardware values or game binaries committed.

Standalone: WoW-Dependency-Observer-0.2.1-Full.zip
SHA256: d0e26ed84d70f9a93b541a171ebc876064d7bed1663bf337414c02266cc99491
