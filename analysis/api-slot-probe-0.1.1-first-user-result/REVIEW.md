# APIProbe 0.1.1 — first user report; explicit stop decision

## Verified report outcome
The revised geometry gate accepted `pinned_rdata_section_allocation`, addressing the first report's allocation-base assumption. The independent mapped-file name query then failed on its **first call, at the slot address**, with Win32 1006 (`ERROR_FILE_INVALID`). No slot mapped filename was returned. Inspection of the exact native source establishes that this returns before the allocation-base filename query or the Backing method's disk-file open/hash. Earlier pinned-image disk checks are separate and had passed the control flow leading to this gate.

Core accounting is **zero ReadProcessMemory calls, zero bytes requested and zero bytes returned**. No pointer or API name was recovered. The wrapper requested the read helper, not necessarily a memory read; that distinction remains material.

The wrapper records the same game process alive/responding in its metadata observations. The user supplied no separate usability statement with this archive. These observations are not a full stability claim.

## What error 1006 does and does not establish
Microsoft labels 1006 as ERROR_FILE_INVALID: “The volume for a file has been externally altered so that the opened file is no longer valid.” This is the status returned for the mapped-filename operation in this report; the generic text is **not a root-cause diagnosis** of the user's entire G: drive.

The report does not independently demonstrate disk corruption, a filesystem change, an anti-cheat intervention, anonymous mapping, or deliberate filename concealment. It also does not establish that RPM would fail: RPM was never attempted. No disk repair, reformat, driver/security changes or larger privilege request follows from this result.

## Decision — honor the announced stopping rule
The mapping ownership consistency check is unresolved on this run. SetUnhandledExceptionFilter remains a static hypothesis, not a runtime identification. Do not convert this negative metadata result into a confirmed standard-error API, a recovered decryptor, a blanket memory-access impossibility, or proof of network sending.

Park this API/handler detour. No v0.1.2 is produced merely by deleting the failed identity check, no immediate rerun is requested, and no new live tool is claimed necessary from this archive alone. Any future reopening requires independent evidence connecting this path to the target protected pages, not another speculative address hop.

The original CPU/BIOS → population/serialization → TCP/3724 question remains open. Further work should use a separately justified lead in the existing offline materials; none is claimed discovered in this report review.

## Evidence and source boundaries
Only the small user report was read as data. No supplied code was executed; raw user paths/PIDs/logs and game binaries are not committed. `findings.json` preserves report hash and sanitized outcomes. Main and BIOS Path GUI 0.2 were not modified.

Native call sequence: `analysis/api-slot-probe-0.1.1/source/native_windows.go`, committed in 5a149874a8b18797242bf73d6a9db11131ea5939.
Official error definition: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-
Mapped-name API contract: https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew
