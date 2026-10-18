# Explicit one-archive capture: source implementation, not live qualification

`ArchiveReadRequest` requires a pinned TargetSnapshot, exact StreamObjectSpec,
three-digit archive id, absolute byte offset, explicit supported layout and exact
application-content read budget. `capture_archive_stream` accepts an authorized,
unbuffered caller-owned stream and stat size. It does not discover paths or approve
source reads. Unknown layout, out-of-bounds, header disagreement and payload
identity mismatch stop without fallback or source writes.

`WindowsArchiveCapture` pins explicit local fixed-drive root/ancestor handles and
opens precisely Data/data/data.NNN READ/shareREAD. The inherited buffered wrapper
owns the handle, but its read method is never called: the adapter uses the untouched
raw FileIO to avoid buffered application reads beyond a tiny approved span. The
budget does NOT measure OS disk-sector read amplification or physical prefetch.
No .build.info/config/control/index/LRU reads, enumeration, network or CLI exist in
this adapter. observe() is disabled so it cannot silently select metadata mode.

The 30-byte header is a pinned Agent9824 research profile: reversed full EKey,
span size, zero flags, seeded lookup3 checksum and location-bound checksum B.
Direct BLTE is another EXPLICIT layout, never a fallback. Supported archive size
and span end are <=1 GiB; object payload <=256 MiB. Unsupported is not corruption.

After exact-span read, LocalContentCapture independently verifies full EKey/CKey,
BLTE, sizes and hashes, then rereads its private temporary copy. Existing
admit_capture revalidates that copy against exact target candidate/catalogue DBs.
The integration test replaces the source after handle release before admission.
Copy identity is not active generation or product selection authority. Protocol
MD5 plus local SHA256 is not a publisher signature or hostile-collision proof.

Native Windows tests use NEW owned synthetic trees only. They exercise ordinary
writer/delete/rename exclusions, preexisting writer refusal, hardlink rejection,
source-bound failures, cleanup and copy lifetime. They do not establish universal
mapped-writer exclusion or a live installation backend. No game file was opened.

Next blockers: qualified feature/variant/dependency required-set selection;
explicitly approved bounded execution against an independent installation copy;
durable verified cache and transfer recovery; semantic store/quiescence for write;
transactional CASC writer/rollback/activation; future-version and UI qualification.
All installation/apply/reuse authority stays false and required network bytes
remain unknown. This source extends, but does not replace, the unchanged 0.27 ZIP.
