# Bounded mapping-validation repair, 0.1.1

## Trigger and scope
First user report archive SHA-256: `90a926d3ac1f76e53b532c3e14b4cbf474ad2de41207fab20524c159a7b4aa15`.
The prior stop happened before RPM: AllocationBase differed from module base, despite the slot lying inside the loader and a committed/readable MEM_MAPPED region. The allocation delta 0x2040000 equals the pinned DLL's .rdata RVA. The user subsequently asked to continue. This version is a separate bounded correction of that validator, not a claim that the handler detour has a verified connection to protected target pages.

## Narrow accepted geometry
1. Existing whole-module allocation is still geometrically permitted.
2. A split allocation is permitted only for MEM_MAPPED whose AllocationBase exactly equals module base plus the uniquely matching pinned `.rdata` section RVA. That section must contain all eight bytes; its RVA must be allocation-granularity aligned to 0x10000. This tool is fixed to the pinned image, not a general PE-mapping validator.
3. Slot/module/region bounds, readable protection, committed state, correct process creation identity and pinned disk image checks remain mandatory. MEM_PRIVATE and split MEM_IMAGE are rejected. The complete VirtualQueryEx region need not end at the PE section's virtual end; only the fixed eight-byte sample must fit both relevant ranges.
4. Neither geometry is sufficient by itself: both now require independent file-path/hash consistency checks below.

## Independent metadata checks
K32GetMappedFileNameW is called for the slot and AllocationBase. The loader path from module metadata is opened read-only. GetFinalPathNameByHandleW with normalized VOLUME_NAME_NT gives its final NT path. The opened handle itself is hashed and checked for size/mtime consistency. The two mapped paths and opened final path must match (ordinary Windows case-insensitive path assumption) and the hash must equal the pinned loader hash. No path-prefix guessing, QueryDosDevice drive-letter inference, alternate API fallback, memory scans or protection changes are used. Empty/truncated paths or failures stop the probe.

The same operation is performed after the single eight-byte sample. Changed/failed postconditions discard the pointer as a validated result. A precondition failure produces zero direct RPM calls.

## What this does NOT prove
Mapped filename equality is not a queried file-object identity, mapping offset proof or hostile-race defense. Names may be unavailable for anonymous/remapped sections; this version intentionally stops rather than weakening validation. A known filename also does not prove that loaded bytes match disk. Module metadata and path/hash observations are not atomic. The reported export-address equality still assumes the live layout corresponds to the expected image; neither loaded EAT nor code is read. No Windows runtime or game test was performed during construction.

The native API checks are metadata queries separate from the tool's sole explicit process-memory request; no claim is made about OS-internal implementation details of those APIs.

## Other corrections
The own-window monitor retained a CodeRead title in 0.1.0. It now matches the actual APIProbe form and has a regression test. The wrapper's `read_requested` label became `read_helper_requested`, avoiding confusion with actual core RPM counts.

## Sources
- https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew — mapped filename query, PROCESS_QUERY_INFORMATION, K32 export, truncation behavior.
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew — normalized final path, VOLUME_NAME_NT, failure/buffer semantics.

## Decision after this bounded attempt
A standard Windows error-handling API match deprioritizes this detour as a direct decryptor lead. Unresolved identity/API without an independently demonstrated target-page connection parks the detour. No protected page capture, decryptor recovery, CPU/BIOS collection proof or TCP/3724 send proof is claimed by this repair.
