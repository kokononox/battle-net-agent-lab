# APIProbe 0.1.0 — first user execution

## Verified outcome
The user report says `read_stopped: slot mapping/bounds mismatch`. The core reports **zero ReadProcessMemory calls, zero requested bytes and zero returned bytes**. The wrapper field `read_requested: true` only records launching the helper; it is not evidence that the core issued RPM.

The fixed slot is inside both the loader module range and the queried region. The region is committed MEM_MAPPED / PAGE_READONLY, not PAGE_NOACCESS or PAGE_GUARD. Of the mapping/bounds conjunction in `gate`, the failing condition is `region.AllocationBase != loader.Base`.

The reported allocation base equals loader base + 0x2040000. In the pinned offline DLL, **0x2040000 is exactly the .rdata section RVA**, and the fixed slot 0x20A0750 lies in that section. This supports a section-based mapping interpretation. It does not independently prove the mapped region's backing-file identity or reconstruct the complete loader map.

## Correction to the tool's assumption
APIProbe 0.1.0 permits MEM_MAPPED in name, but its allocation-base equality condition rejects section-based mappings of this shape. That condition was overly restrictive for the observed layout. The user did not run the wrong test and this result is not a low-disk-space failure, a demonstrated RPM access denial, or a demonstrated anti-cheat reaction.

Do not remove the check blindly or request broader process rights. A future revised probe would need an explicit, tested provenance rule for section mappings, preferably independently checking mapped-file identity where available. A section-offset coincidence alone should not silently be promoted to proof of identity. No such revised probe has been built or validated in this follow-up.

## Limits and stop decision
- The pointer was not sampled. SetUnhandledExceptionFilter remains a hypothesis; no API name has been resolved by this run.
- Metadata observations recorded the same process alive/responding at three times. They do not establish subjective usability or long-term stability; the user did not state usability in this message.
- Per the previously announced stop rule, the handler/API detour is parked as an unconfirmed lead. No additional live attempt is requested from this report alone. A mapping-validation repair would be a separate, bounded proposal, not proof that this branch connects to target code pages.
- CPU/BIOS collection → serialization → TCP/3724 remains unresolved. This report provides no recovered protected code or network payload evidence.

## Evidence handling
The note and small report ZIP were read as data only. Supplied scripts were not executed. `findings.json` preserves the exact address arithmetic and input archive SHA-256 without local user paths or raw logs. Main and BIOS Path GUI 0.2 were not modified.
