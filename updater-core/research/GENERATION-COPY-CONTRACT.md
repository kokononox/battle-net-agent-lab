# Two-round copied-generation consistency contract — 0.27

## What is implemented
`generation_copy_contract.py` is a pure, offline byte-input contract, not a live reader. It accepts two typed `GenerationCopy` rounds, each with build info, build config, copied control bytes, an explicit inventory and exactly sixteen index byte copies. It has no path discovery, enumeration, filesystem/native calls, network, retries, repair, lock removal or write API.

The existing V4/V5 copied-control research reader determines the sixteen referenced member names. All must exist in the explicit inventory and supplied index mapping. Newer filenames are never substituted. Before/after metadata, entire control bytes, inventory SET and all sixteen index bytes must agree. Inventory order alone is irrelevant. The Retail baseline/config identity and preference grammar are revalidated. Research control states reset/pending stop; no rollback/recount/recovery is attempted. State one is merely an accepted research diagnostic state, not a proven health/quiescence condition.

Each selected index is independently parsed under one of the already bounded supported families: V7 continuous primary/zero tail; V8 supported primary/empty tail, with qwords opaque. Header/bucket and rolling checksums are checked. Unsupported headers/tails/formats and mixed V7/V8 families stop; mixing may be legitimate in an unknown format, but this contract does not claim to support it. This is NOT a diagnosis of corruption. Index checksums are noncryptographic structural checks, not authenticity or payload proof. No archive locators are promoted to reuse evidence.

The bundle SHA256 binds the metadata/control digests, sorted inventory and ordered selected index identities/sizes. It does not bind root, capture time, actual read order, native file IDs or an Agent/launcher decision. Exactly equal sequential byte rounds can miss an ABA change (A→B→A); they are not an atomic snapshot or proof of no intervening changes. Even a synthetically perfect bundle returns active_generation_proven=false, coherent_live_snapshot_proven=false, local_reuse_authorized=false and installation_ready/apply_authorized=false.

## Bounds and privacy
- Per round: info <=1 MiB; config <=4 MiB; control <=64 KiB; exactly 16 indexes each <=4 MiB; inventory 16..512 safe index member names.
- Maximum supplied bytes per round: 72,417,280; two rounds: 144,834,560. These are API input ceilings, NOT a request or permission to read a live game. V8 additionally inherits its <=1-MiB primary-profile cap.
- No raw control name, account/geoip qualifier, root path, opaque array or archive payload is exported. Success output contains public baseline/preference facts, index member/checksum identities and fixed blockers only. Native exception sanitization is not relevant here because there is no native IO; this is still not a public upload tool.
- The fixture report is SYNTHETIC ONLY. No new historical user control/index bytes were opened in this step. Only the old sanitized `SHMEM-COPY-REVIEW-to-share.json` report was consulted; it had already reported V5, 16 referenced names and an extension whose full semantics remained unqualified. That old report was not revalidated or treated as fresh evidence. No user filesystem, game CDN, shmem/LRU file or archive was accessed.

## Why live proof is deliberately still blocked
1. Independently qualify the control protocol and exact role of generation slots; existing reverse-engineering/research profiles alone are not official activation evidence.
2. Bind the control to the correct store/root, actual build/profile and native file identities; a control name or a matching inventory alone is insufficient.
3. Define valid stable/error/extension states, including unknown-version behavior and supported mixed generations. The observed historical extension has unknown full semantics.
4. Design a native bounded read capture with held file/directory identities and explicit compatible-sharing policy; two earlier metadata handles do NOT cover control or all selected indexes. No generic full-store lock or hostile-process guarantee is assumed.
5. Define independent observation showing which generation the client actually uses. Decide a source/experiment with bounded privacy/network/write scope BEFORE asking the user to run anything. Do not silently launch Agent, update, repair, scan, inspect LRU or expand storage reads.

Until these criteria are met, do not ship a user-facing live probe claiming active-generation proof. No user action or new read permission is requested now. The next research task is the versioned control/store binding and independent-use evidence, not writing an installer around unqualified locators. Complete feature/variant/dependency selection and genuinely fresh preferences remain separately open in milestone 1.

## Tests and provenance
40 new synthetic adversarial tests: all sixteen V7/V8 headers/checksums, both known control profiles, extensions as blockers, changed rounds, missing/newer members, pending/reset, mixed/unknown index family, nonempty tails, budgets, private redaction, baseline tamper, typed input and no-authority promotion. `reports/GENERATION-COPY-CONTRACT-SYNTHETIC-to-share.json` is generated only from these synthetic fixtures.

The reusable logic has no historical build-number constant. Existing installed metadata validation handles arbitrary supported Retail versions; unknown schema or index/control format stops rather than guessing. This is contract implementation and negative testing, NOT a completed active-generation detector.

Existing reviewed research references (not executed anew):
- copied_control.py and local_v8_readonly.py link the project's pinned Agent-9824 research at commit 7916903f5378f72a28f745fd30fe3ae11670451a.
- https://github.com/ladislav-zezula/CascLib/blob/38a34665624b8775bb875274b36191b21c38d97b/src/CascIndexFiles.cpp : maximum-generation filename extraction behavior is not activation proof.
- https://github.com/wowemulation-dev/cascette-py/blob/dc0dfb89b146d80b363741de25c2be340c2da8fd/cascette_tools/core/shmem.py : claimed offsets and permissive recovery/write helpers remain unadopted and unqualified. No source code from that module was imported or executed.
