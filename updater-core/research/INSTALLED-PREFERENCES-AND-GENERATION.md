# Installed preference clauses and bounded metadata observation — 0.25

## Implemented and observed
`installed_preferences.py` validates the existing Retail build identity and config MD5 before interpreting public `.build.info` tag clauses. Colon clauses and optional markers are retained. Exactly one platform, architecture, region, locale and text/speech category must be present in each supported clause; ambiguous, unknown or inconsistent clauses fail closed. Text and speech locales are not unioned into a cross product. Private optional acct/geoip qualifiers are withheld, with only their count exported. Unsupported feature tokens remain a stop, not an invented selection rule. ARM64 normalization is explicit.

The historical user-uploaded metadata copies independently pass this reader: baseline 12.1.0.69933, Windows/x86_64/EU, text=enUS and speech=enUS. Four private qualifiers were withheld. `reports/INSTALLED-PREFERENCE-COPY-to-share.json` contains public facts only. This is NOT a fresh launcher preference capture. No live game was accessed, no shmem/LRU content read, no game CDN requested, and no candidate plan changed. ProductConfig integration also keeps alias changes visible as a replan-review gate, rather than rewriting user intent silently.

`windows_metadata_pair.py` is a LIBRARY, not a user-facing live capture tool or installer. On an explicitly supplied local fixed-drive root it holds every ancestor directory against ordinary rename/delete, opens only `.build.info` and the build-config path derived from its validated active row, denies ordinary write/delete sharing for both files, validates both, then re-reads both before returning. Single-link regular files, no reparse/offline/recall, capped sizes (1 MiB + 4 MiB, at most twice those content bytes read), no enumeration, no writes, no network, no shmem, no LRU, no index/archive. There is no raw root or private tag in a success report. A failed call can raise a native OS error with a path; it is not a sanitized report/CLI. `game_access=null` on arbitrary roots means root ownership is NOT inferred. This does not authorize using a live installation. Native ordinary share locks are not an OS snapshot, protection against hostile/privileged processes or a full multi-file storage consistency proof.

## Why active generation is NOT solved by these files
`.build.info` Active=1 identifies a build row, not a coherent CASC index generation. CascLib's maximum filename-generation-per-bucket behavior is an extractor heuristic, not an updater activation oracle.

Pinned source inspected:
- https://github.com/ladislav-zezula/CascLib/blob/38a34665624b8775bb875274b36191b21c38d97b/src/CascIndexFiles.cpp
- https://github.com/wowemulation-dev/cascette-py/blob/dc0dfb89b146d80b363741de25c2be340c2da8fd/cascette_tools/core/shmem.py
- https://github.com/wowemulation-dev/cascette-py/blob/dc0dfb89b146d80b363741de25c2be340c2da8fd/cascette_tools/formats/size.py

The community shmem implementation claims V4/V5 generation slots at 0x110, but accepts warning states, has recount recovery and write/lock helpers. NONE of that code was executed/imported/adopted. The offsets are an unqualified hypothesis, not proof against this user's copied 20-KiB files or the opaque V8 fields. Only historical ZIP member names and sizes were inspected; no shmem bytes were read in this work. Unknown format is still unknown. The same source's size-tag query parser splits on commas/colon rather than the spaces in the actual build-info clauses, and unknown/empty tags may select all. It is not a drop-in grammar or qualified Install/Download oracle. The Classic Era timestamp narrative is not Retail activation evidence.

## Next steps, in order
1. Qualify complete applicable selection semantics (including unknown feature/variant/dependency terms) and obtain genuinely fresh explicit preferences. Historical tag parsing alone is insufficient.
2. Design a generation observation with bounded path/content/privacy scope, format identity and independent consistency criteria before requesting any user run. Do not guess offsets, read shmem/LRU automatically or select maximum filenames. Unknown versions stop safely.
3. Only after those gates: establish reusable local object evidence, required set and exact network bytes; qualify actual transport/recovery; implement and qualify transactional CASC writing, rollback and activation on an isolated copy; then UI/release and future-version regression.

No user action is requested now. No game copy, broad upload, admin/ACL change or official update/repair is requested. A future bounded capture requires its own reviewed tool, privacy scope and explicit approval. Milestone 1 remains open; required_set_selected, active_generation_proven, installation_ready and apply_authorized remain false; required_network_download_bytes is null.
