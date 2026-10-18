# Independent policy reference protocol — research only

## What this step does and does not do
The 0.23 ambiguity audit consumes existing verified copied Install/Download metadata, the exact pinned target and typed public profile. It reproduces candidate membership, partitions feature membership and emits bounded deterministic examples and duplicate-label questions. It changes no plan and does not promote candidate membership to a required set. Counts are descriptive, not an independent oracle.

The target in the saved report is a historical pinned build. An observation from a different build/profile cannot be silently compared or used to close the old case. General future-version behavior still needs independently verified rules or a qualified version-aware reference. Matching a handful of sample cases is necessary evidence for those cases only, never proof of policy completeness or dependency/patch closure.

## Existing source and evidence checks
- Existing selection_policy.review_existing_candidate rehashes the full target catalogue, candidate database, consumed decoded manifests and their bound configuration identities. Metadata/source/target/profile disagreement stops the audit.
- The pure audit covers every manifest ordinal for counts, masks padded bits, and emits at most two earliest ordinals per nonempty feature/candidate cell. Each feature has four disjoint cells; they sum to manifest count. Different features may overlap and are not additive.
- Independent per-ordinal bit checks verify counts and each sample's membership, without using the integer-intersection implementation. They verify arithmetic only, NOT Battle.net semantics.
- All manifest rows remain in scope, including unselected and untagged-per-dimension rows. No cleaning/exclusion is based on a plausibility hint. Duplicate-label groups use opaque slash/casefold metadata, not host paths. At most 16 groups and 8 rows per group are displayed; omitted groups/rows are explicit. There is no choice of variant or EKey.
- Source hashes and candidate SHA are retained in the output. Only public metadata labels/keys, derived counts and bounded question samples are emitted; no payload bytes, private tags, account identifiers, game directory paths, SQLite or large decoded files are shipped.

## Exact reference information needed
A usable independent reference must identify:
1. Reference provenance: documented algorithm and its applicable versions, or a pre-existing official client plan/membership result with a known product/build/profile. Self-generated candidate expectations are not independent.
2. Exact product/branch/region/build config and Install/Download metadata digests. Target snapshot aliases or filenames alone are not enough.
3. Actual platform/architecture and separately selected text/speech locales and supported feature preferences, without account data. A guessed old tag row is not a fresh preference observation.
4. For each sample under test: manifest kind, manifest ordinal and full CKey/EKey/size identity, plus included/excluded/unknown. Unknown is not excluded. Absence from a download log does NOT imply exclusion: the object may be installed, cached or transferred under a different representation.
5. Explanation or observations covering Alternate/Talebound, duplicate-label variants, multiple encoding representations, dependency closure and patch/full selection. Per-object membership alone cannot prove closure.

## User-action boundary
No official client execution, update or capture is authorized by this document. No capture program is shipped in 0.23. Do NOT run an update/repair or collect broad logs. Before any future live reference capture, separately define and approve the exact clone workspace, official executable/action, possible network and write budgets, input paths/byte limits, credential-free privacy filter and stop conditions. A read-only assistant probe cannot manufacture an official client selection plan if none is available.

If an existing independent documented algorithm or sanitized plan is available, inspect its scope first and compare only matching cases. If unavailable, report the blocker; do not mark policy complete, silently adopt extractor defaults, or ask the user for arbitrary large files. Fresh identity and active-generation qualification remain separate open parts of milestone 1.

## Data profiling interpretation
The copied receipt JSONs are single nested provenance documents, not event tables; the generic profiler's flattened duplicates/nulls/mixed types are structural, not missing manifest records. Their time fields are provenance timestamps, not a time series. Catalogue table row counts have different grains and must not be summed into a rate. Raw custom binary manifests are parsed by the existing strict readers, not inferred by a tabular profiler. The derived partitions.csv has grain (manifest, feature, candidate_selected, tag_member); its 24 rows have no duplicate full rows. Boolean-text categories are deliberate, no date/numeric imputation or row dropping is performed.

No chart is required for this implementation handoff: the deliverable is bounded record-identity questions and software tests, not an inferred preference comparison or trend. A bar chart would not resolve membership semantics.
