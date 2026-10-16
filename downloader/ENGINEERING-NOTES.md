# Scope and integration boundary

This is executable repair infrastructure, not a new index-diagnostic version.
It does not replace or mutate any earlier package, game file, cache or report.
The GUI and the CASC writer are deliberately not attached.

## Full Download inventory increment

`target_metadata.py` discovers an EU target from official HTTPS tables, verifies
BuildConfig/CDNConfig hashes and Retail build identity, and binds the complete
Download manifest's CKey/EKey/decoded and encoded sizes. No arbitrary asset is
assumed loose just because an EKey exists. The known Download manifest object is
requested directly, in line with the documented metadata organization.

`download_inventory.py` verifies the decoded object's CKey, parses DL 1/2/3 into
bounded-cache, disk-backed SQLite, retains every original record and tag bitmap,
and provides a unique-object view ONLY after rejecting conflicting sizes for the
same full EKey. Records with equal EKey and size are not silently erased. Counts
and byte sums are independently reconciled against raw accumulation.

The DL inventory itself does not filter tags. The later planner applies only an
explicit conservative profile model, not the earlier strict AND subset as a
complete installation recipe. Untagged/shared records remain.
Zero-sized objects, unknown tag types, raw checksum/flags/priority and unused
bitmap padding are observations, not content-verification or corruption verdicts.
Priority-minus-base is an exposed arithmetic field, not a vendor scheduling proof.
The actual manifest tested here was DL v1. Its 31 tag masks had nonzero unused
padding bits; these are excluded from membership counts, not called corruption.

The discovery/config chain and actual Download object were tested over HTTPS on
Linux. No user game directory was read and no bulk game asset was downloaded.
The full manifest/database is kept in the builder workspace, NOT distributed in
this source package. See LIVE-METADATA-TEST.json for the measured scope.

If the official target changes before the final recheck, prepare_inventory raises.
Its private pinned DB may remain, but no fresh ready-to-download plan is returned.
No global version lock or continuous latest-version guarantee is claimed.

Sources used for independent implementation, not copied as a shipping dependency:
- https://wowdev.wiki/TACT#Download_manifest
- https://github.com/ladislav-zezula/CascLib/blob/38a34665624b8775bb875274b36191b21c38d97b/src/CascStructs.h
- https://github.com/ladislav-zezula/CascLib/blob/38a34665624b8775bb875274b36191b21c38d97b/src/CascOpenStorage.cpp

## Reuse

`decoded_payload.py` is byte-for-byte from the project's verified decoded staging
0.30, SHA-256:
`408428f62f190ce13b6bd61e1763f247f6e4dc0f381fbbeeee61a3ae3f740062`.

## Encoding/catalog/conditional plan increment

The earlier project's `encoding_readonly.py` and `cdn_catalog.py` are retained
unchanged. Full index validation uses an EMPTY wanted set so the earlier 16K
match-output cap never becomes a silent limit on full catalog ingestion.

Encoding is mapped read-only, verified by decoded CKey and all C/E page hashes,
then loaded into bounded-cache SQLite. Full EKeys, alternatives, decoded sizes
and encoded sizes are preserved. An EKey mapping to different CKeys remains an
ambiguous blocker; DL/Encoding size disagreement is never resolved by guessing.

The initial real test exposed an incorrect assumption: archive-group is a
client-generated aggregate, not a CDN object. The failed group request was not
treated as missing content, and was NOT retried via HTTP, proxy or another host.
The corrected acquisition never fetches group remotely. It checks a configured
owned cached group, or fetches the real configured archive indices, bounded to
four parallel metadata transfers and an aggregate byte/request budget. Every
accepted catalog still receives full checksum/order/range verification.
Reference: https://wowdev.wiki/TACT#archive-group

Plan source DBs are attached with explicit read-only SQLite URIs, not as writable
databases. Target bindings must agree. Inputs are watched before output
publication; concurrent source changes block publication. Outputs are separate,
unique lab files. They are not authenticated against a malicious local owner.

The Windows/EU profile is explicit; no user locale is assumed. Matching OR
unclassified records are kept within each platform/architecture/region/locale
dimension; locales are unioned, dimensions intersected. Optional tags stay.
This conservative model must not be described as official vendor selection.

Cache evidence is BATCHED, candidate-based, not a recursive/global disk scan.
Candidates can be explicit decoded files, encoded files, or exact logical CASC
spans. A span is accepted only if its total indexed size is the known encoded
size or encoded size+30, within physical file bounds, and full EKey/CKey proof
passes. Zero wrapper fields, matching 9-byte prefixes and generation filenames
do NOT establish content identity. All bytes are discarded after verification,
not saved or executed. A mismatch is not a corruption verdict on the whole file.

Decoded content availability and exact encoded-representation availability are
separate flags. Only the latter reduces conditional encoded transfer bytes.
Evidence binds to the unique source plan ID, not just the target version.
Unknown/unread/unsupported candidates stay unknown; no exact download size is
reported without complete local-game coverage and final installation policy.

SQLite compatibility regression: SQLite 3.40 reported false NULL violations for
a WITHOUT ROWID table whose composite PK columns were interleaved with a non-PK
column. Reordered the schema's PK columns together and used named INSERT columns;
integrity checks remain enabled. No integrity check was bypassed.

## Transaction protocol

1. Acquire cooperative OS workspace lock. Recover unfinished journals first.
2. Scan requested standalone files; bind damaged/missing baselines by size/SHA-256.
3. Acquire only missing content, retaining encoded partials. Validate HTTP ranges,
   complete BLTE EKey, decoded CKey and decoded disk readback.
4. Check transaction space including larger original-file restoration temporary.
5. Copy verified decoded files into transaction staging. Copy/re-hash every existing
   baseline into backup BEFORE replacing any target. Publish prepared journal.
6. Publish applying journal. Recheck baseline and backup. Copy new bytes into a
   same-directory temporary, fsync and replace each file. Read back each file.
   Persist row completion. Verify all changed targets before logical commit.
7. A normal error attempts rollback. Recovery from a terminated process uses disk
   journal, not the last in-memory row status. A replacement can have happened
   before row completion was journaled.
8. Rollback preflights every target and backup. Only expected old/new content is
   admissible. Unknown content blocks automatic rollback and retains evidence.
   Original missing files are returned to absence; original files are restored
   from verified backup, without downloading.
9. A durable committed journal is never replayed over later repairs. If journal
   publication succeeds but directory sync raises, consult durable journal before
   deciding whether rollback is permitted.

The journal is not a security boundary against local tampering by its owner.
No arbitrary path stored in the journal is used for backup/stage lookup; those are
fixed ordinal names inside the owning transaction. Journals bind to workspace ID.

## Resume

Partial names bind source route + EKey + CKey + sizes + target path. For an archive
range, resume adds downloaded length to the original archive offset. A server
ignoring Range is rejected, never appended as if it were a correct suffix.
No trust is placed in a retained partial just because its length matches:
full encoded/decoded integrity is recomputed before materialization.
Oversized or payload-invalid partials are quarantined inside the owned workspace.
Interrupted or cancelled valid prefixes remain. There is no hidden retry loop.

## Acceptance evidence

See TEST-RESULTS.json and the verbose unit-test log. Process-termination tests start
a separate Python process and call os._exit after prepare, after replacement and
after commit; recovery runs through a new Lab object and reacquires the OS lock.
The process-termination tests are NOT power-loss or Windows tests. The metadata
online test is separately recorded; it is not a full-game/publisher-trust test.

## Before production game writes

- Validate final locale/platform install policy and full install/root/metadata
  closure after the implemented DL/Encoding/catalog conditional plan.
- Complete install/download target closure and safe local reuse, including CASC.
- A tested CASC publication strategy (not inferred from sampled alias geometry).
- Game/process exclusion and actual filesystem/Windows failure behavior.
- Verified backup/restore and interruption handling for ALL activation metadata.
- UI and a clearly authorized real installation transaction.

Do not pass a real game installation to Lab or manufacture its marker there.
## Local CASC read-only reuse increment

`local_casc.py` bridges verified continuous local idx records to full target keys
and bounded complete payload proof. The unchanged public-domain lookup3 port is
carried forward, with independent pinned C-reference vectors in the test suite.
The local idx layout and rolling checksums follow CascLib's pinned reference:
https://github.com/ladislav-zezula/CascLib/blob/38a34665624b8775bb875274b36191b21c38d97b/src/CascIndexFiles.cpp

All observed generations remain eligible; no newest/active generation choice.
Prefix collisions retain alternatives. Missing/ambiguous archives, wrong size
geometry and unsupported index layouts never supply trusted candidates. Normalized
wrapper/direct aliases deduplicate by full target EKey, archive ID and payload
offset. Even a zero wrapper is not evidence; only full target payload proof counts.

Immutable output batches reserve space and preserve earlier complete checkpoints.
A current interrupted batch is not imported; resume restarts from the last complete
checkpoint after exact plan/snapshot binding and source fingerprint checks. Each
new checkpoint copies earlier evidence (not constant-time journal appending).
No archive bytes are read by inventory; only bounded candidate spans by verification.
Final publication checks all observed source fingerprints/file set twice. This is
NOT an OS atomic snapshot, malicious-writer defense or game-process lock.
No writes to source storage, no shmem parsing, no code execution and no CASC writer.

Absence from supported observed indexes is NOT absence from installation. Encrypted
or unsupported data remains unverified, not globally corrupt. Conditional remaining
bytes are not an exact download requirement. Evidence DBs contain private source
paths and offsets and must remain local. The aggregate report excludes these.
An actual local source must be quiescent; final reuse must revalidate the span.

Tests cover complete synthetic content proof, corrupt payload/chunk/key collisions,
all-generation alternatives, normalized aliases, budget pause, immutable resume,
source change rejection, read-only opens, low space, binding mismatch, and an
actual child-process os._exit followed by resumption. A separate large synthetic
run covers 100K targets/400K references. Full official-plan integration uses
DELIBERATELY INVALID generated local payloads and proves zero false reuse; it is
not an actual user CASC test. The optional small official CDN payload request was
blocked by HTTP 403. No HTTP/proxy/host fallback or repeated request was attempted;
this failed network sample is recorded separately, not described as successful.

## Unified legacy/local reuse and conditional queue increment

The old cache/staging import bridge now recognizes v0.25 receipts, v0.30 decoded
manifests and earlier supply-plan cache claims. These are bounded 4 MiB JSON inputs
with duplicate-key/path rejection; historical endpoint/absolute-path/success claims
are never followed as authority. Candidates must bind to the CURRENT selected plan
by full keys/sizes and prove content afresh. Identical content may survive a version
change, without treating the old version as an installation target.

Only owned local checkpoint full proofs are inherited, after exact plan/snapshot
binding and source stability checks. Unknown old cache evidence DBs are not accepted
as proof. Encoded overlaps are unioned by full target EKey. Decoded-only content is
not possession of the required encoded representation. Existing local proofs are
available even with zero cache-read budget; skipping a duplicate source does NOT
claim that skipped file itself was verified. Conditional queue materialization keeps
every plan key and original content/route property and preserves unresolved/pending
states. All evidence/queue outputs are private lab DBs, never game storage writes.

IMPORTANT CORRECTION to the earlier optional HTTP403 sample: the PLAN/catalog data
was correct, but the BUILDER SAMPLE HARNESS compared against `archive` instead of
`archive_range`, then wrongly requested a direct EKey. That 403 did NOT prove CDN
blocking. `transfer_routes.spec` now recognizes exact `archive_range` and
`advertised_direct` only, with required provenance/geometry and no unknown-to-direct
fallback. A new exact Range-header/full-decode regression covers this boundary.
With the corrected range, three official payloads (3453 encoded bytes) succeeded.
No insecure host/proxy/HTTP fallback was used. The failed initial attempt is retained
as historical evidence and superseded by a separately documented corrected sample.

The live reuse integration uses the real 2,881,619-key plan and those three payloads
in GENERATED legacy/local fixtures, not user storage. It proves two encoded available
keys + one decoded-only key, overlap counted once, no encoded-byte subtraction for
decoded-only content. Independent all-row reconciliation checks queue identity, all
content/routing fields, availability and conditional-transfer decisions. No exact
user deficit, full install closure, Windows behavior, global HTTP availability or
CASC activation/writer is claimed. Fingerprints are not a hostile-writer/OS-snapshot
guarantee; revalidate actual sources again before future use.
