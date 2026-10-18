# Independent content capture instead of treating a locator as authority

## Design decision
A matching index prefix/control sequence is only a locator hint. Conversely, an
unknown generation does NOT make an independently captured, fully target-verified
object unusable as candidate input. These are different evidence questions:

1. What was the active/coherent installation generation? Still unresolved.
2. Do THESE captured bytes satisfy the exact target EKey/CKey, sizes and BLTE chunk
   checks, and still verify in our independent copy? Implemented here.
3. Does the product require this object for the current profile, and can it safely
   be installed? Still unresolved; candidate admission is NOT required-set or apply.

The new path never uses a guessed control/store name, never acquires an unproven
Agent mutex and never elevates raw return=0 to successful client binding. Reviewing
Agent9824 name-seed/binding evidence found it explicitly does not establish actual
installation binding or real Windows mutex interoperability. No live mutex was
opened/created and no new user installation data was consumed.

## Implemented code
`LocalContentCapture.capture` receives an explicit caller-provided stream for ONE
bounded BLTE object, typed target/spec, existing caller-owned scratch directory
and explicit encoded-byte budget (maximum 256 MiB). No source discovery, archive
paths/offsets, network or CLI. Reads are <=64 KiB. A virtual EOF prevents the
verifier's sentinel read from touching one byte outside the declared object span.
The cap is a parser/import limit, not file-read permission.

Each byte read is copied into a private OS temporary file. The stream's target
full EKey/CKey, sizes and BLTE chunk hashes are checked, then the COPY is freshly
verified again. Short reads are supported. The original source is never reread
for proof and may change/disappear afterwards without changing this copy. Changes
while reading either produce the exact target-valid captured object or fail the
identity checks; neither outcome diagnoses the entire installation. This uses
CASC's MD5 identities plus independently retained SHA256 copy digests, not a
publisher signature or protection against an adversarial collision attacker.

`admit_capture` binds that fresh copy to the same pinned candidate/catalogue,
checks full database identities and exact selected EKey, CKey and sizes, and
reverifies the copy. It has no fake HTTP response, ETag, download route or network
request to fabricate a local import. Every admission rechecks the copy rather
than trusting an old receipt flag. It grants only verified candidate staging
input; installed reuse, required set, network savings and apply remain false/null.

The temporary file is kept open until context exit/close; then it is deleted.
This is NOT a persistent cache, installer, archive reader, crash-recovery system,
process-isolation/hostile-writer boundary or power-loss-qualified commit. There
is no automatic installed-file read and no further read approval implied.

## Decision-making Windows experiment
The initial hypothesis was that a previously writable mapping could remain usable
while our held read view succeeded. Actual Windows CI instead returned sharing
violation (WinError 32) in both experiments, even after the original file/section
handles were closed. The first run also had unrelated POSIX fixture setup errors;
those were fixed using native fixtures, without weakening production validation.

Follow-up tests assert this specific observed outcome: the mapped byte remains
writable, the held capture refuses that source with sharing violation 32, simply
restoring the byte is insufficient, and unmapping permits the capture. This is
positive exclusion evidence for this exact Windows profile, NOT an observed
bypass, and NOT a proof about every possible mapping/process/Agent path. We did
not demonstrate a successful mapped A->B->A bypass. Prior read-view blocker wording
was narrowed to unqualified mapping cases rather than claiming a proven bypass.

Only the receipt of the follow-up source establishes that these assertions passed.
No user control/index/archive is used. Full client quiescence, all mapping modes
and product store binding remain unqualified. Independent content capture remains
useful because stale locators and copied/changed sources are independently handled
by complete target identity checks, regardless of this single mapping result.

## Completion criteria and remaining work
The independent-copy path is implemented and tested, not yet a live local reuse
backend. Next: a separately approved, exact bounded local object reader feeding
this API (with no prefix-as-proof), full selection qualification, and transactional
writer/rollback on an isolated copy. Store quiescence and binding remain mandatory
for any claims about the installed generation and for future installation writes;
they are not silently waived. Unknown does not mean zero network download bytes.

No new ZIP, game read/write, account data, admin/ACL, Agent execution, repair,
CDN request or guessed Global mutex is performed by this change.
