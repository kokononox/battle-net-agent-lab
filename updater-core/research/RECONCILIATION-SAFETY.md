# Explicit committed-range reconciliation — 0.21

## Authority and scope
TransferController.reconcile_pending requires a known exact grant, caller-supplied matching baseline and approved=True. It is a local-only API: no transport callback is accepted, no fetch occurs, no automatic step/restore runs afterward, and existing network scope/budget is never renewed. A serialized grant still requires explicit approval when restored. This is cooperative trusted owned scratch, NOT game installation, hostile-process protection or full production crash recovery.

## Acceptance rule
1. Hold every stage's cooperative writer lock through verification and ledger publication. Do not break or remove preexisting locks.
2. Validate strict ledger/grant/checkpoint identity and a pending reserved range. Every unrelated stage must match the ledger's exact journal hash and committed byte count.
3. If the selected stage still matches the old journal, freshly check existing segment SHA but retain pending unchanged. Unknown network outcome is not a reason to refetch or restore budget.
4. Otherwise, accept only exactly ONE complete segment matching the reserved [a,b]. Reconstruct its canonical predecessor journal by removing that segment and restoring the prior committed/entity fields; SHA256 must equal the old ledger journal hash. Noncanonical predecessor bytes may fail closed.
5. Reconstruct and compare prior shared-archive entities; reject ETag/total conflicts. Freshly verify every existing segment SHA. If this completes the selected object, verify its complete BLTE EKey/CKey and chunk checksums too. A partial object's segment SHA is not full-content proof or an eligibility decision.
6. Recheck all journal hashes and atomically publish cursor+1/pending=false with unchanged reserved request/body counters. No request is issued. A later explicit restore may continue only the previously granted remaining ranges.

## Faults and unresolved cases
- Before reconciliation publication: pending remains, no automatic continuation.
- After ledger publication but before returning: explicit restore sees committed state; there is no duplicate network attempt.
- During a hard process stop inside a writer-lock critical section, abandoned lock files may remain; the API refuses them. No automatic stale-lock recovery is added.
- Pending without a committed range, orphan segments, extra ranges, changed prefix, missing segment, changed source/target/baseline, shared entity conflict, or invalid full BLTE content are not adopted.
- Real power loss, filesystem/storage durability, disk-full recovery, authorized retirement of failed scopes and real CDN/TLS failure qualification remain open. Flush/atomic rename requests do not establish these properties.

## Tests
26 synthetic reconciliation cases on Linux and actual Windows CI: complete and partial objects, nonempty prior journal, same-archive objects, wrong entities, corruption including updated segment digest, changed identities, preserved budget/locks, repeated-call rejection, before/after-publication faults, and local reconciliation in a fresh process. No HTTP, game path, scan, admin, permission change or decoded export is involved.
