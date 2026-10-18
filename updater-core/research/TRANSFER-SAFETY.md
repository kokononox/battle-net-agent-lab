# Transfer controller threat and authority boundary — 0.20

## Implemented scope
- Exact StreamStage/WindowsStreamStage types; one coherent pinned checkpoint; unique stage paths and source/spec identities. Cooperative trusted owned scratch only.
- TransferGrant has a strict bounded shape, range derivation from approved initial commits and an exact application request/body budget. Saved bytes are not permission: restoration explicitly requires new approval. Existing closed approvals are not imported.
- A durable pending reservation precedes each callback/HTTP attempt. The ledger monotonically charges planned body lengths and attempts, including failed/uncertain attempts. Atomic publication uses the backend's existing flush/rename; this is not power-loss/hardware qualification.
- Resumption between committed ranges rechecks all prior segment SHA and exact journal digests. A pending attempt MUST stop ordinary restore. As of 0.21, a separate explicitly approved LOCAL reconciliation may accept exactly one already-journaled reserved segment after reconstructing its predecessor and fresh verification; it never fetches or resets a budget. As of 0.22 an explicit separate retirement/successor lifecycle handles pending attempts whose stage journals have not advanced, retaining reservations and pinned history. It never automatically retries. Locks and orphans remain stopped. See RECONCILIATION-SAFETY.md and SCOPE-RETIREMENT-SAFETY.md.
- ETag and archive total are pinned across all objects sharing the same archive URL. Provided baseline equality is checked before attempts; no claim that the caller measured a fresh live installation is made.
- Final verification rereads every segment and full BLTE identity. Proof is owned staged data only, never vendor required-set selection, active-generation proof or apply authority.
- ApprovedStreamHTTP consumes exact grant ranges, strong ETag/If-Range and fixed total. No redirects, retries, encoded response, Transfer-Encoding, duplicate critical headers, or EOF probing. Reads are <=64 KiB; single response storage <=1 MiB. Chunk/body counters are application data, not physical wire traffic.

## Tests and limits
53 synthetic controller/HTTP cases run on Linux and real Windows, including fresh-process multiobject resume. HTTP opener is mocked; no CDN, loopback or game access was executed. Numeric grant limits were not exercised at full scale. Bounded explicit uncommitted-scope retirement is now implemented and tested separately (33 cases); general interrupted-operation and abandoned-lock recovery, transport TLS/CDN behavior, real interruption recovery, disk-full/actual power-loss qualification and hostile namespace/process defenses remain open.

## Reproduction
Use a new owned temporary directory, create independent synthetic stages, obtain a fresh explicit grant, connect ApprovedStreamHTTP.fetch to TransferController, call step with caller-supplied checked baseline and cancellation callback, then finish for fresh proof. Never run these tests against a game directory. Receipt flags cannot grant installation. No command in this source release requests production apply.
