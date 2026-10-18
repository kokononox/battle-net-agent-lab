# Explicit uncommitted-scope retirement — 0.22

## Authority and state
This is an API for cooperative, trusted, updater-owned scratch only. It does not inspect or modify a game installation. retire_uncommitted requires approved=True and the matching current baseline and grant. It holds every stage writer lock and freshly hashes all committed prefixes. The active ledger must have a pending reservation but every stage journal and committed byte count must STILL exactly match the ledger. A stage commit not accounted for in the ledger must be reconciled using the separate 0.21 API first; retirement cannot silently adopt or discard it.

A canonical immutable receipt is written under the fixed filename <old-grant-sha256>.json and flushed before an atomic retired ledger marker is published. No directory enumeration, orphan adoption/deletion, lock breaking, budget refund, network callback, automatic retry or continuation occurs. The existing reserved request and planned application-body charges are preserved even when no request body was received. These counters are conservative reservations, not measured wire traffic.

A fresh explicit retry after interruption between receipt and marker may finish retirement only when the existing receipt bytes exactly match. A matching already-retired marker is idempotent. An abandoned writer lock still stops both operations; this does not qualify hard-crash or power-loss recovery.

## New scope, not reactivation
approve_successor requires separate explicit approval, verifies the retired record and all prior receipts, rechecks stage identity and fresh prefixes, and issues a new v2 grant with a fresh random nonce. A history digest binds the accumulated closed scopes into that grant. create_successor requires explicit approval and rechecks all state under stage locks before publishing a new active ledger; it does NOT call step or fetch. The old grant cannot reactivate the retired ledger. An ordinary new grant with an empty history digest cannot bypass successor accounting.

The new scope has separate fresh per-scope counters. lifetime_reserved_requests and lifetime_reserved_application_body_bytes include every prior retired scope. Exact prior grants, their pending ledgers and reservation totals are retained in immutable referenced receipts; each previous history must equal the chain prefix. Missing/corrupt/hardlinked receipts, changed rows, dropped history, reused grant IDs or mismatched current baseline/source/target fail closed. A changed target requires a new plan/workspace, not a successor that silently changes the pinned target.

Limits: 16 prior scopes maximum; 256 KiB maximum per retirement receipt. No recursive embedded bodies, no scanning and no unbounded history growth. Legacy v1 grant/ledger pairs with empty history remain readable. The cooperative digest chain is NOT a signature, rollback-resistant external audit or protection against an actor able to rewrite the whole workspace and substitute approval objects.

## Tests and remaining gaps
33 new cases include retirement/approval boundaries, commit-before-ledger refusal, prefix corruption, fresh nonce and pinned history, old-grant rejection, cumulative counters over multiple scopes, missing/corrupt/hardlinked receipts, history truncation/limit, explicit idempotent fault recovery before/after publication, abandoned-lock preservation, legacy compatibility and lifecycle/restore in two fresh child processes. Native Windows and POSIX use their own exact staging backend; no HTTP requests occur.

No real disk-full, abrupt process kill while holding a lock, power loss, hardware durability, hostile namespace, full-scale grant, actual CDN/TLS or live game qualification is implied. Current baseline equality is checked against caller-supplied data; the live installed-generation reader remains a separate blocker. installation_ready=false and apply_authorized=false remain unchanged.
