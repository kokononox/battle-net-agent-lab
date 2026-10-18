# Streaming verifier and stage threat/authority boundary

- New parser budgets do not expand any earlier read/download permission.
- Only caller-owned/coherent supplied bytes/streams are consumed. No scanning or network client is added.
- The streaming verifier performs no decoded output export. N/Z only; encrypted/unsupported is unknown, not corrupt.
- POSIX staged files are under trusted scratch and cooperative exclusive writer locks. No hostile-process protection or actual power-loss claims. Native Windows scratch I/O is separate, not a POSIX emulation.
- Restore validates metadata, not payload. Eligibility requires fresh full stream/segment/content verification and exact target catalogue membership.
- Synthetic data crossed the previous 4 MiB limit; real public metadata up to 188062372 encoded bytes was verified. The numeric 4 GiB/32 GiB caps are not full-scale qualification.
- Separate offline Windows CI runs 73 portable parser/selection tests, 38 native owned-scratch tests and 10 native candidate-admission tests, with contents:read. A clean publisher job has contents:write and validates a strict receipt; no test log, game payload or account secret is published. No bootstrapper, installer, game or account login runs. Existing Agent observation workflow is unchanged.
- Complete native transactional CASC writing/rollback/activation requires additional implementation, independently qualified format/policy and an isolated Windows game-copy environment. Production apply remains unauthorized.

## Native Windows scratch boundary (0.18)

- WindowsStore holds ancestors and the new scratch root with FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, and no FILE_SHARE_DELETE. No directory enumeration is performed. Metadata-only desired access was insufficient in the first real Windows run: the root could be renamed; the failed receipt is preserved. The corrective code requests directory data access so sharing checks apply. Pass status is taken only from the subsequent source-matched receipt.
- Reparse/offline/recall paths, nonfixed drives, UNC/ADS names, duplicate or unexpected journal keys and hardlinks are rejected. Reader handles deny write/delete until closed. All production I/O is on owned stage children; no game path, network client, ACL change or administrator operation is introduced.
- Immutable segments are flushed with FlushFileBuffers before MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH) publishes the journal. These are OS requests, not evidence of hardware durability. No Windows directory fsync claim is made. Abandoned writer.lock and orphan segments are never automatically adopted or removed.
- Tests simulate interruptions; actual power loss, hostile concurrent namespace changes, filesystem diversity, native CASC transactions, rollback and activation are NOT qualified. Hold handles must be closed before fixture cleanup.
- As of 0.19, the exact StreamStage and WindowsStreamStage types are admitted; arbitrary subclasses are rejected before receipt I/O. Read-only SQLite URIs use Path.as_uri. Selected full EKey/CKey, lengths and target-bound database identities are checked before fresh payload/segment verification. Receipts cannot grant apply. These are trusted owned scratch databases, not hostile-process snapshot protection. Synthetic admission success does not establish fresh installed reuse, policy selection, an integrated downloader, or permission to apply.

## Transfer integration added in 0.20
The caller-supplied-response-only gap now has a bounded controller and explicit HTTP adapter, tested using synthetic payloads/mocked responses on both OS backends. See TRANSFER-SAFETY.md. This does not mean real CDN or production recovery is qualified. Durable pending attempts stop rather than retry, and live baseline freshness is still supplied by the caller, not measured by this controller.
