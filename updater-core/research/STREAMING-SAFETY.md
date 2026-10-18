# Streaming verifier and stage threat/authority boundary

- New parser budgets do not expand any earlier read/download permission.
- Only caller-owned/coherent supplied bytes/streams are consumed. No scanning or network client is added.
- The streaming verifier performs no decoded output export. N/Z only; encrypted/unsupported is unknown, not corrupt.
- POSIX staged files are under trusted scratch and cooperative exclusive writer locks. No hostile-process protection, Windows file API or actual power-loss claims.
- Restore validates metadata, not payload. Eligibility requires fresh full stream/segment/content verification and exact target catalogue membership.
- Synthetic data crossed the previous 4 MiB limit; real public metadata up to 188062372 encoded bytes was verified. The numeric 4 GiB/32 GiB caps are not full-scale qualification.
- Separate offline Windows CI runs only synthetic parser/selection tests, with contents:read. A clean publisher job has contents:write and validates a strict receipt; no test log, game payload or account secret is published. No bootstrapper, installer, game or account login runs. Existing Agent observation workflow is unchanged.
- Complete native transactional CASC writing/rollback/activation requires additional implementation, independently qualified format/policy and an isolated Windows game-copy environment. Production apply remains unauthorized.
