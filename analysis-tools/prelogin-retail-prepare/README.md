# Anonymous limited Retail transfer attempt — c10

This step changes scope: after the proven non-finalizing form and repeated
owned-path checks, one finalized=true request may be sent to /install/wow.
No account, country or EULA/consent field is sent. Finalization can have network
and installation side effects, even before /update. A zero EULA code or boolean
is not interpreted as user consent or a legal-policy oracle. If authentication,
minimum-spec, legal/form error, unknown schema, unexpected path, or unfinished
finalization appears, stop; no retry or bypass.

Only after a finalized=true response with all known form errors zero and the
same normalized owned path with verified existing ancestors, read a baseline
GET /game/wow, POST /update {uid:wow}, then at most four GET /game/wow polls.
Three-second HTTP socket timeouts, response65,536B cap, at most7 extra requests.
The API may queue the whole product; this run does not wait for or claim a
complete installation. It is an early transfer attempt that may stop before
any actual transfer is observable. full_game_download_requested is conservatively
set once finalization is attempted, not a claim of completion.

The proven native Job supervisor remains mandatory. Five native fixtures must
pass (real wall timeout; synthetic global network/disk and synthetic transfer
phase time/network conditions). Each must show >=2 active owned processes and
zero at end. Before finalization the worker writes an intent signal; the native
parent samples it and enforces an additional30s /64MiB HOSTWIDE counter threshold.
Overall240s /1GiB /10GiB reserve limits remain; no limits reset or weakened.
Neither byte threshold is a hard cap; 250ms polling permits overshoot. Phase
baseline includes the previous sample interval and may include unrelated or
prephase activity. No exact process-byte attribution from adapter counters.
The signal is not proof of a request or transfer; it can precede a refused call.

Separate transfer receipt is atomically persisted before network attempts and
after observations. On native termination the latest valid receipt may remain
pending: it proves intent, not successful delivery. Final worker/form receipt
may be absent when killed. Publish supervisor, transfer and form results
independently with source/run binding; never use an older receipt as current.

Evidence collected: only typed Agent progress flags/allowlisted counters,
bounded owned-directory metadata totals (<=512 entries, depth<=8; no file
contents/names), and counts of ESTABLISHED IPv4 TCP endpoints owned by the same
verified local Agent listener PID, bucketed by public fixed port categories.
No PID, address, domain, token, payload or raw path is published. Counts omit
IPv6/UDP/other Agent children, do not count bytes and cannot identify hardware
uploads. No TLS decryption or packet capture in c10. An increasing file size may
be preallocation/metadata, not proof of downloaded playable content. Agent
progress counters are reports, not independently verified wire bytes.

Q2 game-file provenance/watermark analysis is not started. complete_installation
and hardware_upload claims remain false. No game execution or account login.

C9 never reached handshake/finalization: bootstrap_not_ready after language/
Agent observation, no HTTP Agent requests. This does not establish which
cleanup precondition failed. C10 records the bootstrap's original cleanup flag
and at most4 post-cleanup checks /3 calls to the same existing stop_observed
mechanism, sleeping1s between. Original result/cleanup flag are not rewritten;
probe's own empty-process/identity/freshness requirements remain unchanged.
The standalone sanitizer now sets its own probe import path and has a fresh
interpreter test without PYTHONPATH. A missing standalone receipt is never
inferred to mean a successful transfer.

## Independent attempt reconciliation (offline reporting fix)

Use `reports/prelogin-retail-attempt-latest.json` for the source/run-bound combined
state, not an older `prepare-runtime` file that survived worker termination.
`attempt_report.py` reports missing receipts and ignores stale identities before
consuming their schemas. Current malformed receipts are refused. Persisted
`finalization_attempted`/`start_attempted` flags are labeled as intent, not HTTP
delivery proof. CI publication derives this aggregate only from incoming validated
receipts from the same run, including when the final worker/form receipt is absent.
This reporting-only change does not trigger another approved target run, alter
native guards, reset counter baselines, or raise any limits. See
`docs/PRELOGIN-RETAIL-C10-RECONCILIATION.fa.md` for the offline C10 reconciliation.
