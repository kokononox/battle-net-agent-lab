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

## D1 read-only network-counter diagnostics

`network_diagnostics.h` tracks sample gaps/deltas, interface membership changes,
and per-interface counter decreases. Interface LUIDs and absolute per-interface
counters remain in memory and are never serialized. `guard.cpp` emits schema3
with these diagnostic counts; schema2 receipts remain readable. Production C10
limits, previous-sample phase baseline, and fail-closed behavior are unchanged.
A phase clock of 0ms can coexist with a nonzero preceding sample interval; the
boundary diagnostic reports that interval separately and does not claim a rate.

The separate `prelogin-counter-diagnostics.yml` approval runs a Windows build of
the production guard without executing it, native synthetic C++ assertions, and
33 adapter-counter samples at nominal250ms spacing. The marker at sample8 is
synthetic, not a game-transfer marker. Neither Setup nor Agent is downloaded or
launched and no transfer request is sent. This is a measurement/toolchain control,
not a reproduction of the historical C10 event. A clean D1 cannot exclude a
transient interface change, sampling stall, or network burst in C10.
Only a strictly validated, source/run-bound typed receipt is published at
`reports/prelogin-counter-diagnostic-latest.json`; no adapter names, IPs, PIDs,
raw paths, or compiler logs are published. The target workflow's exact C10
commit-message approval does not match this diagnostic-only approval.

## D13: acknowledged pre-request phase arming

D11 completed a non-finalizing form update. D12 then hit the phase counter limit
before even recording a finalization attempt: the boundary interval contained
256,406,670 hostwide bytes over266ms, with no observed interface-set change/reset.
This is not evidence of game-transfer bytes; the transfer receipt had0 requests.

D13 supersedes the earlier previous-sample phase baseline policy. The worker
writes intent and waits for an atomic ready acknowledgment. The native parent
captures one immutable network/time baseline, checks the unchanged global budget,
disk and time limits, and only then publishes the acknowledgment. No target
request is permitted before that acknowledgment. The64MiB/30s phase budget starts
before permission is issued; no resets occur after arming. Pre-arming bytes still
count against the unchanged global1GiB/240s budget. This removes the unobserved
pre-request boundary interval without exempting any requested transfer bytes.
Native receipts use schema4 with an explicit baseline-policy/ack flag; transfer
receipts use schema2 and reject request-intent flags without acknowledged arming.
Older receipt schemas remain readable. The active workflow requires a separate
D13 exact commit-message approval. No account/country/consent fields are added.


### D19: shorter passive startup observation

D18 was stopped by the unchanged hostwide phase threshold before its status GET.
D19 reduces the passive bootstrap observation from 120 to 30 seconds only.
The bootstrap wrapper still refuses a changed caller scope; signature, pin, empty
environment, cleanup, readiness, listener ownership, arming and all Job budgets
remain unchanged. Actual observation duration is recorded as the optional fixed
`bootstrap_settle.observation_seconds` field (older receipts remain readable).
The handshake report retains its original 120-second maximum budget; it is not
a claim of the actual bootstrap observation duration. A non-ready Agent is a
failed experiment, never permission to skip the readiness gates.


### D20: acknowledged-phase identity-only negative control

D19 reached finalization but was stopped before its status GET. D20 deliberately
sends **zero phase HTTP requests** after the same arming acknowledgement, runs
the same live identity verifier, records only metadata and exits. No finalization,
/update, URL following or consent occurs. All startup and nonfinalizing form
preparation remain identical to D19; startup may itself cause network activity.
The immutable post-arm baseline and all native budgets remain unchanged. A stop
in this control cannot be attributed to a phase finalization/download request,
but does not itself identify which process caused the hostwide bytes.

D20 result: the acknowledged control completed its identity-only checkpoint
with zero phase HTTP requests; the parent then stopped at 202,297,567 hostwide
bytes in 250ms. No finalization/update occurred; the owned destination snapshot
was empty. This excludes attribution of that threshold event to a phase HTTP
request, **not** automatic Agent activity or other host traffic. See
[the fixed-evidence report](../../docs/PRELOGIN-RETAIL-D20-CONTROL.fa.md).
The offline `negative_control.py` rejects mixed-run and incomplete controls.


T2 repeats the D20 zero-phase-HTTP control with a calibrated, source-bound
per-connection observer. The first T2 attempt did not launch the target: the
meter did not compile. Target-free build run40610911964 then compiled both
units and revalidated exact known transfer counters. The next approved T2
keeps all budget, ownership, pin and nonfinalizing control gates unchanged.

The compiled T2 meter observed six owned external IPv4 TCP connections and
333,304 incoming bytes before the phase was armed, but its ready marker used
Windows text-mode CRLF while the Python gate correctly required exact LF.
The worker refused before any phase request. Ready output is now explicitly
binary; exact-marker success and CRLF refusal are covered by mocked IPC tests.


T3 response contract hypothesis is grounded in the public source, not a guessed
root label: barncastle/Battle.Net-Installer commit
3aa2d98d866b393197da0b75d7381b7fff495ad9,
BNetInstaller/Endpoints/ProductEndpoint.cs reads `response_uri`. Its README
requires recent sign-in, so it does not prove logged-out Retail installation.
Only the exact owned /game/wow resource is recognized; unknown siblings remain
unknown, raw URIs are never exported, and T3 forbids /update. Public source:
https://github.com/barncastle/Battle.Net-Installer/blob/3aa2d98d866b393197da0b75d7381b7fff495ad9/BNetInstaller/Endpoints/ProductEndpoint.cs


T4: if the finalization reply names the exact owned /install/wow resource,
read that form once. Unknown sibling fields remain unknown. No URL from the
response is followed generically, no finalization is retried, no /update or
account/country/legal acceptance parameter is sent. The standalone source-bound
final-form receipt records only field names, explicit numeric codes, finalized
boolean and redacted containment checks; an absent error stays null.


T4 confirmed the exact /install/wow handoff but its GET is not a form. That is
not an Agent error: it invalidates the old form-only interpretation. T5 records
a typed operation state (finite numeric progress, download-complete boolean,
explicit error/refusal indicators) and follows the public client's documented
POST /update uid=wow only when that owned incomplete operation is recognized.
Any form, authentication/legal indicator, malformed required flag, nonzero error
or unknown operation schema refuses the start. No account/country/legal field
is sent. Each request repeats the original identity checks, owned containment
is rechecked, and every native time/network/disk budget remains unchanged.
Schema6 records `owned_install_operation` authorization without fabricating a
returned finalized flag or an absent Agent error zero. One update maximum and
at most4 status polls (7 phase requests total). This is a bounded start attempt,
not a claim of full installation or verified game payload.
Public flow reference: BNetInstaller/Operations/InstallProductTask.cs at
3aa2d98d866b393197da0b75d7381b7fff495ad9. Its country defaults and recent-login
assumption are NOT imported into this test; credentials/legal requirements
remain server-enforced, and explicit refusals stop the run.


T5 reached one explicit /update (HTTP200) and a subsequent status GET (HTTP200),
but the unchanged phase guard stopped the job during the post-response identity
check. T6 adds at most2.5s of read-only readiness BEFORE the phase intent: three
fresh 250ms TCP-meter intervals <=1MiB each, no connection turnover, no meter
errors. All startup/preparation bytes and waiting time remain charged to the
unchanged GLOBAL guard; the phase baseline is still armed once before any
finalization request. There is no byte-budget reset, cap increase or requested
transfer before acknowledgement. Quiet in this incomplete socket scope is only
a readiness heuristic, not proof of total Agent/host silence. Failure refuses
finalization. Parsed operation state/file metadata are now checkpointed before
the post-response identity check, explicitly marked unconfirmed; such a pending
checkpoint cannot authorize any subsequent start. Earlier confirmed states are
retained; a successful check updates the last state to confirmed.


## Consolidated attribution verdict (T1–T8)

See [`PRELOGIN-RETAIL-ATTRIBUTION-VERDICT.fa.md`](../../docs/PRELOGIN-RETAIL-ATTRIBUTION-VERDICT.fa.md).
T7 completed with zero harness product API requests and a positive owned TCP
counter checkpoint. This is neither a payload classifier nor proof of a WoW
asset download. T8 hit the unchanged phase guard before update; its current
receipts are kept separate from historical operation-state files.

`attribution_verdict.py` reproduces the limited findings from hash-bound frozen
public receipts. `public_manifest_sizes.py` audits a separately fetched small
public config, without fetching the large referenced manifests or changing any
runtime budget. The encoded encoding object's declared size exceeds the 64 MiB
phase threshold; the implication is conditional on needing that whole object
inside the armed phase, not a causal identification of observed Agent traffic.


## T9 explicit user-approved bounded content experiment

The user approved a 2 GiB hostwide global threshold and 512 MiB hostwide phase
threshold in chat. Time remains 240 s global / 30 s phase; disk reserve 10 GiB.
Only `RETAIL_BUDGET_PROFILE=approved-2g-512m-t9` selects this named finite policy;
unknown profiles are refused. All native synthetic stopping fixtures retain the
legacy limits, and the shared selector has independent portable C++ tests.

The small official install manifest was fetched separately as public metadata
(23,106 encoded bytes, 24,078 decoded); its full EKey/BLTE checks and decoded CKey
were verified against the checksum-bound config for build 12.1.5.70575. The
reference contains only fixed public component names, sizes and content hashes;
no game executable, raw response, local path or identifier is published.
`make_content_reference.py` reproduces reference extraction from those two local
public-metadata inputs. Install-policy tags are NOT interpreted; both official
voice-proxy variants are accepted as components of this build, not as proof of
architecture selection or complete installation.

`content_probe.py` is read-only: checks both fixed owned layouts, requires absent
baseline components and matching build identity, rejects reparse/hard links,
limits per-file reads to 4 MiB plus a single extra-byte EOF check, at most eight
hash attempts / 16 MiB declared hashed content, and validates before/open/after
fingerprints. At most 64 scans and a 20 s passive observation (no extra HTTP)
follow a successfully verified operation start. A positive match proves a known
component materialized in the previously empty destination; it does NOT prove
which socket delivered that exact file, full installation, or hardware upload.
No account, country, EULA, minimum-spec bypass, game execution or user install.


T9 pre-target portability diagnosis: the Windows checkout converted public,
byte-hash-bound JSON to CRLF (`reference_has_crlf=true`, exact reference hash
false, all 12 frozen receipt hashes unequal). The target did not launch. Scoped
`.gitattributes` preserves LF for just these public inputs; no hash check,
signature check, test, or runtime limit is disabled or normalized away.


The LF-fixed T9 run 40618043591 passed all CI/native controls, but the bootstrap
had not exposed Agent within the legacy 30 s observation. It cleanly returned
`handshake_not_ready` with zero product requests; CI success was not a download
success. `RETAIL_BOOTSTRAP_WAIT=original-120-t9` now restores the original bounded
120 s passive bootstrap observation ONLY with the approved T9 budget profile.
The native global time limit remains 240 s, and all bootstrap traffic/time stays
charged to its existing global budget. No readiness or signature gate changes.


T9 bounded observation completed at run 40618511090 / source da2e6721ba5770fc8a89472d2a8584575a428bf3.
The phase stop fired at the approved threshold; this is NOT content verification.
Further target execution is paused after that stop. The subsequent snapshot-order
and censored-count changes are locally tested preparation, not a new live result.
A non-approval documentation commit intentionally cancels the follow-up attempt
through the workflow's existing concurrency group, rather than consuming another
bounded target run after the approved stop.

Cancellation confirmed: follow-up run 40619129965 ended cancelled; stop-only run
40619262177 ended skipped. The cancelled follow-up is not counted as new content
evidence. No further target run remains active.


## T10: renewed same-budget continuation

The user asked to continue after T9. T10 keeps the approved 2 GiB / 512 MiB
thresholds, 240 s / 30 s timers and 10 GiB reserve unchanged. A synchronized,
read-only fixed-path watcher starts only immediately before the already-authorized
owned `/update` HTTP request. It shares the 64-scan and eight-hash bounds with the main thread; it has a 4 s lifetime,
50 ms polling, explicit stop/join and no network or executable capability.
Unknown scope or watcher path-security failures refuse further requests.

The corrected censored metadata enumeration also runs in this experiment;
only `tree_limit` becomes unknown counts, never zero. Other errors remain fatal.
New failure receipts expose a finite stage/type/reason code, never raw exception
values. A positive official component match is still materialization evidence,
not same-file socket delivery, complete game installation or hardware upload.

T10 schema 2 additionally checks the build's main `Wow.exe` and
`wow_loader.dll` from the same already verified public IN manifest, rather than
assuming a helper must arrive first. The local read-only hash bound is explicitly
128 MiB per candidate / 256 MiB cumulative declared hash work; this does NOT alter
network thresholds, timers, or disk reserve. Reads are streaming and bounded by
expected exact size plus one EOF byte, with before/open/after identity checks.
Historical schema 1 receipts retain their original 16 MiB hash-work limit and
two-component reference interpretation. Neither executable is ever launched.
