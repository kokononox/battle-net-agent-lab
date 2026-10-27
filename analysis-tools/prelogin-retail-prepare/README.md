# Logged-out Retail non-finalizing preparation under independent supervision — c6

Scope remains anonymous local handshake, GET /game, POST /install and one
POST /install/wow with finalized=false + owned destination + enUS. No /update,
finalized=true, account/country/legal acceptance, game execution or Q2 scanning.

New native supervisor creates a Windows Job with KILL_ON_JOB_CLOSE, creates
its worker suspended, assigns it before resume and supervises the whole worker
process tree. Refuse if job setup/assignment/metrics fail: no ungated fallback.
No BREAKAWAY_OK flags are requested. On return or limit, TerminateJobObject is
called and active job processes are polled to zero (up to5s). This controls
processes inside this Job, not unrelated processes/services or other jobs.

Before real observation, three harmless native fixtures run. Each spawns an
owned child and grandchild. Timeout is real wall time; network/disk conditions
are SYNTHETIC inputs, not real traffic or a filled disk. Each gate requires
max active>=2 and final active=0 after termination. The Agent is never launched
unless all fixture gates pass. The Python driver stays outside the native Job.

Observation limits: 240s, 1GiB hostwide adapter counter delta, 10GiB minimum
free on both RUNNER_TEMP and system volume, 250ms polling. Interface counters
can double-count across virtual adapters and include unrelated traffic. They
are NOT per-Agent attribution or a hard byte cap: overshoot between samples
is possible. Counter reset/read failure stops the Job. The guard's own
crash/handle closure is covered by KILL_ON_JOB_CLOSE; not power failure or an
unverified process that escaped this Job. An external service started through
a broker is not automatically proven to be in the tree. No claim of universal
containment. Full-game transfer is not requested in c6.

After lexical returned-path check, metadata-only lstat walks ancestors from
root and refuses reparse/non-directory/error/outside paths. Missing tail is
reported separately. No raw returned path is published or opened as a game
file. This is a snapshot, not race-free file-handle containment. Revalidate
before any future transfer.

Windows CI builds guard.cpp using installed MSVC. Native fixtures cannot be
executed by Linux local tests. Only strict source-bound typed receipts,
compact form summaries and numeric counters are published. Tokens, PIDs,
paths, UI, raw logs/responses, binaries and UUIDs are not published.

EULA=true still has unverified semantics and is NOT accepted by the tool.
Zero form errors/finalized=false do not prove successful downloading or an
absence of network side effects. No content/payload trace in c6.
