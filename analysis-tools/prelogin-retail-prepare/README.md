# Logged-out WoW Retail form update (c4)

Fresh hosted Windows first-attempt approved push on the research branch only.
Uses the pinned bootstrap and existing owned signed Agent / listener identity
checks. Retains narrow same-hash signed temporary image verification.

Sequence: public EU versions discovery, bootstrap language-only observation,
local anonymous handshake, one GET /game, one Retail POST /install, then at most
one POST /install/wow with finalized=false. The last request contains only a new
owned destination, language=[enUS], selected_asset_locale=enUS and
selected_locale=enUS. No account, country, EULA or other consent parameter.
No /update, finalization=true, install polling, game execution or retry.

The last request is experimental: finalized=false is requested, but is NOT an
independent guarantee that the current Agent has no side effects or cannot
start work. No full game or content-start request is issued. Metadata and
other child network traffic may occur; there is no hard child-byte cap. Owned
Agent cleanup follows the response/error; HTTP timeout10s, observation step6m,
job12m. No later request is made even if the server unexpectedly reports true.
The report calls this unexpected_finalized, not a successful safe update.

Prerequisites: strict known initial form; authentication and minimum-spec error
zero; initial finalized exactly false; enUS in all three language arrays;
bounded required_space; a new empty directory beneath RUNNER_TEMP, fixed drive,
no reparse ancestors, free space at least reported requirement plus 10GiB.
Refuse rather than bypass or silently change another setting. These disk
checks are not a full-download capacity guarantee.

Only strict typed summaries, bounded structure and fixed known language enums
are published. No raw tokens, UUIDs, paths, logs, UI, binaries or legal text.
Initial form and response-after-update remain separate. EULA=true is not
interpreted as consent or legal necessity. eula_review_pending is our
conservative review rule, not an Agent error code.

A 200/201, zero error, matching path or returned finalized=false cannot prove
actual game transfer, a complete installation, absence of telemetry, or server
storage. No packet/payload tracing in c4; Q2 remains queued.

Tests: python -m unittest discover -s analysis-tools/prelogin-retail-prepare -p 'test_*.py' -v
