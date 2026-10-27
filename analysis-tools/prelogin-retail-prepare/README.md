# Logged-out WoW Retail preparation (c2)

Purpose: query the fresh, owned Battle.net Agent's Retail (`wow`, not Classic)
installation preparation form without logging into a Battle.net account.
EU/enUS Windows x64 is the experiment profile, not an inferred user preference.

Execution is restricted to the approved first-attempt hosted Windows push on the
research branch. Bootstrap must match the pinned SHA-256 and existing signature,
process-image and listener-owner checks. A signed same-hash temporary image
transition is allowed only through the existing narrow Agent identity verifier.

1. Fetch the public EU Retail versions table over HTTPS, no redirects/proxy.
2. Observe the signed bootstrap, language-only UI; no Install button click.
3. Launch the owned Agent through the existing anonymous local handshake.
4. One GET /game, refuse unless exactly empty or integer error zero.
5. One POST /install with the Retail initialization payload. No retries.
6. Export fixed form field names, numeric error codes and blocker enums only.
7. Stop and clean up the owned process tree.

Local authorization token is not an account login token. It remains in memory.
No /install/wow finalization, account login, game execution, EULA acceptance,
country fabrication, minimum-spec bypass, user-install access, Frida or hooks.
The initialization request can cause metadata/state/network activity; it is NOT
a dry run and child traffic has no hard byte cap. No game-payload download or
full game download is requested by this experiment. Metadata discovery does not
prove which build the Agent actually selected or that downloading succeeds.

The public summary cannot establish hardware transmission during downloading,
server receipt, download authorization, or game-file provenance. A zero
preparation authentication error alone proves none of these. EULA presence
always remains a review blocker, regardless of its returned boolean value.

Only sanitized summaries and typed CI outcomes are uploaded, not raw responses,
logs, tokens, identifiers, private paths, UI data or binaries. Unknown form
fields fail schema validation and their labels/values are not exported.

Tests: python -m unittest discover -s analysis-tools/prelogin-retail-prepare -p 'test_*.py' -v
