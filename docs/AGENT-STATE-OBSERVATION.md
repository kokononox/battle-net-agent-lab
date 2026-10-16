# Read-only post-language Agent-state observation

## Scope

A fresh GitHub-hosted Windows VM reconstructs the previously approved English (US) -> Continue step once, then only observes. The earlier runner does not persist. No next-page button, install option, agreement, login, game selection or WoW download is driven. The bootstrapper can itself fetch components; there is no hard child-network byte cap. No user Lab, cache, game files or CASC data are touched.

## Evidence collection

- Preserve process/network samples, verified installer and Agent signature, and file-category counters.
- Observe for 120 seconds after bootstrapper launch. Only the original language-page callback can act, once.
- Read at most 24 regular .log/.txt files discovered within fixed bootstrap roots; reject reparse files/ancestors. Limits: 2 MiB/file, 16 MiB total, six-second collection deadline, 10,000 lines/file, 2048 characters/line and 96 retained event records.
- Export only finite event categories/severity, file ordinal, source category, line number and explicitly formatted HTTP response codes. Export no filenames, paths, log text, URLs, account data, tokens or arbitrary error strings. Read UTF-8/UTF-16 logs; skip incomplete final and oversized lines. Counters and truncation are explicit.
- Read-only UIA/native UI probes retain finite known labels and word markers, never edit/password text or screenshots. Additional page signals are language/legal/account/installation-options/progress/error booleans. They are heuristic signals, not definitive page classifications.
- Schema version 7 adds agent_state and its strict nested publication validator. Failure reports start with an empty valid state. Previous schema-6 evidence remains in reports; do not reinterpret it as a schema-7 result.

## Interpretation limits

A log mention is not proof an operation happened, succeeded, or caused a blockage. Agent initialization, self-update, local storage and network signals do not demonstrate WoW download/patch behavior. Empty/truncated logs do not prove absence. No claim of complete Battle.net installation follows from Agent.exe being observed.

Next decision must be based on the actual structured report, not test success or keyword counts alone. Preserve the user's existing Lab, cached downloads and previous scan.
