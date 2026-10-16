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

## Verified first observation result

Evidence: reports/run-38929058776-1.json, source 9a7c4552bff2f8409011cd55cb6dbdfb7c52cfc2. All 136 Windows tests passed with zero skips/failures. The exact authorized language step completed and the signed Blizzard Agent was observed.

Nine scoped log files were read: 25,628 bytes and 331 lines, with zero skipped files or oversized/incomplete lines. The retained event list reached 96 records and was truncated; counts cover the scanned text, not only retained records. No raw log text, paths or account data was exported. Log failure/product/completion mentions coexist and do not identify a root cause or prove a failed installation.

At the final 122.2-second UI snapshot the same setup process showed Continue, two unknown static text elements, one unknown checkbox and a Change hyperlink. The snapshot was complete with zero UIA errors, but the finite label/marker rules did not recognize the page. This is not proof that the page is an installation-options screen, a legal screen, or an error screen. No next-page control was activated.

The Agent area contained 129 observed files. No files were observed in the checked app/local_app/temporary_install directories. Full application installation and WoW update/patch behavior remain unproven. No login, game request or user-game/CASC modification occurred.

Next scoped task: classify the fixed setup-page captions and checkbox using a read-only, sanitized UI probe before considering any new action or requesting manual installation. GitHub-hosted runner desktops are ephemeral and no interactive desktop-control channel is available through the current MCP. Do not ask the user to interact with the old runner or imply the browser preview can show it.
