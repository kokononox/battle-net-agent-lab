# Selection-policy blocker review — follow-up to 0.22

## Priority correction
The first product milestone is NOT complete. It contains (a) qualified required-set selection/variant/dependency/patch rules, (b) fresh installed preferences and identity, and (c) coherent active installed generation. A bounded two-metadata-file reader would cover only part of (b), not (a) or (c). No new identity-reader code was committed or qualified in this review. Subsequent download-size and apply stages must not be promoted on this basis.

## Newly inspected immutable independent sources
1. CascLib at 38a34665624b8775bb875274b36191b21c38d97b, src/CascRootFile_Install.cpp, blob 2a01acb8590e5f99f92421b7e7286f40ca5c0382. TRootHandler_Install::Load explicitly skips tag records, then inserts file names whose CKeys are known. This is a root lookup handler, NOT an updater selection oracle.
   https://github.com/ladislav-zezula/CascLib/blob/38a34665624b8775bb875274b36191b21c38d97b/src/CascRootFile_Install.cpp
2. TACTSharp at 67fd53ac852ca297e9bf95bb41d1a97da202eba4, TACTSharp/InstallInstance.cs, blob 89ffc3fd5028c6afe9ad5a7fa569d1ea2f0259f2. Parses tag bitmaps and records per-entry tags; does not establish Battle.net required-set selection, Alternate/Talebound preference or patch closure.
   https://github.com/wowdev/TACTSharp/blob/67fd53ac852ca297e9bf95bb41d1a97da202eba4/TACTSharp/InstallInstance.cs
3. Same TACTSharp commit, TACTTool/Program.cs, blob f259de8a97b34df4259ab41f7f3693308f97aae3. HandleFileName selects a US-tagged entry when multiple results exist, otherwise the first result; HandleCKey uses the first encoding representation. These are extraction heuristics, not authoritative updater variant rules; do not import them as EU install policy or EKey route choice.
   https://github.com/wowdev/TACTSharp/blob/67fd53ac852ca297e9bf95bb41d1a97da202eba4/TACTTool/Program.cs

An unscoped Talebound code search returned predominantly unrelated service/game database names; none was used as policy evidence. Stop this keyword line rather than treating a label match as an installer reference.

## Evidence still needed before closing milestone 1
- A source that actually implements/describes the relevant Battle.net install-selection rules, OR independent bounded reference observations for the same pinned build and explicit profile. One reference case is not proof for every future version or profile.
- Reference outputs must distinguish candidate membership and duplicate-name variants, explain Alternate/0x4000 and Talebound inclusion/exclusion, and establish dependency and patch/full route closure. A label definition, extractor default, manifest bitmap or internally self-generated expected list is insufficient.
- Fresh installation preference input must separate text and speech locales and any actual supported feature preference. An old uploaded tag row is not fresh state.
- Active-generation evidence must bind the live installation coherently; choosing the highest index filename, old copied indices or metadata Active=1 alone is insufficient. Unknown V8 is not guessed.

No live probe/reference capture is prepared or requested here. Before asking the user to run one, define exact inputs/files/byte limits, privacy filtering and stop conditions; no game writes, automatic update, repair, scan, admin or permission changes. User availability of Windows/space is not approval to perform an official update or capture arbitrary logs/account data.

## State
vendor_selection_policy_qualified=false; feature_tag_policy_qualified=false; fresh_installed_preferences_proven=false; dependency_and_variant_policy_qualified=false; patch_route_policy_qualified=false; active_generation_proven=false; required_set_selected=false; required_network_download_bytes=null; installation_ready=false; apply_authorized=false.

No candidate bitmap or plan was changed. No new code/tests or game/CDN/installer operations occurred. Previous 0.22 counts remain 595 Linux and 233 native Windows; those are NOT evidence of vendor policy. This is documentation/evidence review only.
