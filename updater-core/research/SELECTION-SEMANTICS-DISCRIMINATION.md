# Selection semantic discrimination: bounded progress, NOT vendor qualification

## Newly inspected sources
- https://github.com/wowemulation-dev/cascette-py/blob/dc0dfb89b146d80b363741de25c2be340c2da8fd/cascette_tools/formats/size.py : `parse_tag_query` splits comma/question/colon, NOT spaces; additive bitmaps are ORed within numeric type and ANDed across groups. Unknown tokens are ignored; a query with no recognized tokens returns all 0xff. We do NOT copy these fallback or padding behaviors.
- https://github.com/wowemulation-dev/cascette-py/blob/dc0dfb89b146d80b363741de25c2be340c2da8fd/docs/install-workflow-differences.md : claims Agent-aligned selection, but reports Classic-family test installs, priority filtering, no base/target query pair, extra indexed tag-excluded files and unresolved orchestration/recovery differences. These are useful community implementation claims, not an independent official Retail 12.1.5 or future-version oracle. No external code or installer is executed.
- https://github.com/wowemulation-dev/cascette-rs/blob/2d1294b9d8eba0c0d0ffc6387f0777f36ecae671/crates/cascette-formats/src/install/tag.rs : enum maps Category to 4, Unknown to 5, Region to 128. The verified historical Retail manifest/profile uses region 4, speech/text 5. Numeric taxonomy cannot be imported solely by enum name. No new Rust selector implementation was established by the files inspected.

The SourceHut Agent reimplementation location named by the upstream workflow was also checked through page loading, but no content was available. Its raw function implementation/provenance was NOT verified; do not cite it as inspected evidence. No hidden/private RE document was accessed.

## Functional change to our actual selection-review path
`selection_policy.review_tags` now calls `selection_semantics.discriminate` for BOTH Install and Download. The existing paired DNF candidate bitmap is retained exactly. A separate grouped hypothesis is generated from typed dimensions, not by passing candidate DNF strings to an unrelated Agent grammar. Unknown/missing required dimensions still reject; unknown-token => select-all is forbidden.

Each manifest reports the paired and grouped bitmap hashes, counts and at most two earliest differing ordinals. Locale/category cross-pairing is detected. For each opaque 0x4000 tag, explicit hypothetical membership-only, member-or-untagged-in-kind and exclude-tag results are shown separately. They are NOT inferred user preferences, and their results can overlap. We do not adopt any hypothesis or reinterpret missing ProductConfig extra_tags as false.

A four-row regression (enUS/text, enUS/speech, deDE/text, deDE/speech) distinguishes paired preferences from grouped cross-product selection. Same-profile agreement remains insufficient evidence. All arithmetic masks padding. No intersection/union of tested hypotheses is called a required set: hypotheses are not known exhaustive and agreement does not prove closure.

## Owned historical replay
The existing release-bound candidate review rehashed both SQLite databases and consumed metadata/config identities, then re-ran the integrated review on the already-owned 12.1.5.70448 manifests. Grouped and paired hypotheses agree for the historical enUS/text+speech input, and independent per-ordinal checks reproduce the agreement. Candidate bitmap and plan were NOT changed. The historical target is NOT called latest online or a current installed profile. Full details and public-source content digests: reports/SELECTION-SEMANTICS-to-share.json.

This closes an integration/diagnostic gap, not the vendor policy knowledge gap. Open: raw applicable Agent selection evidence or independently scoped Retail reference; Alternate/Talebound/default behavior; duplicate-label variants; dependency/full/patch closure; fresh preferences and active store generation. No live read, game CDN transfer, repair, admin, ACL or write permission is implied. No new ZIP or arbitrary upload request.
