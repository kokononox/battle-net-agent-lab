# Targeted public policy evidence review — 0.20

Sources loaded during this step:
- https://wowdev.wiki/TACT — World of Warcraft / Tags describes Alternate as a special category for censored content and maps alternate to 0x4000 in the version-specific values. It also describes multiple EKey representations and download priorities. This is community format documentation, NOT a complete selection algorithm for Battle.net.
- https://github.com/wowdev/TACTSharp — README presents TACTTool as a simple extraction tool. Install-tag priority and encrypted-product support appear under TODO for 1.0 in the retrieved README. Extraction support is not independent evidence of production required-set policy or transactional installation behavior.

Consequences:
- Do not classify every 16384 tag as an ordinary optional feature.
- Do not infer Talebound semantics, precedence, variant exclusion, patch closure or region-specific selection from the enum alone.
- Do not flip vendor_selection_policy_qualified or feature_tag_policy_qualified. Previously computed candidate counts/bitmaps stay unchanged; no object was dropped or downloaded based on this review.
- Still required: independent policy/reference evidence for the relevant product and fresh installation preferences. Public evidence retrieved here is insufficient. Further identical keyword searches are not a substitute for an oracle.

No new game-CDN scope was executed or reopened. This review does not establish installed generation or download size.
