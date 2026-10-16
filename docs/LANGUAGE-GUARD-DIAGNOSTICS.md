# Language-page guard diagnostics

The report for source 356b582 showed known language controls, but the action helper returned the broad page_not_language status before any selection or Continue. This does not identify which guard failed, and the cause is not yet established.

This change preserves the exact checks and action scope. It only replaces broad rejection codes with finite reasons: unsafe_name, name_too_long, forbidden_control, forbidden_text, language_group_missing, language_group_ambiguous, continue_missing, continue_ambiguous, page_changed. No provider text is exported.

The one-off workflow authorization is rotated for the user-requested continuation. Only the first push attempt for the exact named commit may select English (US) and invoke the same language-page Continue once. No agreements, login, game selection or CASC changes are authorized. A rerun remains observation-only.

Local validation covers the Python language wrapper and finite-code publication contract. Native Windows compilation and the full safety suite remain required in Actions. This is a diagnostic change, not a claim that the installer blocker is fixed.

## First Windows result and targeted traversal correction

Run 38841730984 passed all 105 safety tests, verified the installer, and returned language_group_missing with no action. Both read-only UIA snapshots showed the language group. The action walk uniquely pruned nodes AND their children using runtime IDs, unlike the read-only walk. That optimization can discard structural occurrences in provider trees.

Remove only subtree pruning by runtime ID. Keep the full existing node, sibling, stack, depth, time, PID, owner/path, exact-label, legal/account, pattern, uniqueness and revalidation guards. If a tree repeats too much, exceeds bounds or presents duplicate matching controls it still stops; no fallback clicks are added. Radio matching within the accepted group remains separately bounded and deduplicated as before. This targets an implementation difference; a fresh Windows run must establish whether it resolves the real failure.
