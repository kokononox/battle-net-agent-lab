# Fixed-vocabulary setup-caption observation

## Scope

Reconstruct only the already approved language step on a fresh hosted Windows VM, then observe the next page without invoking any controls. Checkbox state is read using TogglePattern.Current.ToggleState; Toggle is never called. No account inputs, agreement acceptance, directory changes, installation actions or game requests are authorized.

## Data minimization

Only visible, non-password Text and CheckBox captions receive optional caption_features. Names remain bounded to 512 characters. Drive/UNC paths, emails and URLs are removed before vocabulary extraction. Only a fixed technical word vocabulary is emitted, with booleans for path presence, omitted unknown words and truncation. Unknown words, raw text, paths and addresses are never exported. Checkbox state is a finite enum, not a user action. All other control types receive null. The publication validator accepts only these fields and finite words/states, including legacy elements without this optional field.

Python regression tests cover redaction and schema constraints. A required native Windows self-test runs the actual C# classifier on fixed synthetic captions and emits only pass/fail booleans. Native and Python vocabularies must match. Existing read-only API restrictions and signature/language-action safety checks remain enforced.

## Interpretation

Use the actual post-language caption tokens plus control roles/state to identify the page. A path, Change hyperlink and startup checkbox may support identifying installation options; do not assume that before the report arrives. Do not activate the next Continue until its purpose and any agreement/installation implications are explicit.

## Static-text read fallback

Run 38930265052 passed all 153 Windows tests. The final checkbox vocabulary identified Launch / Battle.net / when / start / computer with toggle_state on. The two static Text names did not identify their displayed content; no next-page action was made.

For an already PID/HWND-scoped, visible, non-password ControlType.Text only, when the Name yields no known tokens or path, the next probe may read ValuePattern.Current.Value and then TextPattern.DocumentRange.GetText(512). Both go immediately through the same fixed-vocabulary/path/address sanitizer. No ValuePattern is requested on Edit, Document, Custom or unknown controls. No text range actions, selections or writes occur. Existing tests that prohibited all text/value reads are refined to assert the exact static-text scope and fixed 512-character read limit, while preserving every mutating-API prohibition.
