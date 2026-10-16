# One approved Battle.net client-install step

## Scope and evidence
The user supplied screenshots of the official installer and requested the next step. The third screenshot identifies the options page: install location, Change, checked launch-at-startup option, Continue. This resolves the meaning of the six-control UIA shape in earlier reports; it does not establish that prior runs installed the client.

## Permitted action
On one exact, first-attempt source push on a fresh GitHub-hosted Windows runner:
1. Download and validate the official Blizzard-signed bootstrapper under existing rules.
2. Perform the already approved language selection and Continue once.
3. At or after 30 seconds, attempt one scoped setup-options inspection only if the language action returned with no uncertainty.
4. Verify original setup PID, HWND, executable path, Authenticode trust and Blizzard publisher. Require the exact bounded six-element setup-options tree, including exact startup-option name, Change and Continue. Reject extra roles, password/offscreen/disabled controls, known legal/account/error text or ambiguous controls.
5. Recheck owner and exact same page/button; journal the attempt durably, then invoke Continue once. Never retry uncertain outcomes.
6. Observe read-only for the remainder of the bounded 150-second period, then clean up processes. No account, legal, login, game or additional wizard actions exist. Startup checkbox and installation path are not changed.

The official installer may download the Battle.net desktop client in this disposable VM. As in the existing report, child-process network traffic has no hard byte cap; duration and fresh-runner scope are bounded. No user game files, account credentials or WoW data are used. No machine-wide screenshot is taken; the previously refused visual capture is disabled for this install run.

## Reporting
Schema 9 adds strict install_step booleans/enums and permits the one additional scoped pre-install GUI snapshot. `continued` means Invoke returned, NOT proof of completed installation. Final GUI, process and file metadata remain read-only evidence. Login screens are observed, not acted upon; no readiness poll repeats a click.

## Before first execution
Existing tests plus dedicated default-deny, scope, authorization, schema, journal, uncertain-timeout, signature/page-source guard and Windows denied-config tests must pass. Local Linux tests skip native Windows checks; the mandatory Windows suite runs before downloading Setup. Execution results are not yet known at this source commit.
