# One-window visual inspection

The static-caption methods could identify the selected startup checkbox but not the two other Text elements, even with bounded static ValuePattern/TextPattern reads (run 38931735443, all 155 Windows tests passed). Stop extending keyword probes and inspect the actual rendered setup page.

## Capture boundary

Only after the user-approved language step, on a fresh hosted VM with no account input, capture the exact current setup options window, not the desktop. The helper verifies the target HWND/PID, visibility, exact setup process name, Authenticode and Blizzard publisher, and a complete small UIA tree: one setup window, one Continue button, one Change hyperlink, one CheckBox, two static Text controls. All elements must be same-process, visible, enabled and non-password. Any edit/document/account or unknown extra control refuses capture. Revalidate the page after PrintWindow. No UI actions are added.

PrintWindow renders only the window; there is no screen/desktop fallback. Dimensions are 100..1024 by 100..768, PNG at most 64 KiB. The image may show only this fresh runner's setup page and generic installation path; unlike the finite caption probe it is actual window pixels, not text-redacted. No human account, user game/Lab, tokens, raw logs or game binaries are present or exported. Store only in the existing private experiment repository report.

Schema 8 adds setup_visual with a strict finite status, dimensions and PNG-only bounded base64 payload. A denied-config native integration test must return refusal without pixels. Old evidence remains in versioned reports. The user is not asked to interact with the ephemeral runner. Do not click Continue or alter the checkbox based solely on a guessed page classification.
