# Source sync 0.17

This directory preserves the 0.17 release source and sanitized receipts, separate from historical `downloader/`. It is not a Windows installer. Binary **public metadata** fixtures are text-encoded in five `research/fixtures/*.b64` files because the GitHub MCP push API supports UTF-8 text only. No game asset payload, private Lab, SQLite database, staged object, credentials or raw transcript is included.

Run from this directory:
```sh
python restore_public_fixtures.py
python -m unittest discover -v
```
The release manifest verifies exact restored bytes. The original ZIP SHA-256 is `42e44d43bda6248382f11713d6d05ddaddc63a3347358c98882fc10815c9b95f`. 476 tests passed on Linux; this is not native Windows qualification. Historical approvals in receipts are closed, not permission to repeat network or install actions.

Actual Windows CI passed 73 synthetic parser/selection tests without skip. This does not qualify the POSIX stage, a native Windows writer, game activation or live reuse. See reports/WINDOWS-PORTABLE-CI-to-share.json.
