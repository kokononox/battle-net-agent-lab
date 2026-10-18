# Source sync 0.15

This directory preserves the 0.15 release source and sanitized receipts, separate from historical `downloader/`. It is not a Windows installer. Binary **public metadata** fixtures are text-encoded in five `research/fixtures/*.b64` files because the GitHub MCP push API supports UTF-8 text only. No game asset payload, private Lab, SQLite database, staged object, credentials or raw transcript is included.

Run from this directory:
```sh
python restore_public_fixtures.py
python -m unittest discover -v
```
The release manifest verifies exact restored bytes. The original ZIP SHA-256 is `7e3a4184ff5366f59eabe52a09e0b8ae98176dbf5316b129a3c24b9a96ff06c4`. 383 tests passed on Linux; this is not native Windows qualification. Historical approvals in receipts are closed, not permission to repeat network or install actions.
