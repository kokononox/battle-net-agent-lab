# Source sync 0.16

This directory preserves the 0.16 release source and sanitized receipts, separate from historical `downloader/`. It is not a Windows installer. Binary **public metadata** fixtures are text-encoded in five `research/fixtures/*.b64` files because the GitHub MCP push API supports UTF-8 text only. No game asset payload, private Lab, SQLite database, staged object, credentials or raw transcript is included.

Run from this directory:
```sh
python restore_public_fixtures.py
python -m unittest discover -v
```
The release manifest verifies exact restored bytes. The original ZIP SHA-256 is `adc62a754f061d7591d8b4d51e328748683ecdcd05ca7b8f69d2e8223eab41a0`. 411 tests passed on Linux; this is not native Windows qualification. Historical approvals in receipts are closed, not permission to repeat network or install actions.
