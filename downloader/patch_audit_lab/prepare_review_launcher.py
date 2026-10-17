"""Explicit local continuation entry point. No automatic batch loop."""
import sys
if sys.version_info<(3,10):
    print("Python 3.10 or newer is required. No files changed.");raise SystemExit(1)
from local_review_launcher import main
if __name__=="__main__":raise SystemExit(main(metadata_only=True))
