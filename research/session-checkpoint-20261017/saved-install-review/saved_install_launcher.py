"""One manual exact saved Install metadata observation; no continuation."""
from pathlib import Path
import json
import sys
import uuid


def main():
    if sys.version_info < (3, 10):
        print("Python 3.10+ required. No inputs changed.")
        return 1
    import saved_install_review as review
    sys.addaudithook(review.block_network)
    progress = review.Progress()
    print("Diagnostic build:", review.VERSION)
    print("READ-ONLY: existing saved Lab + TWO previously approved game metadata files.")
    print("ONE exact decoded Install cache reference; at most 24,078 bytes, ONE pass.")
    print("ZERO Download/Encoding or archive payload reads. No network or game/Lab writes.")
    print("Absent exact metadata means UNKNOWN: no search, extraction or download.")
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        try:
            lab = filedialog.askdirectory(title="Select EXISTING saved Lab containing LAB-ONLY.json")
            if not lab:
                print("Cancelled.")
                return 0
            game = filedialog.askdirectory(title="Select SAME game ROOT containing .build.info")
        finally:
            root.destroy()
        if not game:
            print("Cancelled.")
            return 0
        base = Path(__file__).resolve().parent
        report, final = review.run(
            Path(lab), base / "pinned_metadata", Path(game),
            base / "Results" / ("Install-Review-" + uuid.uuid4().hex), progress=progress.mark,
        )
        print("Completed read-only observation. Share ONLY:")
        print(final)
        print(json.dumps({"status": report["status"], "installation_ready": False}, indent=2))
        print("Do NOT delete Lab, move caches, restart scans or download anything.")
        return 0
    except KeyboardInterrupt:
        print("Cancelled safely.")
        return 130
    except Exception as error:
        print(json.dumps(review.public_error(error, progress.stage)))
        print("Do NOT delete Lab or change game/permissions.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())