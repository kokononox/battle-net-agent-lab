"""Folder-picker entry for the bounded read-only review bundle, not an updater."""
from pathlib import Path
import json,sys,uuid

def main():
    if sys.version_info<(3,10):
        print('Python 3.10 or newer is required. No files changed.');return 1
    import local_update_review as review
    progress=review.Progress()
    print('Diagnostic build:',review.DIAGNOSTICS_VERSION)
    print('READ-ONLY: existing saved Lab only; no network, no scan restart, no game writes.')
    print('At most 32 MiB of archive payload reads. Unknown is not missing or corrupt.')
    try:
        import tkinter as tk
        from tkinter import filedialog,messagebox
        root=tk.Tk();root.withdraw()
        progress.mark('select_lab')
        lab=filedialog.askdirectory(title='Select EXISTING saved WoW-Downloader-Lab (not the game folder)')
        root.destroy()
        if not lab:print('Cancelled. No files changed.');return 0
        base=Path(__file__).resolve().parent
        report,private=review.review(Path(lab),base/'pinned_metadata',progress=progress.mark)
        out=review.publish(Path(lab),report,private,base/'Results'/('Local-Review-'+uuid.uuid4().hex),progress=progress.mark)
        progress.mark('complete')
        print('Completed. Share ONLY this report:');print(out/'LOCAL-UPDATE-REVIEW-to-share.json')
        print(json.dumps({'actions':report['actions'],'archive_payload_bytes_read':report['local_verification']['archive_payload_bytes_read'],'installation_ready':False},indent=2))
        return 0
    except KeyboardInterrupt:print('Cancelled safely.');return 130
    except Exception as ex:
        print(json.dumps(review.public_error(ex,stage=progress.stage)))
        print('Do NOT delete Lab, modify the game or restart scans/downloads.')
        print('Use local_update_review.py --help for the command-line method.')
        return 1
if __name__=='__main__':raise SystemExit(main())
