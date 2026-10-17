"""Single-run picker for saved metadata scope review; no automatic continuation."""
from pathlib import Path
import json,sys,uuid

def main():
    if sys.version_info<(3,10):print('Python 3.10+ required. No files changed.');return 1
    import saved_scope_review as s
    progress=s.Progress();print('Diagnostic build:',s.VERSION)
    print('READ-ONLY: existing saved Lab metadata + TWO approved game metadata files.')
    print('Exact saved decoded Download metadata only (<=256 MiB); ZERO archive payload reads.')
    print('No network, scan restart, game/Lab writes, or automatic continuation.')
    try:
        import tkinter as tk
        from tkinter import filedialog
        root=tk.Tk();root.withdraw()
        try:
            lab=filedialog.askdirectory(title='Select EXISTING saved Lab containing LAB-ONLY.json')
            if not lab:print('Cancelled.');return 0
            game=filedialog.askdirectory(title='Select SAME game ROOT containing .build.info (not Data or _retail_)')
        finally:root.destroy()
        if not game:print('Cancelled.');return 0
        base=Path(__file__).resolve().parent
        q,private=s.review(Path(lab),base/'pinned_metadata',Path(game),progress=progress.mark)
        final=s.publish(q,private,base/'Results'/('Saved-Scope-'+uuid.uuid4().hex),progress=progress.mark)
        progress.mark('complete');print('Completed diagnostic. Share ONLY:');print(final)
        print(json.dumps({'status':q['status'],'archive_payload_bytes_read':0,'installation_ready':False},indent=2))
        print('Unknown is NOT missing/corrupt. Do NOT restart scans/downloads or old batches.')
        return 0
    except KeyboardInterrupt:print('Cancelled safely.');return 130
    except Exception as ex:
        print(json.dumps(s.public_error(ex,progress.stage)));print('Do NOT delete Lab or change game/permissions.');return 1
if __name__=='__main__':raise SystemExit(main())
