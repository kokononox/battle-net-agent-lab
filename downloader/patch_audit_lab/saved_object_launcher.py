"""One manual read-only saved object review; no automatic continuation."""
from pathlib import Path
import json,sys,uuid
def main():
    if sys.version_info<(3,10):print('Python 3.10+ required. No files changed.');return 1
    import saved_object_review as s
    progress=s.Progress();print('Diagnostic build:',s.VERSION)
    print('READ-ONLY: saved Lab metadata + TWO approved game metadata files.')
    print('Exact saved decoded Download metadata: at most TWO passes, <=256 MiB TOTAL.')
    print('ZERO archive payload reads; no network, scan restart, game/Lab writes.')
    print('Private disposable SQLite: <=512 MiB, separate new output only; NOT a new inventory.')
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
        shown=set()
        def mark(stage):
            progress.mark(stage)
            messages={'deduplicate_selected_records':'Pass 2: revalidate saved Download and deduplicate selected records...',
                'join_saved_inventory':'Compare selected unique EKeys with the EXACT saved inventory (metadata only)...',
                'remove_private_workspace':'Private temporary work removed; final input recheck...',
                'publish_report_noreplace':'Publish read-only report without overwrite...'}
            if stage in messages and stage not in shown:shown.add(stage);print(messages[stage],flush=True)
        q,final=s.run(Path(lab),base/'pinned_metadata',Path(game),base/'Results'/('Saved-Objects-'+uuid.uuid4().hex),progress=mark)
        print('Completed diagnostic. Share ONLY:');print(final)
        print(json.dumps({'status':q['status'],'archive_payload_bytes_read':0,'installation_ready':False},indent=2))
        print('Not listed is UNKNOWN, NOT missing/corrupt. Do NOT restart scans/downloads.')
        return 0
    except KeyboardInterrupt:print('Cancelled safely.');return 130
    except Exception as ex:
        print(json.dumps(s.public_error(ex,progress.stage)));print('Do NOT delete Lab or change game/permissions.');return 1
if __name__=='__main__':raise SystemExit(main())