"""Folder picker for the approved two-file, no-archive metadata probe."""
from pathlib import Path
import json,sys,uuid

def main():
    if sys.version_info<(3,10):print('Python 3.10 or newer is required. No files changed.');return 1
    import installed_profile_probe as probe
    progress=probe.Progress()
    print('Diagnostic build:',probe.VERSION)
    print('READ-ONLY: .build.info and its ONE named build-config only.')
    print('No archive reads, no scan, no Lab access, no network, no game writes.')
    try:
        import tkinter as tk
        from tkinter import filedialog
        root=tk.Tk();root.withdraw();progress.mark('select_game_root')
        try:game=filedialog.askdirectory(title='Select game ROOT directly containing .build.info (NOT Data, _retail_ or Lab)')
        finally:root.destroy()
        if not game:print('Cancelled. No files changed.');return 0
        report,private=probe.read(Path(game),progress=progress.mark)
        base=Path(__file__).resolve().parent
        final=probe.publish(report,private,base/'Results'/('Installed-Profile-'+uuid.uuid4().hex),progress=progress.mark)
        progress.mark('complete');print('Completed metadata check. Share ONLY:');print(final)
        print(json.dumps({'status':report['status'],'profile_error':report['profile_error'],'archive_payload_bytes_read':0,'installation_ready':False},indent=2))
        print('Do not send .build.info or raw config. Do not start continuation batches yet.')
        return 0
    except KeyboardInterrupt:print('Cancelled safely.');return 130
    except Exception as ex:
        print(json.dumps(probe.public_error(ex,progress.stage)))
        print('Do NOT modify game or Lab, change permissions, or restart scans/downloads.');return 1
if __name__=='__main__':raise SystemExit(main())
