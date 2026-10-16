"""User entry: select existing Lab, bind saved sources offline, write separate results.

Never network, modify Lab, reread game payloads, repair or apply a patch.
"""
import argparse
import json
from pathlib import Path
import sys
import uuid
import source_binding as b
import patch_audit as a


def output_path(lab,private,requested=None):
    base=Path(__file__).resolve().parent
    output=Path(requested).absolute() if requested else base/'Results'/('Source-Binding-'+uuid.uuid4().hex)
    # Reject symlink/reparse ancestors even for a not-yet-existing destination.
    existing=output
    while not existing.exists() and not existing.is_symlink():
        need_parent=existing.parent
        b.need(need_parent!=existing,'output_parent_not_found');existing=need_parent
    b.safe(existing)
    folder=Path(private['local_storage_snapshot']['directory'])
    game=folder.parent.parent if folder.name.lower()==folder.parent.name.lower()=='data' else folder
    for protected in (Path(lab).absolute(),game,base/'pinned_metadata'):
        b.need(output!=protected and protected not in output.parents and output not in protected.parents,'results_must_be_outside_sources')
    b.need(not output.exists() and not output.is_symlink(),'new_output_required')
    return output


def publish(lab,public,private,requested=None):
    out=output_path(lab,private,requested)
    out.mkdir(parents=True)
    for name,obj in [('Retail-Patch-Source-Binding-to-share.json',public),('PRIVATE-Patch-Source-Plan.json',private)]:
        with (out/name).open('x',encoding='utf-8') as f:json.dump(obj,f,ensure_ascii=False,indent=2)
    return out


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab',help='Existing WoW-Downloader-Lab; picker shown if absent')
    parser.add_argument('--output',help='New output folder, outside Lab and game')
    args=parser.parse_args()
    lab=args.lab
    if not lab:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root=tk.Tk();root.withdraw()
            lab=filedialog.askdirectory(title='Select existing WoW-Downloader-Lab — offline metadata only')
            root.destroy()
        except Exception:
            print('Folder picker unavailable. Use: python source_check.py --lab "PATH_TO_EXISTING_LAB"')
            return 2
        if not lab:return 0
    print('Offline: reading saved metadata and checking source file identities. No archive payload reads. Please wait.')
    try:
        public,private=b.bind(lab,Path(__file__).resolve().parent/'pinned_metadata')
        # Recheck input fingerprints immediately before publishing external results.
        watch=b.Watch()
        for record in private['watched_files']:watch.file(record['path'],record['fingerprint'])
        watch.snapshot(private['local_storage_snapshot']);watch.check()
        out=publish(lab,public,private,args.output)
        print('Completed. Results folder:',out)
        print('Share ONLY: Retail-Patch-Source-Binding-to-share.json')
        print('Keep PRIVATE-Patch-Source-Plan.json local. No patch was applied.')
        print(json.dumps(public['options_by_state']))
        return 0
    except (b.BindingError,a.AuditError) as error:
        # Known safe codes only; no paths, SQLite messages or raw exception data.
        print('Stopped safely. Code:',str(error))
    except Exception as error:
        print('Stopped safely. Error type:',type(error).__name__,'(private details not printed)')
    print('Do not delete Lab or restart scans/downloads because of this error.')
    return 1

if __name__=='__main__':sys.exit(main())
