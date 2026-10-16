"""Offline target-binding diagnosis only. No scans, network, or source payload reads."""
import argparse
import json
from pathlib import Path
import re
import sqlite3
import sys
import uuid
import source_binding as b
import source_check
import patch_audit as a

EXPECTED={'product':'wow','region':'eu','version':a.VERSION,'build_config':a.BUILD,'cdn_config':a.CDN}
HASH_FIELDS={'build_config','cdn_config','download_ckey','download_ekey','encoding_ckey','encoding_ekey','install_ckey','install_ekey'}
FIELDS=tuple(EXPECTED)+tuple(sorted(HASH_FIELDS-set(EXPECTED)))

def public_value(key,value):
    if value is None:return None
    if not isinstance(value,str):return '[invalid type]'
    pattern=r'[0-9a-fA-F]{32}' if key in HASH_FIELDS else r'[0-9]{1,3}(?:\.[0-9]{1,7}){3}' if key=='version' else r'[a-z0-9_-]{1,24}'
    return value if re.fullmatch(pattern,value) else '[redacted invalid value]'

def compare(bindings):
    rows={}
    for label,obj in zip(('plan','queue','inventory','evidence'),bindings):
        valid=isinstance(obj,dict)
        rows[label]={'is_dictionary':valid,'fields':{k:public_value(k,obj.get(k)) for k in FIELDS if valid and k in obj},
          'missing_expected_fields':[k for k in EXPECTED if not valid or k not in obj],
          'mismatched_expected_fields':[k for k,v in EXPECTED.items() if not valid or obj.get(k)!=v]}
    base=bindings[0]
    differing=set()
    if all(isinstance(obj,dict) for obj in bindings):
        for obj in bindings[1:]:
            for k in set(base)|set(obj):
                if (k in base)!=(k in obj) or base.get(k)!=obj.get(k):differing.add(k)
    return {'format':'patch-target-binding-diagnostic-1','expected':EXPECTED,'saved':rows,
      'complete_saved_bindings_equal':all(obj==base for obj in bindings),
      'known_fields_differing_between_saved_databases':sorted(differing.intersection(FIELDS)),
      'other_fields_differing_count':len(differing-set(FIELDS)),
      'network_requests':0,'archive_payload_bytes_read':0,'lab_modified':False,
      'game_modified':False,'binding_validation_bypassed':False,'patch_applied':False}

def inspect(lab_root):
    watch=b.Watch();lab=b.safe(lab_root);objects=b.safe(lab/'objects')
    marker=b.json_object(watch.read(lab/'LAB-ONLY.json'))
    b.need(marker.get('format')=='wow-repair-lab-1' and marker.get('real_game_installation') is False and re.fullmatch('[0-9a-f]{32}',str(marker.get('id',''))),'lab_marker_invalid')
    state=b.json_object(watch.read(objects/'downloader-ui-session.json'))
    b.need(state.get('format')=='queue-downloader-ui-1','session_format')
    record=state.get('local_review')
    b.need(isinstance(record,dict) and record.get('format')=='offline-local-review-1','saved_local_review_required_no_migration')
    records=[('p','plan_file','content-plan'),('q','queue_file','acquisition-queue'),('i','local_inventory','local-casc-inventory'),('e','latest_local','local-casc-evidence')]
    db=sqlite3.connect(':memory:',uri=True)
    try:
        db.execute('PRAGMA trusted_schema=OFF')
        for alias,key,prefix in records:
            path=b.ref(objects,record.get(key),prefix,watch)
            if alias in ('p','q'):b.need(path.name==state.get('plan' if alias=='p' else 'queue'),'session_reference_conflict')
            b.attach(db,watch,path,alias)
        report=compare([b.metadata(db,alias,'target_binding') for alias,_,_ in records])
        snapshot=b.metadata(db,'i','local_storage_snapshot')
        b.need(isinstance(snapshot,dict) and isinstance(snapshot.get('directory'),str),'snapshot_shape')
        # Only the directory string is used to keep output outside game sources.
        # No enumeration or payload access to this directory is performed.
        watch.check()
        return report,{'local_storage_snapshot':snapshot},watch
    finally:db.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--lab');args=parser.parse_args();lab=args.lab
    if not lab:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root=tk.Tk();root.withdraw();lab=filedialog.askdirectory(title='Select existing Lab - target metadata only');root.destroy()
        except Exception:
            print('Folder picker unavailable. Use: python diagnose_target.py --lab "PATH_TO_EXISTING_LAB"');return 2
        if not lab:return 0
    try:
        report,private,watch=inspect(lab)
        proposed=Path(__file__).resolve().parent/'Results'/('Target-Diagnostic-'+uuid.uuid4().hex)
        out=source_check.output_path(lab,private,proposed)
        watch.check();out.mkdir(parents=True)
        with (out/'Target-Binding-to-share.json').open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
        print('Diagnosis completed. Share ONLY: Target-Binding-to-share.json')
        print('Results folder:',out)
        print('No scan, download, queue change or patch was performed.')
        return 0
    except (b.BindingError,a.AuditError) as error:print('Stopped safely. Code:',str(error))
    except Exception as error:print('Stopped safely. Error type:',type(error).__name__)
    print('Keep Lab unchanged. Do not restart scans or downloads.');return 1

if __name__=='__main__':sys.exit(main())
