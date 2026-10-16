"""One pinned Retail reconstruction, offline, separate staging only; no CASC writer."""
import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import sys
import uuid
import patch_audit as a
import source_binding as b
import source_check
import refs_source_check as r

OPTION={'target_ckey':'3d42bf2e42127f313b0ec64cb440cde9','target_size':33940,
 'source_ekey':'914fcad4f4fcf4abb0ba52b197bb066f','source_size':33940,
 'patch_key':'5b933d49c411cc964fe009a18d6c2af9','patch_size':117,'ordinal':0}
OBSERVED={'decoded_sha256':'b03c24b918f8bba4adf016484704e77243b5903d8420aa216c6cf607b53e91a5',
 'encoded_sha256':'da33846ae72275215419174a0a38d8f4a8617b5d872420919f22c89648c01e5e',
 'derived_source_ckey':'98ad7b81687304aa0e99cf326200adfe','encoded_size':158}

def selection(private,prior):
    b.need(private.get('format')=='private-patch-refs-source-1' and private.get('apply_authorized') is False,'private_format')
    b.need(private.get('target')==prior['target'],'private_target_changed')
    b.need(private.get('local_storage_snapshot')==prior['local_storage_snapshot'],'private_snapshot_changed')
    s=private.get('selected_source');b.need(isinstance(s,dict),'selected_source_required')
    b.need(s.get('apply_authorized') is False,'private_not_authorization')
    b.need(s.get('source_ekey')==OPTION['source_ekey'] and s.get('source_size')==OPTION['source_size'],'different_sample_source')
    b.need(s.get('patch_options')==[OPTION],'different_sample_option')
    proof=s.get('proof');b.need(isinstance(proof,dict),'source_proof_required')
    b.need(all(proof.get(k)==v for k,v in OBSERVED.items()),'different_observed_source')
    b.need(proof.get('full_source_ekey_verified') is True and proof.get('pa_source_decoded_size_verified') is True,'prior_source_not_verified')
    b.need(proof.get('source_ekey')==OPTION['source_ekey'] and proof.get('decoded_size')==OPTION['source_size'],'prior_source_identity')
    name=s.get('archive_name');snap=prior['local_storage_snapshot']
    b.need(isinstance(name,str) and re.fullmatch(r'data\.[0-9]{3,}',name) and name in snap['files'],'source_archive_name')
    expected_path=Path(snap['directory'])/name
    b.need(s.get('source_path')==str(expected_path) and s.get('source_fingerprint')==snap['files'][name],'source_location_changed')
    off=s.get('source_offset');raw_off=s.get('raw_offset');span=s.get('span');size=s.get('source_encoded_size')
    b.need(type(off)is int and type(raw_off)is int and raw_off>=0 and off-raw_off in (0,30),'source_offset_shape')
    b.need(type(span)is int and type(size)is int and size==OBSERVED['encoded_size'] and span==size+off-raw_off,'source_span_shape')
    b.need(off+size<=snap['files'][name][2],'source_read_bounds')
    return s

def read_source(s,snapshot,watch):
    path=watch.file(Path(snapshot['directory'])/s['archive_name'],s['source_fingerprint'])
    before=watch.files[path];watch.check()
    with path.open('rb') as f:
        b.need(b.fp(os.fstat(f.fileno()))==before,'source_changed')
        f.seek(s['source_offset']);raw=f.read(s['source_encoded_size'])
        b.need(len(raw)==s['source_encoded_size'] and b.fp(os.fstat(f.fileno()))==before,'source_short_or_changed')
    watch.check()
    decoded,proof=r.decode_source(raw,OPTION['source_ekey'],OPTION['source_size'])
    b.need(all(proof.get(k)==v for k,v in OBSERVED.items()),'source_reverification_mismatch')
    return decoded,proof

def rebuild(old,patch):
    b.need(len(patch)==OPTION['patch_size'],'sample_patch_size')
    return a.apply_patch(old,patch,OPTION['patch_key'],OPTION['target_size'],OPTION['target_ckey'],
                         source_sha256=OBSERVED['decoded_sha256'])

def run(lab,private_file,*,output=None):
    base=Path(__file__).resolve().parent
    _,prior=b.bind(lab,base/'pinned_metadata')
    watch=b.Watch()
    for item in prior['watched_files']:watch.file(item['path'],item['fingerprint'])
    watch.snapshot(prior['local_storage_snapshot'])
    private=b.json_object(watch.read(private_file,2*1024**2))
    s=selection(private,prior)
    # Pin selected relation to current checksum-verified official PA, not just a private report.
    options,_,_=b.load_metadata(base/'pinned_metadata',watch)
    b.need(sum(o.__dict__==OPTION for o in options)==1,'pinned_pa_option_missing_or_ambiguous')
    rows=private.get('watched_files')
    b.need(isinstance(rows,list) and 0<len(rows)<=20000,'private_watch_shape')
    for row in rows:
        b.need(isinstance(row,dict) and set(row)=={'path','fingerprint'},'private_watch_shape')
        watch.file(row['path'],row['fingerprint'])
    out=source_check.output_path(Path(lab),prior,output or base/'Results'/('Staging-Sample-'+uuid.uuid4().hex))
    try:patch=base64.b64decode(watch.read(base/'sample.zbsdiff.base64',4096),validate=True)
    except binascii.Error:raise b.BindingError('patch_base64') from None
    b.need(len(patch)==OPTION['patch_size'] and a.md5(patch)==OPTION['patch_key'],'sample_patch_identity')
    # Validate patch structure before touching any game payload.
    a.parse_patch(patch,OPTION['patch_key'],OPTION['target_size'])
    old,proof=read_source(s,prior['local_storage_snapshot'],watch)
    rebuilt,details=rebuild(old,patch)
    watch.check()
    report={'format':'retail-staging-sample-1','target':prior['target'],
      'status':'one_retail_target_reconstructed_and_ckey_verified','option':OPTION,
      'source_reverified':proof,'patch':details,'patch_md5':a.md5(patch),
      'patch_sha256':a.sha256(patch),'patch_bytes':len(patch),
      'output_ckey':a.md5(rebuilt),'output_sha256':a.sha256(rebuilt),'output_size':len(rebuilt),
      'target_ckey_from_verified_pa':True,'output_readback_verified':False,
      'game_payload_bytes_read':s['source_encoded_size'],
      'network_requests':0,'lab_modified':False,'game_modified':False,
      'patch_applied_in_separate_staging_only':True,'casc_written':False,'activation_performed':False,
      'patch_order_policy_proven':False,'independent_expected_source_ckey_available':False,
      'required_network_download_bytes':None,'installation_ready':False,
      'scope':'one pinned decoded target, not encoded target or installation; no global savings claim',
      'consistency_model':'file-set/stat fingerprints, not OS snapshot or hostile-mutation protection'}
    out.mkdir(parents=True)
    dest=out/'RECONSTRUCTED-TARGET-NOT-INSTALLABLE.bin'
    with dest.open('xb') as f:f.write(rebuilt)
    b.need(dest.read_bytes()==rebuilt,'staging_readback_mismatch')
    watch.check();report['output_readback_verified']=True
    with (out/'Retail-Staging-Sample-to-share.json').open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
    return out,report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--lab');p.add_argument('--private');p.add_argument('--output');args=p.parse_args()
    lab=args.lab;private=args.private
    if not lab or not private:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root=tk.Tk();root.withdraw()
            if not lab:lab=filedialog.askdirectory(title='Select existing Lab root - no scans or writes')
            if lab and not private:private=filedialog.askopenfilename(title='Select LOCAL PRIVATE-Refs-Source.json from previous Results',filetypes=[('Private refs report','PRIVATE-Refs-Source.json')])
            root.destroy()
        except Exception:print('Picker unavailable. Use --lab "LAB" --private "PRIVATE-Refs-Source.json"');return 2
        if not lab or not private:return 0
    print('Offline. One pinned source re-read (158 bytes), one in-memory patch, separate staging only.')
    try:
        out,report=run(lab,private,output=args.output)
        print('Completed. Results folder:',out)
        print('Share ONLY: Retail-Staging-Sample-to-share.json')
        print('Do NOT copy the .bin into the game. No CASC activation was performed.')
        return 0
    except KeyboardInterrupt:print('Cancelled safely.')
    except (b.BindingError,a.AuditError) as e:print('Stopped safely. Code:',str(e))
    except Exception as e:print('Stopped safely. Error type:',type(e).__name__)
    print('Keep Lab and game unchanged. No rescans/downloads needed.');return 1

if __name__=='__main__':sys.exit(main())
