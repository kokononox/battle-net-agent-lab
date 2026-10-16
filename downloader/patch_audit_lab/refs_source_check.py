"""Saved refs lookup, then at most one bounded source proof. Offline; no patch."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
import sys
import time
import uuid
import patch_audit as a
import source_binding as b
import source_check

MAX_MATCHES=250000
MAX_CANDIDATES=256
MAX_READ=32*1024**2
MAX_SPAN=8*1024**2+30
MAX_ATTEMPTS=16
PREFERRED_PATCHES=frozenset(('a56b3fe67a775fe9f4e86d6cbb688b5d','9f5a10d155141ec21d1485b481ca4387'))

def decode_source(raw,ekey,expected_size):
    """Verify encoded identity; derive decoded CKey (not an independent CKey).

    Supports ordinary N/Z single-chunk or table BLTE only. Encrypted/F modes
    remain unsupported, never interpreted as corrupt or absent.
    """
    a.key(ekey)
    a.require(type(expected_size)is int and 0<expected_size<=a.MAX_METADATA,'source_decoded_limit')
    a.require(8<len(raw)<=MAX_SPAN and raw[:4]==b'BLTE','source_blte_header')
    hs=int.from_bytes(raw[4:8],'big')
    if hs==0:
        a.require(a.md5(raw)==ekey,'source_full_ekey_mismatch')
        chunks=[(raw[8:],expected_size)]
    else:
        a.require(len(raw)>=12 and raw[8]==15,'source_blte_flags')
        count=int.from_bytes(raw[9:12],'big')
        a.require(0<count<=1024 and hs==12+24*count and hs<=len(raw),'source_blte_table')
        a.require(a.md5(raw[:hs])==ekey,'source_full_ekey_mismatch')
        chunks=[];offset=hs;total=0
        for i in range(count):
            at=12+i*24;cs,ds=struct.unpack_from('>II',raw,at)
            a.require(cs>0 and ds>0 and offset+cs<=len(raw) and total+ds<=expected_size,'source_chunk_bounds')
            chunk=raw[offset:offset+cs]
            a.require(hashlib.md5(chunk).digest()==raw[at+8:at+24],'source_chunk_checksum')
            chunks.append((chunk,ds));offset+=cs;total+=ds
        a.require(offset==len(raw) and total==expected_size,'source_encoded_or_decoded_size')
    out=bytearray()
    for chunk,ds in chunks:
        a.require(chunk[:1] in (b'N',b'Z'),'source_unsupported_chunk_mode')
        data=chunk[1:] if chunk[:1]==b'N' else a.inflate(chunk[1:],ds)
        a.require(len(data)==ds and len(out)+ds<=expected_size,'source_chunk_decoded_size')
        out.extend(data)
    a.require(len(out)==expected_size,'source_decoded_size')
    return bytes(out),{'source_ekey':ekey,'decoded_size':len(out),'derived_source_ckey':a.md5(out),
      'decoded_sha256':a.sha256(out),'encoded_sha256':a.sha256(raw),'encoded_size':len(raw),
      'full_source_ekey_verified':True,'chunk_integrity_verified':hs!=0,
      'single_chunk_full_object_hash_verified':hs==0,'pa_source_decoded_size_verified':True,
      'independent_expected_source_ckey_available':False,'decoded_ckey_is_derived_not_independent':True,
      'patch_applied':False,'patch_order_policy_proven':False}

def search_refs(db,options,snapshot,*,time_limit=120,cancel=lambda:False):
    """Scan saved refs metadata ONCE, indexed transient lookup; no source writes."""
    b.schema(db,'i','refs',('prefix','archive_id','raw_offset','span'))
    b.schema(db,'i','archives',('archive_id','name','size','ambiguous'))
    bykey={}
    for o in options:
        if o.source_ekey in bykey:b.need(bykey[o.source_ekey][0].source_size==o.source_size,'pa_source_size_conflict')
        bykey.setdefault(o.source_ekey,[]).append(o)
    byprefix={}
    for key in bykey:byprefix.setdefault(bytes.fromhex(key)[:9],[]).append(key)
    db.execute('CREATE TEMP TABLE wanted_prefix(prefix BLOB PRIMARY KEY) WITHOUT ROWID')
    db.executemany('INSERT INTO wanted_prefix VALUES (?)',[(p,) for p in byprefix])
    started=time.monotonic()
    b.need(not cancel(),'cancelled')
    db.set_progress_handler(lambda:int(cancel() or time.monotonic()-started>time_limit),10000)
    sql='''SELECT r.prefix,r.archive_id,r.raw_offset,r.span,a.name,a.size,a.ambiguous
      FROM i.refs r CROSS JOIN wanted_prefix w ON w.prefix=r.prefix
      LEFT JOIN i.archives a ON a.archive_id=r.archive_id LIMIT ?'''
    plan=[r[3] for r in db.execute('EXPLAIN QUERY PLAN '+sql,(MAX_MATCHES+1,))]
    # CROSS JOIN enforces refs outer scan; transient primary key handles lookup.
    b.need(any('SEARCH w USING PRIMARY KEY' in s for s in plan),'unexpected_refs_query_plan')
    matched=set();sources=set();candidates={};invalid=oversize=rows=0
    for prefix,aid,offset,span,name,size,ambiguous in db.execute(sql,(MAX_MATCHES+1,)):
        rows+=1;b.need(rows<=MAX_MATCHES,'matched_reference_limit')
        if rows%1024==0:b.need(not cancel() and time.monotonic()-started<=time_limit,'cancelled_or_metadata_time_limit')
        keys=byprefix[prefix];matched.add(prefix);sources.update(keys)
        valid=(type(aid)is int and 0<=aid<1024 and type(offset)is int and offset>=0 and type(span)is int and span>0
          and type(size)is int and size>0 and ambiguous==0 and isinstance(name,str)
          and re.fullmatch(r'data\.[0-9]{3,}',name) and name in snapshot['files']
          and snapshot['files'][name][2]==size and offset+span<=size)
        if not valid:invalid+=1;continue
        if span>MAX_SPAN:oversize+=1;continue
        for key in keys:
            opts=bykey[key]
            if not 0<opts[0].source_size<=a.MAX_METADATA:continue
            preferred=any(o.patch_key in PREFERRED_PATCHES for o in opts)
            row={'source_ekey':key,'source_size':opts[0].source_size,'archive_name':name,'raw_offset':offset,'span':span,
                 'patch_options':[o.__dict__ for o in opts]}
            rank=(not preferred,span,key,aid,offset)
            candidates[rank]=row
        # Keep only best bounded metadata candidates; still count all matches.
        if len(candidates)>MAX_CANDIDATES:
            candidates={k:candidates[k] for k in sorted(candidates)[:MAX_CANDIDATES]}
    b.need(not cancel() and time.monotonic()-started<=time_limit,'cancelled_or_metadata_time_limit')
    return [candidates[k] for k in sorted(candidates)],{
      'pa_distinct_source_ekeys':len(bykey),'matched_reference_rows':rows,
      'source_ekeys_with_prefix_candidates':len(sources),'matched_prefixes':len(matched),
      'invalid_or_unavailable_archive_reference_rows':invalid,'oversize_reference_rows':oversize,
      'retained_bounded_candidates':len(candidates),'refs_metadata_scanned_once':True,
      'prefix_match_is_not_source_proof':True,'no_prefix_match_is_not_global_absence':True,
      'scope':'all_pinned_PA_sources_against_saved_refs_not_profile_filtered',
      'refs_metadata_query_seconds':round(time.monotonic()-started,3)}


def verify_one(candidates,snapshot,watch,*,budget=MAX_READ,max_attempts=MAX_ATTEMPTS,cancel=lambda:False):
    b.need(type(budget)is int and 0<=budget<=MAX_READ and type(max_attempts)is int and 0<=max_attempts<=MAX_ATTEMPTS,'source_read_budget')
    spent=attempts=0;reasons=Counter();verified=None;private=None;reads={}
    folder=Path(snapshot['directory'])
    for candidate in candidates:
        b.need(not cancel(),'cancelled')
        if attempts>=max_attempts:break
        key=(candidate['archive_name'],candidate['raw_offset'],candidate['span'])
        if key not in reads and candidate['span']>budget-spent:
            reasons['candidate_exceeds_remaining_budget']+=1;continue
        if key in reads:raw=reads[key]
        else:
            span=candidate['span'];offset=candidate['raw_offset']
            b.need(type(span)is int and 0<span<=MAX_SPAN and type(offset)is int and offset>=0,'source_read_bounds')
            name=candidate['archive_name'];b.need(re.fullmatch(r'data\.[0-9]{3,}',name) and name in snapshot['files'],'source_archive_name')
            path=watch.file(folder/name,snapshot['files'][name]);expected=watch.files[path]
            b.need(offset+span<=expected[2],'source_read_bounds')
            with path.open('rb') as f:
                b.need(b.fp(os.fstat(f.fileno()))==expected,'source_changed')
                f.seek(offset);raw=f.read(span);spent+=len(raw)
                b.need(len(raw)==span and b.fp(os.fstat(f.fileno()))==expected,'source_short_or_changed')
            watch.check();reads[key]=raw
        attempts+=1
        for shift in (0,30):
            if len(raw)<=shift+8:continue
            try:
                decoded,proof=decode_source(raw[shift:],candidate['source_ekey'],candidate['source_size'])
            except a.AuditError as error:
                reasons[str(error)]+=1;continue
            watch.check()
            verified=proof
            private={**candidate,'source_path':str(folder/candidate['archive_name']),
              'source_offset':candidate['raw_offset']+shift,'source_encoded_size':len(raw)-shift,
              'source_fingerprint':snapshot['files'][candidate['archive_name']],
              'proof':proof,'apply_authorized':False}
            break
        if verified:break
    return verified,private,{'archive_payload_bytes_read':spent,'candidate_attempts':attempts,
      'read_budget_bytes':budget,'max_candidate_attempts':max_attempts,
      'attempt_outcomes_not_corruption_verdicts':dict(sorted(reasons.items()))}


def run(lab_root,*,output=None,metadata_only=False):
    base=Path(__file__).resolve().parent
    # Reuse all established plan/queue/checkpoint/binding/snapshot guards.
    _,prior=b.bind(lab_root,base/'pinned_metadata')
    watch=b.Watch()
    for row in prior['watched_files']:watch.file(row['path'],row['fingerprint'])
    snapshot=prior['local_storage_snapshot'];watch.snapshot(snapshot)
    lab=b.safe(lab_root);state=b.json_object(watch.read(lab/'objects'/'downloader-ui-session.json'))
    inv=b.ref(lab/'objects',state['local_review']['local_inventory'],'local-casc-inventory',watch)
    options,_,_=b.load_metadata(base/'pinned_metadata',watch)
    db=sqlite3.connect(':memory:',uri=True)
    try:
        db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA temp_store=MEMORY')
        b.attach(db,watch,inv,'i')
        candidates,discovery=search_refs(db,options,snapshot)
    except sqlite3.OperationalError:raise b.BindingError('refs_query_cancelled_or_rejected') from None
    finally:db.close()
    watch.check()
    proof,source,usage=verify_one(candidates,snapshot,watch,budget=0 if metadata_only else MAX_READ)
    report={'format':'patch-refs-source-check-1','target':prior['target'],**discovery,**usage,
      'status':'one_source_encoded_identity_verified' if proof else 'no_source_proof_within_this_bounded_check',
      'verified_source':proof,'associated_patch_options':source['patch_options'] if source else [],'network_requests':0,'lab_modified':False,'game_modified':False,
      'idx_files_reread':False,'whole_archives_scanned':False,'patch_applied':False,
      'patch_order_policy_proven':False,'required_network_download_bytes':None,'installation_ready':False,
      'metadata_only_requested':metadata_only,'consistency_model':'saved_file_set_and_stat_fingerprints_not_OS_snapshot'}
    private={'format':'private-patch-refs-source-1','target':prior['target'],'apply_authorized':False,
      'local_storage_snapshot':snapshot,'selected_source':source,'bounded_candidates':candidates,
      'watched_files':[{'path':str(p),'fingerprint':v} for p,v in watch.files.items()]}
    out=source_check.output_path(lab,private,output or base/'Results'/('Refs-Source-'+uuid.uuid4().hex))
    watch.check();out.mkdir(parents=True)
    for name,obj in [('Retail-Refs-Source-to-share.json',report),('PRIVATE-Refs-Source.json',private)]:
        with (out/name).open('x',encoding='utf-8') as f:json.dump(obj,f,indent=2)
    return out,report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--lab');p.add_argument('--output');p.add_argument('--metadata-only',action='store_true');args=p.parse_args();lab=args.lab
    if not lab:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root=tk.Tk();root.withdraw();lab=filedialog.askdirectory(title='Select existing Lab - saved refs + bounded source read');root.destroy()
        except Exception:
            print('Folder picker unavailable. Use: python refs_source_check.py --lab "EXISTING_LAB"');return 2
        if not lab:return 0
    print('Offline: saved refs metadata lookup, then at most 32 MiB of candidate archive spans. No network or patch.')
    try:
        out,report=run(lab,output=args.output,metadata_only=args.metadata_only)
        print('Completed. Results folder:',out)
        print('Share ONLY: Retail-Refs-Source-to-share.json')
        print('Keep PRIVATE-Refs-Source.json local.')
        print('Status:',report['status'],'; source bytes read:',report['archive_payload_bytes_read'])
        return 0
    except KeyboardInterrupt:print('Cancelled safely.')
    except (b.BindingError,a.AuditError) as error:print('Stopped safely. Code:',str(error))
    except Exception as error:print('Stopped safely. Error type:',type(error).__name__)
    print('Keep Lab unchanged. Do not restart scans or downloads.');return 1

if __name__=='__main__':sys.exit(main())
