"""Offline target Encoding lookup and bounded exact re-encoding, no CASC writes."""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
import sys
import uuid
import zlib
import patch_audit as a
import source_binding as b
import source_check
import refs_source_check as r
import staging_sample as sample

TARGET_SHA256='3818ed3b407ad07a407fb104a65c03ab39f8a89e86937ea4e261e26b99c71bd9'
class UnsupportedSpec(ValueError):pass

def exact(f,at,n):
    b.need(type(at)is int and at>=0 and type(n)is int and 0<=n<=16*1024**2,'encoding_read_bounds')
    f.seek(at);raw=f.read(n);b.need(len(raw)==n,'encoding_short_read');return raw

class EncodingLookup:
    """Read checked index tables + selected pages; caller pins whole-file CKey."""
    def __init__(self,f,size):
        self.f=f;self.read_bytes=0;self.pages=set()
        h=self.read(0,22)
        b.need(h[:5]==b'EN\x01\x10\x10' and h[17]==0,'encoding_header')
        self.cs=int.from_bytes(h[5:7],'big')*1024;self.es=int.from_bytes(h[7:9],'big')*1024
        self.cn=int.from_bytes(h[9:13],'big');self.en=int.from_bytes(h[13:17],'big');specsize=int.from_bytes(h[18:22],'big')
        b.need(1024<=self.cs<=65536 and 1024<=self.es<=65536 and 0<self.cn<=500000 and 0<self.en<=500000 and 0<specsize<=8*1024**2,'encoding_geometry_limit')
        ci=22+specsize;self.cp=ci+32*self.cn;ei=self.cp+self.cs*self.cn;self.ep=ei+32*self.en
        b.need(self.ep+self.es*self.en<=size,'encoding_geometry_bounds')
        spec=self.read(22,specsize)
        b.need(spec.endswith(b'\0'),'encoding_espec_terminator')
        try:self.specs=spec[:-1].decode('ascii').split('\0')
        except UnicodeError:raise b.BindingError('encoding_espec_ascii') from None
        b.need(len(self.specs)<=250000,'encoding_spec_count_limit')
        self.cindex=self.index(ci,self.cn);self.eindex=self.index(ei,self.en)
        self.unparsed_tail=size-(self.ep+self.es*self.en)
    def read(self,at,n):
        raw=exact(self.f,at,n);self.read_bytes+=len(raw);b.need(self.read_bytes<=64*1024**2,'encoding_lookup_read_budget');return raw
    def index(self,at,count):
        raw=self.read(at,32*count);rows=[(raw[i:i+16],raw[i+16:i+32]) for i in range(0,len(raw),32)]
        b.need(all(k!=bytes(16) for k,_ in rows) and all(rows[i-1][0]<rows[i][0] for i in range(1,len(rows))),'encoding_index_order')
        return rows
    def page(self,which,key):
        rows=self.cindex if which=='c' else self.eindex;keys=[x[0] for x in rows]
        i=bisect.bisect_right(keys,key)-1
        if i<0:return None
        width=self.cs if which=='c' else self.es;start=self.cp if which=='c' else self.ep
        raw=self.read(start+i*width,width)
        b.need(hashlib.md5(raw).digest()==rows[i][1],'encoding_selected_page_checksum')
        self.pages.add((which,i));return raw,rows[i][0],rows[i+1][0] if i+1<len(rows) else None
    def content(self,key):
        selected=self.page('c',key)
        if selected is None:return None
        raw,first,following=selected;pos=0;last=None;found=None
        while pos<len(raw):
            count=raw[pos]
            if count==0:
                b.need(not any(raw[pos:]),'encoding_ckey_padding');break
            stop=pos+22+16*count;b.need(stop<=len(raw),'encoding_ckey_record_bounds')
            ck=raw[pos+6:pos+22];size=int.from_bytes(raw[pos+1:pos+6],'big')
            b.need(ck!=bytes(16) and (last is not None or ck==first) and (last is None or last<ck) and (following is None or ck<following),'encoding_ckey_page_order')
            links=[raw[x:x+16] for x in range(pos+22,stop,16)]
            b.need(all(x!=bytes(16) for x in links) and len(set(links))==len(links),'encoding_ckey_links')
            if ck==key:found=(size,links)
            last=ck;pos=stop
        return found
    def encoded(self,key):
        selected=self.page('e',key)
        if selected is None:return None
        raw,first,following=selected;last=None;found=None;used=0
        for pos in range(0,len(raw)-24,25):
            ek=raw[pos:pos+16]
            if ek==bytes(16):
                b.need(raw[pos+16:pos+20] in (bytes(4),b'\xff'*4) and not any(raw[pos+20:]),'encoding_ekey_terminator');used=len(raw);break
            b.need((last is not None or ek==first) and (last is None or last<ek) and (following is None or ek<following),'encoding_ekey_page_order')
            if ek==key:
                index=int.from_bytes(raw[pos+16:pos+20],'big');size=int.from_bytes(raw[pos+20:pos+25],'big')
                b.need(index<len(self.specs) and 0<len(self.specs[index])<=2048 and size>0,'encoding_espec_reference')
                found={'ekey':key.hex(),'encoded_size':size,'espec_index':index,'espec':self.specs[index]}
            last=ek;used=pos+25
        b.need(not any(raw[used:]),'encoding_ekey_padding');return found

def leaf(data,spec):
    if spec=='n':return b'N'+data
    m=re.fullmatch(r'z(?::([0-9])|:\{([0-9]),(9|1[0-5]|mpq)\})?',spec)
    if not m:raise UnsupportedSpec('unsupported_leaf_recipe')
    level=int(m[1] or m[2] or 9);bits=m[3] or '15'
    if bits=='mpq':bits=max(9,min(15,(max(len(data),1)-1).bit_length()))
    obj=zlib.compressobj(level,zlib.DEFLATED,int(bits))
    return b'Z'+obj.compress(data)+obj.flush()

def split_specs(text):
    parts=[];depth=0;at=0
    for i,ch in enumerate(text):
        if ch=='{':depth+=1
        if ch=='}':depth-=1
        if depth<0 or depth>1:raise UnsupportedSpec('unsupported_nested_recipe')
        if ch==',' and depth==0:parts.append(text[at:i]);at=i+1
    if depth:raise UnsupportedSpec('unbalanced_recipe')
    return parts+[text[at:]]

def encode(data,spec):
    if not 0<len(data)<=8*1024**2:raise UnsupportedSpec('encoder_input_limit')
    if not spec.startswith('b:'):return b'BLTE'+bytes(4)+leaf(data,spec)
    text=spec[2:]
    if text.startswith('{') and text.endswith('}'):text=text[1:-1]
    parts=split_specs(text);chunks=[];sizes=[];at=0
    for i,part in enumerate(parts):
        m=re.fullmatch(r'(\*|[1-9][0-9]{0,8}[KM]?(?:\*(?:[1-9][0-9]{0,3})?)?)=(.+)',part)
        if not m:raise UnsupportedSpec('unsupported_block_recipe')
        size_spec,sub=m.groups();greedy=size_spec=='*' or size_spec.endswith('*')
        if greedy and i!=len(parts)-1:raise UnsupportedSpec('nonfinal_greedy_recipe')
        if size_spec=='*':width=len(data)-at;count=1 if width else 0
        else:
            fields=size_spec.split('*');unit=fields[0];factor=1024 if unit.endswith('K') else 1024**2 if unit.endswith('M') else 1
            width=int(unit[:-1] if factor>1 else unit)*factor
            count=(len(data)-at+width-1)//width if greedy else int(fields[1]) if len(fields)==2 else 1
        if not 0<width<=8*1024**2 or not 0<=count<=256 or len(chunks)+count>256:raise UnsupportedSpec('block_recipe_limit')
        for _ in range(count):
            n=min(width,len(data)-at) if greedy else width
            if n<=0 or at+n>len(data):raise UnsupportedSpec('block_recipe_input_bounds')
            chunks.append(leaf(data[at:at+n],sub));sizes.append(n);at+=n
    if at!=len(data) or not chunks:raise UnsupportedSpec('block_recipe_not_full_input')
    header=b'BLTE'+(12+24*len(chunks)).to_bytes(4,'big')+b'\x0f'+len(chunks).to_bytes(3,'big')
    for chunk,size in zip(chunks,sizes):header+=struct.pack('>II',len(chunk),size)+hashlib.md5(chunk).digest()
    return header+b''.join(chunks)

def assess(data,entry):
    report={**entry,'reencode_attempted':False,'exact_target_ekey_reproduced':False,'encoded_output_written':False}
    if entry['encoded_size']>8*1024**2:
        return {**report,'status':'expected_encoded_size_outside_encoder_limit'},None
    try:raw=encode(data,entry['espec'])
    except UnsupportedSpec as e:return {**report,'status':str(e)},None
    report.update(reencode_attempted=True,generated_encoded_size=len(raw),generated_sha256=a.sha256(raw))
    header=int.from_bytes(raw[4:8],'big');actual=a.md5(raw[:header] if header else raw)
    report['generated_ekey']=actual
    if len(raw)!=entry['encoded_size'] or actual!=entry['ekey']:
        return {**report,'status':'recipe_supported_but_exact_ekey_not_reproduced_not_corruption'},None
    decoded,proof=r.decode_source(raw,entry['ekey'],len(data))
    b.need(decoded==data,'encoded_roundtrip_mismatch')
    return {**report,'status':'exact_encoding_identity_and_roundtrip_verified','exact_target_ekey_reproduced':True,'roundtrip_ckey':a.md5(decoded),'chunk_integrity_verified':proof['chunk_integrity_verified']},raw

def lookup_file(path,watch,expected_ckey,expected_size,target_ckey):
    path=watch.file(path);before=watch.files[path]
    b.need(before[2]==expected_size and 0<expected_size<=512*1024**2,'encoding_pinned_file_size')
    digest=hashlib.md5();sha=hashlib.sha256();count=0
    with path.open('rb') as f:
        b.need(b.fp(os.fstat(f.fileno()))==before,'encoding_source_changed')
        while count<expected_size:
            data=f.read(min(1024**2,expected_size-count));b.need(bool(data),'encoding_hash_short_read')
            digest.update(data);sha.update(data);count+=len(data)
        b.need(not f.read(1),'encoding_hash_trailing_bytes')
        b.need(digest.hexdigest()==expected_ckey,'encoding_whole_file_ckey')
        table=EncodingLookup(f,expected_size);record=table.content(bytes.fromhex(target_ckey))
        b.need(record is not None,'target_ckey_not_in_encoding')
        size,links=record;b.need(0<len(links)<=16,'target_encoding_link_limit')
        results=[]
        for key in links:
            result=table.encoded(key);b.need(result is not None,'target_ekey_spec_missing');results.append(result)
        b.need(b.fp(os.fstat(f.fileno()))==before,'encoding_source_changed')
    watch.check()
    return size,results,{'encoding_ckey':expected_ckey,'encoding_size':expected_size,'encoding_sha256':sha.hexdigest(),
      'whole_decoded_encoding_ckey_verified':True,'selected_page_hashes_verified':True,'index_keys_order_verified':True,
      'selected_unique_pages':len(table.pages),'full_metadata_hash_bytes_read':count,'lookup_metadata_bytes_read':table.read_bytes,
      'encoding_tail_not_semantically_parsed_bytes':table.unparsed_tail,'all_page_semantics_reparsed':False}

def plan_rows(lab,prior,watch,entries):
    state=b.json_object(watch.read(Path(lab)/'objects'/'downloader-ui-session.json'))
    path=b.ref(Path(lab)/'objects',state['local_review']['plan_file'],'content-plan',watch)
    db=sqlite3.connect(':memory:',uri=True)
    try:
        db.execute('PRAGMA trusted_schema=OFF');b.attach(db,watch,path,'p')
        b.need(b.metadata(db,'p','target_binding')==prior['target'],'encoding_plan_target_changed')
        b.schema(db,'p','plan',('ekey','encoded_size','ckey','decoded_size','mapping_state','route_kind','archive_key','archive_offset','index_key'))
        for entry in entries:
            row=db.execute('SELECT encoded_size,ckey,decoded_size,mapping_state,route_kind,archive_key,archive_offset,index_key FROM p.plan WHERE ekey=?',(bytes.fromhex(entry['ekey']),)).fetchone()
            entry['present_in_saved_download_plan']=row is not None
            if row:
                b.need(row[:4]==(entry['encoded_size'],bytes.fromhex(sample.OPTION['target_ckey']),sample.OPTION['target_size'],'mapped'),'encoding_plan_mapping_conflict')
                entry['saved_plan_route']={'kind':row[4],'archive_key':row[5],'offset':row[6],'index_key':row[7],'current_http_availability_tested':False}
    finally:db.close()
    watch.check()

def run(lab,staging_report,*,output=None):
    base=Path(__file__).resolve().parent;_,prior=b.bind(lab,base/'pinned_metadata');watch=b.Watch()
    for item in prior['watched_files']:watch.file(item['path'],item['fingerprint'])
    watch.snapshot(prior['local_storage_snapshot']);report_path=b.safe(staging_report,True)
    b.need(report_path.name=='Retail-Staging-Sample-to-share.json','staging_report_filename')
    previous=b.json_object(watch.read(report_path))
    b.need(previous.get('format')=='retail-staging-sample-1' and previous.get('status')=='one_retail_target_reconstructed_and_ckey_verified' and previous.get('target')==prior['target'] and previous.get('option')==sample.OPTION and previous.get('output_readback_verified') is True,'staging_report_binding')
    data=watch.read(report_path.parent/'RECONSTRUCTED-TARGET-NOT-INSTALLABLE.bin')
    b.need(len(data)==sample.OPTION['target_size'] and a.md5(data)==sample.OPTION['target_ckey'] and a.sha256(data)==TARGET_SHA256,'staging_target_reverification')
    out=source_check.output_path(Path(lab),prior,output or base/'Results'/('Encoding-Target-'+uuid.uuid4().hex))
    b.need(report_path.parent!=out and report_path.parent not in out.parents and out not in report_path.parent.parents,'output_overlaps_prior_staging')
    build=a.config(watch.read(base/'pinned_metadata'/'build.config'),a.BUILD)
    pair=build.get('encoding',[]);sizes=build.get('encoding-size',[])
    b.need(len(pair)==len(sizes)==2,'encoding_build_binding')
    for key in pair:a.key(key)
    b.need(all(isinstance(x,str) and x.isascii() and x.isdigit() for x in sizes),'encoding_build_sizes')
    ds,es=map(int,sizes);path=Path(lab)/'objects'/(pair[0]+'-'+str(ds)+'.decoded')
    print('Hashing saved decoded Encoding metadata (bytes):',ds,'; no network or game payload reads.')
    decoded_size,entries,proof=lookup_file(path,watch,pair[0],ds,sample.OPTION['target_ckey'])
    b.need(decoded_size==len(data),'encoding_target_decoded_size')
    plan_rows(lab,prior,watch,entries);results=[];encoded=[]
    for entry in entries:
        result,raw=assess(data,entry);results.append(result)
        if raw is not None:encoded.append((result,raw))
    watch.check()
    report={'format':'retail-target-encoding-1','target':prior['target'],'target_ckey':sample.OPTION['target_ckey'],
      'target_decoded_size':len(data),'target_decoded_sha256':a.sha256(data),'staging_target_reverified':True,'encoding_proof':proof,
      'status':'target_encoding_reproduced_exactly_in_separate_staging' if encoded else 'target_encoding_mapping_verified_exact_reproduction_not_proven',
      'encoding_options':results,'zlib_compile_version':zlib.ZLIB_VERSION,'zlib_runtime_version':zlib.ZLIB_RUNTIME_VERSION,
      'game_payload_bytes_read':0,'network_requests':0,'lab_modified':False,'game_modified':False,
      'casc_written':False,'activation_performed':False,'installation_ready':False,'patch_order_policy_proven':False,
      'required_network_download_bytes':None,'consistency_model':'file-set/stat fingerprints, not OS snapshot',
      'scope':'one target Encoding relation and supported recipe attempt; no general compressor compatibility or installation claim'}
    out.mkdir(parents=True)
    for result,raw in encoded:
        dest=out/('EXACT-ENCODED-NOT-INSTALLABLE-'+result['ekey']+'.blte')
        with dest.open('xb') as f:f.write(raw)
        b.need(dest.read_bytes()==raw,'encoded_staging_readback')
        result['encoded_output_written']=True;result['encoded_output_readback_verified']=True
    watch.check()
    with (out/'Retail-Target-Encoding-to-share.json').open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
    return out,report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--lab');p.add_argument('--staging-report');p.add_argument('--output');args=p.parse_args();lab=args.lab;report=args.staging_report
    if not lab or not report:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root=tk.Tk();root.withdraw()
            if not lab:lab=filedialog.askdirectory(title='Select existing Lab root - read-only')
            if lab and not report:report=filedialog.askopenfilename(title='Select previous Retail-Staging-Sample-to-share.json (keep sibling .bin)',filetypes=[('Staging report','Retail-Staging-Sample-to-share.json')])
            root.destroy()
        except Exception:print('Picker unavailable. Use --lab "LAB" --staging-report "REPORT"');return 2
        if not lab or not report:return 0
    print('Offline: verify previous staging and saved Encoding metadata; no CASC writes.')
    try:
        out,result=run(lab,report,output=args.output);print('Completed. Results folder:',out)
        print('Share ONLY: Retail-Target-Encoding-to-share.json');print('Status:',result['status'])
        print('Do NOT install or execute any output. Keep Lab unchanged.');return 0
    except KeyboardInterrupt:print('Cancelled safely.')
    except (b.BindingError,a.AuditError) as e:print('Stopped safely. Code:',str(e))
    except Exception as e:print('Stopped safely. Error type:',type(e).__name__)
    print('Do not rerun scans, prepare metadata, download or delete Lab.');return 1

if __name__=='__main__':sys.exit(main())
