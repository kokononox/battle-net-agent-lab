"""Read-only export of one pinned Retail fixture. No database or private JSON export."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import uuid
import zipfile
import patch_audit as a
import source_binding as b
import source_check
import staging_sample as s
import encoding_target as e
import refs_source_check as r
import portable_run as portable

LIMIT=512*1024**2

def saved_inputs(lab,private_file,staging_file):
    base=Path(__file__).resolve().parent;_,prior=b.bind(lab,base/'pinned_metadata');watch=b.Watch()
    for item in prior['watched_files']:watch.file(item['path'],item['fingerprint'])
    watch.snapshot(prior['local_storage_snapshot'])
    private=b.json_object(watch.read(private_file,2*1024**2));selected=s.selection(private,prior)
    rows=private.get('watched_files');b.need(isinstance(rows,list) and 0<len(rows)<=20000,'private_watch_shape')
    for row in rows:
        b.need(isinstance(row,dict) and set(row)=={'path','fingerprint'},'private_watch_shape')
        watch.file(row['path'],row['fingerprint'])
    options,_,_=b.load_metadata(base/'pinned_metadata',watch)
    b.need(sum(o.__dict__==s.OPTION for o in options)==1,'export_pinned_pa_relation')
    report_path=b.safe(staging_file,True)
    b.need(report_path.name=='Retail-Staging-Sample-to-share.json','export_staging_filename')
    report=b.json_object(watch.read(report_path))
    b.need(report.get('format')=='retail-staging-sample-1' and report.get('status')=='one_retail_target_reconstructed_and_ckey_verified' and report.get('target')==prior['target'] and report.get('option')==s.OPTION and report.get('output_readback_verified') is True,'export_staging_report_binding')
    data=watch.read(report_path.parent/'RECONSTRUCTED-TARGET-NOT-INSTALLABLE.bin')
    b.need(len(data)==s.OPTION['target_size'] and a.md5(data)==s.OPTION['target_ckey'] and a.sha256(data)==e.TARGET_SHA256,'export_staging_target')
    source=watch.file(Path(prior['local_storage_snapshot']['directory'])/selected['archive_name'],selected['source_fingerprint']);before=watch.files[source]
    with source.open('rb') as f:
        b.need(b.fp(os.fstat(f.fileno()))==before,'export_source_changed')
        f.seek(selected['source_offset']);raw=f.read(selected['source_encoded_size'])
        b.need(len(raw)==selected['source_encoded_size'] and b.fp(os.fstat(f.fileno()))==before,'export_source_short_or_changed')
    old,proof=r.decode_source(raw,s.OPTION['source_ekey'],s.OPTION['source_size'])
    b.need(all(proof.get(k)==v for k,v in s.OBSERVED.items()),'export_source_proof')
    try:patch=base64.b64decode(watch.read(base/'sample.zbsdiff.base64',4096),validate=True)
    except ValueError:raise b.BindingError('export_patch_base64') from None
    rebuilt,_=s.rebuild(old,patch);b.need(rebuilt==data,'export_reconstruction_mismatch')
    build=a.config(watch.read(base/'pinned_metadata'/'build.config'),a.BUILD)
    b.need(len(build.get('encoding',[]))==len(build.get('encoding-size',[]))==2,'export_encoding_binding')
    ck,ek=build['encoding'];a.key(ck);a.key(ek)
    b.need(all(x.isascii() and x.isdigit() for x in build['encoding-size']),'export_encoding_size_shape')
    ds,es=map(int,build['encoding-size'])
    b.need(0<ds<=LIMIT and 0<es<=LIMIT,'export_encoding_size_limit')
    encoding=watch.file(Path(lab)/'objects'/(ck+'-'+str(ds)+'.decoded'))
    b.need(watch.files[encoding][2]==ds,'export_saved_encoding_size')
    evidence={'format':'portable-retail-public-evidence-1','target':prior['target'],'option':s.OPTION,
      'source_reverified':proof,'staging_target_sha256':a.sha256(data),'target_ckey_verified':True,
      'target_exact_bytes_reconstructed_again':True,'encoding_ckey':ck,'encoding_ekey':ek,
      'encoding_decoded_size':ds,'encoding_encoded_size':es,
      'full_source_archive_exported':False,'source_archive_span_bytes_exported':len(raw),
      'databases_exported':False,'private_reports_exported':False,'local_paths_exported':False,
      'network_requests':0,'game_payload_bytes_read':len(raw),'lab_modified':False,'game_modified':False,
      'installation_ready':False,'proof_scope':'exported fixture only; not a portable full Lab or activation proof',
      'consistency_model':'saved file-set/stat fingerprints, not OS snapshot'}
    payloads={'source.blte':raw,'target.decoded':data,'sample.zbsdiff':patch,
      'PUBLIC-EVIDENCE.json':(json.dumps(evidence,indent=2)+'\n').encode(),
      'README-fa.md':README.encode('utf-8')}
    watch.check();return prior,watch,encoding,ck,ds,payloads,report_path.parent

README='''# بستهٔ قابل‌حمل آزمایش یک نمونهٔ Retail

این ZIP شامل متادیتای رسمی Encoding، یک بازهٔ کوچک منبع، پچ و هدف decoded است؛ نه کل Lab، نصب بازی یا ابزار فعال‌سازی. هیچ فایل PRIVATE یا بانک SQLite داخل آن نیست. نام‌ها ثابت‌اند و مسیر محلی در manifest/گزارش صادر نشده است.

برای بازتولید فقط‌خواندنی، پس از بازبینی کد اجرا کنید:

python -B portable_run.py

گزینهٔ -B جلوی ساخت __pycache__ را می‌گیرد. برنامه هیچ درخواست شبکه یا خروجی فایلی ندارد و فقط نتیجهٔ JSON چاپ می‌کند. کد صادرشده، جایگزین بررسی صحت فایل‌ها یا اعتماد به منشأ آن نیست؛ manifest امضای دیجیتال ناشر محسوب نمی‌شود.

صحت Encoding از MD5 کامل فایل decoded و BuildConfig ثابت بررسی می‌شود؛ سپس رابطهٔ CKey/EKey/ESpec از صفحات منتخب بررسی می‌شود. تنها دستورهای N/Z و بلوک‌بندی محدود پشتیبانی می‌شوند. خروجی تولیدی فقط با تطبیق اندازه/EKey کامل و roundtrip تأیید می‌شود؛ ناموفق‌بودن بازفشرده‌سازی به معنی خرابی فایل نیست و ممکن است به نسخه/جزئیات کمپرسور مربوط باشد.

هیچ خروجی را به بازی کپی نکنید. این نمونهٔ کوچک، قفل‌های Windows، سازگاری کل Lab، closure نصب، writer یا فعال‌سازی CASC را ثابت نمی‌کند. نامزدها و شواهد کاملِ ذخیره‌شده در Lab اصلی صادر نشده‌اند.
'''

def write_bundle(out,watch,encoding,expected_ckey,expected_size,payloads,code_root):
    """New external directory only; streaming ZIP, fixed whitelist, no arbitrary tree."""
    out=Path(out);b.need(not out.exists() and not out.is_symlink(),'export_new_output_required')
    # Input overlap is validated by run; still reject links in destination ancestors.
    ancestor=out.parent
    while not ancestor.exists():ancestor=ancestor.parent
    b.safe(ancestor)
    b.need(shutil.disk_usage(ancestor).free>=expected_size+256*1024**2,'export_free_space_need_size_plus_256MiB')
    memory=dict(payloads)
    b.need(set(memory)==set(portable.PAYLOAD),'export_payload_whitelist')
    for name in portable.CODE+portable.METADATA:memory[name]=watch.read(Path(code_root)/name)
    b.need(set(memory)|{'encoding.decoded'}==portable.FIXED,'export_fixed_whitelist')
    b.need(sum(map(len,memory.values()))+expected_size<=LIMIT,'export_total_limit')
    encoding=watch.file(encoding);before=watch.files[encoding]
    b.need(type(expected_size)is int and before[2]==expected_size and 0<expected_size<=LIMIT,'export_encoding_size')
    out.mkdir(parents=True);partial=out/'Portable-Retail-Sample.zip.partial';final=out/'Portable-Retail-Sample.zip';entries={}
    try:
        watch.check()
        with zipfile.ZipFile(partial,'x',zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as z:
            for name,data in memory.items():
                z.writestr('Portable-Retail-Sample/'+name,data)
                entries[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            md5=hashlib.md5();sha=hashlib.sha256();total=0
            with encoding.open('rb') as f,z.open('Portable-Retail-Sample/encoding.decoded','w',force_zip64=True) as sink:
                b.need(b.fp(os.fstat(f.fileno()))==before,'export_encoding_changed')
                while total<expected_size:
                    data=f.read(min(1024**2,expected_size-total));b.need(bool(data),'export_encoding_short_read')
                    md5.update(data);sha.update(data);sink.write(data);total+=len(data)
                b.need(not f.read(1) and b.fp(os.fstat(f.fileno()))==before,'export_encoding_changed')
            b.need(md5.hexdigest()==expected_ckey,'export_encoding_ckey_mismatch')
            watch.check();entries['encoding.decoded']={'bytes':total,'sha256':sha.hexdigest()}
            manifest={'format':'portable-retail-fixture-1','files':entries,
              'encoding_whole_decoded_ckey_verified_at_export':True,'path_policy':'fixed whitelist, no path-derived names',
              'private_or_sqlite_files_exported':False,'network_requests':0,'installation_ready':False}
            z.writestr('Portable-Retail-Sample/PORTABLE-MANIFEST.json',json.dumps(manifest,indent=2)+'\n')
        # Full CRC readback checks the ZIP we just wrote, without rereading game archives.
        with zipfile.ZipFile(partial) as z:
            b.need(z.testzip() is None,'export_zip_crc_failed')
            b.need(set(z.namelist())=={'Portable-Retail-Sample/'+n for n in portable.FIXED|{'PORTABLE-MANIFEST.json'}},'export_zip_entry_whitelist')
        sha=hashlib.sha256()
        with partial.open('rb') as f:
            for block in iter(lambda:f.read(1024**2),b''):sha.update(block)
        watch.check();partial.rename(final)
        summary={'format':'portable-export-summary-1','status':'verified_portable_fixture_exported',
          'archive_filename':final.name,'archive_bytes':final.stat().st_size,'archive_sha256':sha.hexdigest(),
          'encoding_bytes_read':total,'game_payload_bytes_read':158,'zip_crc_readback_verified':True,
          'input_stat_fingerprints_unchanged':True,'databases_exported':False,'private_reports_exported':False,
          'local_paths_exported':False,'network_requests':0,'lab_modified':False,'game_modified':False,'installation_ready':False}
        with (out/'Portable-Export-to-share.json').open('x',encoding='utf-8') as f:json.dump(summary,f,indent=2)
        return final,summary
    except BaseException:
        if partial.exists():partial.unlink()
        raise

def run(lab,private_file,staging_file,*,output=None):
    prior,watch,encoding,ck,ds,payloads,stage=saved_inputs(lab,private_file,staging_file)
    base=Path(__file__).resolve().parent
    out=source_check.output_path(Path(lab),prior,output or base/'Results'/('Portable-Export-'+uuid.uuid4().hex))
    for protected in (stage,Path(private_file).absolute().parent):
        b.need(out!=protected and protected not in out.parents and out not in protected.parents,'export_overlaps_previous_results')
    print('Exporting verified saved Encoding metadata (bytes):',ds)
    print('No downloads. ZIP CRC readback follows; this can take a few minutes.')
    return write_bundle(out,watch,encoding,ck,ds,payloads,base)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--lab');p.add_argument('--private');p.add_argument('--staging-report');p.add_argument('--output');args=p.parse_args()
    lab=args.lab;private=args.private;stage=args.staging_report
    if not lab or not private or not stage:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root=tk.Tk();root.withdraw()
            if not lab:lab=filedialog.askdirectory(title='1. Select existing Lab root (read-only)')
            if lab and not private:private=filedialog.askopenfilename(title='2. Select LOCAL PRIVATE-Refs-Source.json (will NOT be exported)',filetypes=[('Private refs report','PRIVATE-Refs-Source.json')])
            if lab and private and not stage:stage=filedialog.askopenfilename(title='3. Select Retail-Staging-Sample-to-share.json (keep sibling .bin)',filetypes=[('Staging report','Retail-Staging-Sample-to-share.json')])
            root.destroy()
        except Exception:print('Picker unavailable. Use --lab "LAB" --private "PRIVATE" --staging-report "REPORT"');return 2
        if not lab or not private or not stage:return 0
    print('Offline, read-only export. No whole game archives or databases will be copied.')
    try:
        archive,summary=run(lab,private,stage,output=args.output)
        print('Completed. Upload this ZIP:',archive)
        print('Also share: Portable-Export-to-share.json')
        print('Do NOT upload PRIVATE files, SQLite databases or the entire Lab.');return 0
    except KeyboardInterrupt:print('Cancelled safely.')
    except (b.BindingError,a.AuditError) as ex:print('Stopped safely. Code:',str(ex))
    except Exception as ex:print('Stopped safely. Error type:',type(ex).__name__)
    print('Keep Lab unchanged. No new scans, preparation or downloads.');return 1

if __name__=='__main__':sys.exit(main())
