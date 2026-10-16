"""Read-only portable fixture reproduction. Run with python -B portable_run.py."""
import hashlib
import json
from pathlib import Path
import re
import sys
import patch_audit as a
import source_binding as b
import refs_source_check as r
import staging_sample as s
import encoding_target as e

CODE=('portable_run.py','encoding_target.py','staging_sample.py','refs_source_check.py','source_binding.py','source_check.py','patch_audit.py','cdn_catalog.py')
PAYLOAD=('source.blte','target.decoded','sample.zbsdiff','PUBLIC-EVIDENCE.json','README-fa.md')
METADATA=('pinned_metadata/build.config',)+tuple('pinned_metadata/manifest.pa.base64.part'+str(i) for i in range(3))
FIXED=set(CODE+PAYLOAD+METADATA+('encoding.decoded',))

def check_manifest(root,watch):
    manifest=b.json_object(watch.read(root/'PORTABLE-MANIFEST.json',65536))
    b.need(manifest.get('format')=='portable-retail-fixture-1','portable_manifest_format')
    entries=manifest.get('files');b.need(isinstance(entries,dict) and set(entries)==FIXED,'portable_file_whitelist')
    total=0
    for name,info in entries.items():
        b.need(isinstance(info,dict) and set(info)=={'bytes','sha256'} and type(info['bytes'])is int and 0<=info['bytes']<=512*1024**2 and isinstance(info['sha256'],str) and re.fullmatch('[0-9a-f]{64}',info['sha256']),'portable_file_record')
        total+=info['bytes'];b.need(total<=512*1024**2,'portable_total_limit')
        path=watch.file(root/name);before=watch.files[path];b.need(before[2]==info['bytes'],'portable_size_mismatch')
        sha=hashlib.sha256()
        with path.open('rb') as f:
            b.need(b.fp(__import__('os').fstat(f.fileno()))==before,'portable_source_changed')
            remaining=info['bytes']
            while remaining:
                data=f.read(min(1024**2,remaining));b.need(bool(data),'portable_short_read');sha.update(data);remaining-=len(data)
            b.need(not f.read(1),'portable_extra_bytes')
        b.need(sha.hexdigest()==info['sha256'],'portable_sha256_mismatch')
    watch.check();return manifest

def run(root):
    root=b.safe(root);watch=b.Watch();check_manifest(root,watch)
    options,_,target=b.load_metadata(root/'pinned_metadata',watch)
    b.need(sum(o.__dict__==s.OPTION for o in options)==1,'portable_pa_relation')
    source=watch.read(root/'source.blte');old,proof=r.decode_source(source,s.OPTION['source_ekey'],s.OPTION['source_size'])
    b.need(all(proof.get(k)==v for k,v in s.OBSERVED.items()),'portable_source_proof')
    patch=watch.read(root/'sample.zbsdiff');rebuilt,details=s.rebuild(old,patch)
    expected=watch.read(root/'target.decoded')
    b.need(rebuilt==expected and a.sha256(expected)==e.TARGET_SHA256,'portable_target_mismatch')
    build=a.config(watch.read(root/'pinned_metadata'/'build.config'),a.BUILD)
    ck,ek=build['encoding'];ds,es=map(int,build['encoding-size'])
    size,entries,ep=e.lookup_file(root/'encoding.decoded',watch,ck,ds,s.OPTION['target_ckey'])
    b.need(size==len(expected),'portable_encoding_target_size')
    attempts=[e.assess(expected,row)[0] for row in entries];watch.check()
    return {'format':'portable-retail-reproduction-1','status':'source_patch_target_and_encoding_verified',
      'source_full_ekey_verified':True,'patch_hash_verified':True,'target_ckey':a.md5(expected),'target_sha256':a.sha256(expected),
      'encoding_proof':ep,'encoding_options':attempts,'network_requests':0,'files_written':0,
      'user_lab_available':False,'whole_user_lab_consistency_verified_here':False,'installation_ready':False,
      'zlib_runtime_version':e.zlib.ZLIB_RUNTIME_VERSION}

if __name__=='__main__':
    try:print(json.dumps(run(Path(__file__).resolve().parent),indent=2))
    except (b.BindingError,a.AuditError) as ex:print('Stopped safely. Code:',str(ex));sys.exit(1)
    except Exception as ex:print('Stopped safely. Error type:',type(ex).__name__);sys.exit(1)
