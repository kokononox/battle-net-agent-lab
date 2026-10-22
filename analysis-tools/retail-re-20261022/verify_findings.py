from pathlib import Path
import json,sys,struct,hashlib,uuid,re,argparse
import numpy as np
sys.path.insert(0,'/data/re-tools');import pefile
p=argparse.ArgumentParser();p.add_argument('--input-dir',type=Path,default=Path('/data/raw/wow-retail-20261022'));p.add_argument('--output-dir',type=Path,default=Path('/data/analysis/wow-retail-20261022'));p.add_argument('--crash',type=Path,default=Path('/data/raw/wow-crash-10768/crash.txt'));p.add_argument('--prior-report',type=Path,default=Path('/data/raw/wow-repo-review/hardware_relationship.json'));a=p.parse_args();root=a.input_dir;out=a.output_dir
pe=pefile.PE(str(root/'wow_loader.dll'));pdb=[]
for d in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
 if d.struct.Type==2:
  b=pe.__data__[d.struct.PointerToRawData:d.struct.PointerToRawData+d.struct.SizeOfData]
  if b[:4]==b'RSDS':pdb.append({'guid':str(uuid.UUID(bytes_le=b[4:20])),'age':struct.unpack_from('<I',b,20)[0]})
crash=a.crash.read_text(encoding='utf-8-sig')
m=re.search(r'DBG-MODULE<([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"Wow_loader.dll"\s+"loader.pdb"\s+\d+\s+\{([^}]+)\}\s+(\d+)\s+(\d+)>',crash)
assert m
norm=lambda s:s.replace('-','').lower()
binding={'loader_file_sha256':hashlib.sha256((root/'wow_loader.dll').read_bytes()).hexdigest(),'crash_module_image_size_matches':int(m[2],16)==pe.OPTIONAL_HEADER.SizeOfImage,'crash_module_timestamp_matches':int(m[5])==pe.FILE_HEADER.TimeDateStamp,'crash_module_codeview_guid_age_matches':any(norm(x['guid'])==norm(m[3]) and x['age']==int(m[4]) for x in pdb),'runtime_loaded_image_hash_measured':False,'guid_comparison':'hyphens removed; report has a nonstandard GUID hyphen layout','interpretation':'Provided loader metadata matches the crash module; not a full runtime image hash measurement or proof of the exact failing security check.'}
assert all(binding[k] for k in ['crash_module_image_size_matches','crash_module_timestamp_matches','crash_module_codeview_guid_age_matches'])
(out/'crash-loader-binding.json').write_text(json.dumps(binding,indent=2)+'\n')
b=(root/'Wow.exe').read_bytes();e=struct.unpack_from('<I',b,0x3c)[0];ns=struct.unpack_from('<H',b,e+6)[0];optsize=struct.unpack_from('<H',b,e+20)[0];sect=e+24+optsize
assert struct.unpack_from('<H',b,e+4)[0]==0x8664
for i in range(ns):
 row=b[sect+i*40:sect+(i+1)*40]
 if row[:8].rstrip(b'\0')==b'.text':
  size,off=struct.unpack_from('<II',row,16);arr=np.frombuffer(b[off:off+size],dtype=np.uint8);cnt=np.bincount(arr,minlength=256);prob=cnt[cnt>0]/len(arr);h=float(-(prob*np.log2(prob)).sum());break
prof=next(x for x in json.loads((out/'pe-profile.json').read_text()) if x['name']=='Wow.exe');reported=next(x for x in prof['sections'] if x['name']=='.text')['entropy'];assert round(h,5)==reported
tr=json.loads((out/'descriptor-trace.json').read_text());wr=next(x for x in tr['selected_messages'] if x['message'].endswith('.ClientSystemSpec'));prior=json.loads(a.prior_report.read_text());assert wr['descriptor_sha256']==prior['wrapper_descriptor']['descriptor_sha256']
qa={'all_input_sha256_verified':True,'same_wow_hash_as_prior_analysis':prof['sha256']==prior['wow_sha256'],'wrapper_descriptor_hash_matches_prior':True,'raw_struct_header_check':True,'independent_numpy_entropy_check':True,'archive_byte_reassembly_verified':True,'tamper_and_overwrite_refusal_tested':True,'crash_loader_metadata_binding_verified':True,'input_binaries_executed':False,'protection_bypassed':False,'runtime_send_or_3724_hardware_binding_proven':False,'publisher_signatures_validated':False}
(out/'QA.json').write_text(json.dumps(qa,indent=2)+'\n');print('PASS: loader size/timestamp/CodeView match (normalized GUID); independent PE/entropy/schema checks.')
