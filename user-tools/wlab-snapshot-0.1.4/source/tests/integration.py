"""Offline synthetic minidump integration tests. No process is inspected/executed.
Usage: python tests/integration.py EXTRACTOR PINNED_WOW WORKDIR
Mock bytes come from the pinned disk input; fixtures are NOT runtime observations.
"""
import hashlib,json,struct,subprocess,sys
from pathlib import Path
exe,disk,work=[Path(v).resolve() for v in sys.argv[1:4]];work.mkdir(parents=True,exist_ok=False)
b=disk.read_bytes();assert hashlib.sha256(b).hexdigest()=='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
u32=lambda o:struct.unpack_from('<I',b,o)[0]
nt=u32(0x3c);n=struct.unpack_from('<H',b,nt+6)[0];sz=struct.unpack_from('<H',b,nt+20)[0];stamp=u32(nt+8);image=u32(nt+24+56)
sections=[]
for i in range(n):
 s=nt+24+sz+i*40;vs,va,rs,ro=struct.unpack_from('<IIII',b,s+8);sections.append((va,rs,ro))
def read(r,n):
 if r==0:return b[:n]
 for va,rs,ro in sections:
  d=r-va
  if 0<=d and d+n<=rs:return b[ro+d:ro+d+n]
 raise AssertionError('non-file-backed mock range')
base=0x150000000
pages=[0,0x1b11000,0x1b14000,0x3306000]
def fixture(case):
 ps=[p for p in pages if case!='missing' or p!=0x1b11000]
 out=bytearray(1024+4096*len(ps));struct.pack_into('<4sIIIIIQ',out,0,b'MDMP',0xa793,3,32,0,0,0)
 struct.pack_into('<III',out,32,4,112,80);struct.pack_into('<III',out,44,7,2,200);struct.pack_into('<H',out,200,9)
 struct.pack_into('<III',out,56,9,16+16*len(ps),300)
 struct.pack_into('<I',out,80,1);struct.pack_into('<QIIII',out,84,base,image,0,stamp+(case=='wrong-module-stamp'),220)
 name='C:\\Mock\\Wow.exe'.encode('utf-16le');struct.pack_into('<I',out,220,len(name));out[224:224+len(name)]=name
 struct.pack_into('<QQ',out,300,len(ps),1024)
 for i,r in enumerate(ps):
  struct.pack_into('<QQ',out,316+16*i,base+r,4096)
  data=bytearray(read(r,4096))
  if case=='changed' and r==0x1b11000:data[0x190]=0xc3
  if case=='wrong-memory-header' and r==0:struct.pack_into('<I',data,nt+8,stamp^1)
  out[1024+4096*i:1024+4096*(i+1)]=data
 return out
results=[]
for case in ['unchanged','changed','missing','wrong-module-stamp','wrong-memory-header']:
 d=work/(case+'.dmp');d.write_bytes(fixture(case));o=work/case
 p=subprocess.run([str(exe),'--extract',str(d),str(disk),str(o)],capture_output=True,text=True)
 j=json.loads((o/'analysis.json').read_text())
 if case.startswith('wrong'):
  assert p.returncode!=0 and j['status']=='extraction_failed',(case,j)
 else:
  assert p.returncode==0,(case,p.stderr)
  rows={r['role_candidate']:r for r in j['targets']}
  assert j['module_base']=='0x150000000'
  if case=='unchanged':assert all(r['raw_bytes_equal_disk'] for r in rows.values())
  if case=='changed':assert rows['creator_candidate']['raw_bytes_equal_disk'] is False and rows['merge_candidate']['raw_bytes_equal_disk'] is True
  if case=='missing':assert j['target_missing_count']==1 and rows['creator_candidate']['status']=='missing'
 results.append({'case':case,'passed':True,'synthetic_only':True})
(work/'integration-results.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results))
