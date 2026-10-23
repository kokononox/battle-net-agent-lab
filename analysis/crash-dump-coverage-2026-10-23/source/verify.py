"""Independent stdlib stream/range/module check; does not import producer parsers."""
from pathlib import Path
import struct,hashlib,json,zipfile,os,copy
D=Path(__file__).resolve().parents[1];zpath=Path(os.environ.get('ARCHIVE','Errors.zip'))
report=json.loads((D/'reports/inspection.json').read_text());comparison=json.loads((D/'reports/comparison.json').read_text())
def h(b):return hashlib.sha256(b).hexdigest()
checks=[]
with zipfile.ZipFile(zpath) as z:
 assert h(zpath.read_bytes())==report['archive_sha256']
 for row in report['dumps']:
  b=z.read(row['name']);assert len(b)==row['size_bytes'] and h(b)==row['sha256']
  def read(off,n):
   assert 0<=off<=len(b) and 0<=n<=len(b)-off;return b[off:off+n]
  def unpack(fmt,o):return struct.unpack(fmt,read(o,struct.calcsize(fmt)))
  count,dr=unpack('<II',8);streams=[unpack('<III',dr+12*i) for i in range(count)];assert all(t!=9 for t,n,o in streams)
  mr=next(o for t,n,o in streams if t==5);n=unpack('<I',mr)[0];ranges=[unpack('<QII',mr+4+16*i) for i in range(n)]
  assert len(ranges)==row['memory_range_count'] and sum(n for a,n,o in ranges)==row['stored_memory_bytes']
  for a,n,o in ranges:read(o,n)
  modr=next(o for t,n,o in streams if t==4);mn=unpack('<I',modr)[0];mods={}
  for i in range(mn):
   q=modr+4+108*i;base,size,checksum,stamp,sr=unpack('<QIIII',q);slen=unpack('<I',sr)[0];name=read(sr+4,slen).decode('utf-16le').replace('\\','/').split('/')[-1];mods[name.lower()]=(base,size,checksum,stamp)
  base=mods['wow.exe'][0]
  for t in row['targets']:
   a=base+int(t['rva'],16);end=a+t['length'];intersections=[(max(a,x),min(end,x+n)) for x,n,o in ranges if max(a,x)<min(end,x+n)]
   assert not intersections and not t['fully_present'] and t['available_prefix_bytes']==0 and t['sha256'] is None
  assert not any(a<=base<a+n for a,n,o in ranges)
  cr=next(x for x in comparison['dumps'] if x['name']==row['name'])
  for mod in cr['modules']:
   base,size,checksum,stamp=mods[mod['name'].lower()];meta=comparison['disk_identity'][mod['name'].lower()]
   assert size==meta['size_image'] and stamp==meta['timestamp'] and checksum==meta['checksum']
   # Separate executable interval traversal using the producer's disk section inventory.
   total=0
   for a,n,o in ranges:
    for sec in meta['executable_sections']:
     lo=max(a,base+sec['rva']);hi=min(a+n,base+sec['rva']+sec['length'])
     if lo<hi:total+=hi-lo
   assert total==mod['captured_executable_bytes_sum']
   assert all(mod['identity_checks'].values())
  checks.append({'dump':row['name'],'hash_directory_ranges_and_absence_rechecked':True})
# Guard acceptance logic: intentionally inconsistent claims must fail.
def acceptance(r,c):
 assert len(r['dumps'])==len(c['dumps'])==2
 for d in r['dumps']:
  assert all(not x['fully_present'] and x['available_prefix_bytes']==0 and x['sha256'] is None for x in d['targets'])
 for d in c['dumps']:
  for m in d['modules']:assert all(m['identity_checks'].values())
 assert c['dumps'][0]['modules'][0]['captured_executable_bytes_sum']==0
 assert c['dumps'][0]['modules'][1]['captured_executable_bytes_sum']==256
 assert c['dumps'][0]['modules'][1]['different_bytes_sum']==0
 return True
acceptance(report,comparison);tests=[]
for name in ['false_target_presence','false_prefix','invented_target_hash','false_identity','invented_Wow_code','claim_changed_loader_bytes']:
 r,c=copy.deepcopy((report,comparison))
 if name=='false_target_presence':r['dumps'][0]['targets'][0]['fully_present']=True
 elif name=='false_prefix':r['dumps'][0]['targets'][0]['available_prefix_bytes']=1
 elif name=='invented_target_hash':r['dumps'][0]['targets'][0]['sha256']='0'*64
 elif name=='false_identity':c['dumps'][0]['modules'][0]['identity_checks']['codeview_equal']=False
 elif name=='invented_Wow_code':c['dumps'][0]['modules'][0]['captured_executable_bytes_sum']=1
 else:c['dumps'][0]['modules'][1]['different_bytes_sum']=1
 try:acceptance(r,c)
 except AssertionError:tests.append({'case':name,'rejected':True})
 else:raise AssertionError(name)
result={'independent_checks':checks,'negative_claim_tests':tests,'limits':'Independent check repeats directories/ranges/basic module fields and executable intersections; CodeView and per-byte comparison remain producer checks. Negative tests check report gates, not exhaustive minidump-parser robustness. No reason for missing target pages is inferred.'}
(D/'reports/verification.json').write_text(json.dumps(result,indent=2)+'\n');print('Verified two real dump inputs; six inconsistent report claims rejected.')
