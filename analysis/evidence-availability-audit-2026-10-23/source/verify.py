"""Separate verifier of frozen inventory; unzip supplies a second ZIP integrity check."""
from pathlib import Path
from zipfile import ZipFile
import json,hashlib,subprocess,sys,copy,collections
D=Path(__file__).resolve().parents[1];m=json.loads(Path(sys.argv[1]).read_text());r=json.loads((D/'reports/inventory.json').read_text())
spec={s['label']:s for s in m['inputs']};expected={};crc_checks=0
for label,s in spec.items():
 p=Path(s['path']);blob=p.read_bytes();v={'sha256':hashlib.sha256(blob).hexdigest(),'size_bytes':len(blob),'category':s['category']}
 if p.suffix.lower()=='.zip':
  out=subprocess.run(['unzip','-tqq',str(p)],capture_output=True);assert out.returncode==0,(label,'unzip integrity failure');crc_checks+=1
  with ZipFile(p) as z:
   v['members']=[{'name':i.filename,'size_bytes':i.file_size,'sha256':hashlib.sha256(z.read(i)).hexdigest()} for i in z.infolist() if not i.is_dir()]
 expected[label]=v

def check(r):
 rows=r['archives']+r['conversation_exports']+r['standalone_files'];assert len(rows)==len(spec) and len({a['label'] for a in rows})==len(spec)
 for a in rows:
  e=expected[a['label']]
  for k in ['size_bytes','sha256','category']:assert a[k]==e[k]
  if 'members' in e:
   assert [{k:x[k] for k in ['name','size_bytes','sha256']} for x in a['members']]==e['members']
   assert a['members_fully_read']==len(e['members'])
 assert not r['errors_or_unread'] and not any(r['claims'].values())
 counts=r['counts'];assert counts['archives']==len(r['archives']) and counts['archive_members_fully_read']==sum(len(a['members']) for a in r['archives'])
 assert counts['archive_uncompressed_bytes_read']==sum(x['size_bytes'] for a in r['archives'] for x in a['members'])
 assert counts['conversation_exports']==len(r['conversation_exports']) and counts['standalone_files']==len(r['standalone_files'])
 for a in r['archives']:
  for x in a['members']:
   with ZipFile(spec[a['label']]['path']) as z:
    with z.open(x['name']) as f:b=f.read(64)
   if x['leading_signature']=='pe_candidate':assert b.startswith(b'MZ')
   assert not b.startswith(b'MDMP') and not b.startswith(b'Microsoft C/C++ MSF') and not b.startswith(b'BSJB')
check(r)
# Exact game disk binary hashes; tool distributions are not prepared game images.
pins={'Wow.exe':'1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a','wow_loader.dll':'c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c','libxell.dll':'5ce63652eee5720203e0e41cc97eb45ee541c499c8a51d4bdb1e8fe4eaef4890'}
pe_count=0
for a in r['archives']:
 for x in a['members']:
  if x['leading_signature']=='pe_candidate':
   pe_count+=1
   if a['category']=='original_disk_binaries_not_prepared_runtime_image':assert x['sha256']==pins[Path(x['name']).name]
   else:assert a['category']=='tool_distribution_not_runtime_game_image' and Path(x['name']).name.startswith('WLab-')
  assert x['suffix'] not in ['.dmp','.etl','.pdb','.pcap','.pcapng','.bin']
# Confirm current source marks the test fixtures synthetic; no source is executed.
proof=next(s for s in m['inputs'] if s['path'].endswith('/source/tests/integration.py'))
ptext=Path(proof['path']).read_text();assert 'synthetic minidump' in ptext and 'NOT runtime observations' in ptext
control=next(a for a in r['archives'] if any(x['name']=='control-direct.decoded.txt' for x in a['members']))
with ZipFile(spec[control['label']]['path']) as z:
 for n in ['control-direct.decoded.txt','control-clone.decoded.txt']:
  text=z.read(n).decode('utf-8-sig');assert 'WLab-Control-0.1.0.exe' in text and 'Dump 1 complete' in text
 assert not any(i.filename.lower().endswith('.dmp') for i in z.infolist())
rej=[]
for name,mut in [('member removed',lambda q:q['archives'][0]['members'].pop()),('member hash changed',lambda q:q['archives'][0]['members'][0].__setitem__('sha256','0'*64)),('archive count inflated',lambda q:q['counts'].__setitem__('archives',999)),('fixture reclassified runtime',lambda q:next(x for x in q['standalone_files'] if x['category']=='synthetic_fixture').__setitem__('category','runtime_game_dump')),('symbols claim',lambda q:q['claims'].__setitem__('matched_game_symbols_found',True)),('unread gap hidden',lambda q:q['errors_or_unread'].append({'reason':'unreviewed'}))]:
 q=copy.deepcopy(r);mut(q)
 try:check(q)
 except AssertionError:rej.append(name)
 else:raise AssertionError(name)
out={'status':'PASS','scope':'Inventory size/hash/member-list recomputation with Python ZipFile plus separate unzip CRC test; not independent semantic proof of all text or runtime origins.','input_entries_verified':len(spec),'archives_crc_verified_with_unzip':crc_checks,'members_verified':r['counts']['archive_members_fully_read'],'pe_members_verified_as_original_disk_or_lab_tools':pe_count,'synthetic_fixture_source_checked_not_executed':True,'control_success_logs_confirmed_as_control_process':True,'mutations_rejected':rej}
(D/'reports/verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
