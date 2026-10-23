"""Bounded literal matching of observed V2 startup to static binaries and existing dumps."""
from pathlib import Path
import os,json,struct,hashlib,collections
from pe_manual import PE
D=Path(__file__).resolve().parents[1];I=Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'));DD=Path(os.environ.get('DUMP_DIR','/data/wlab-crash-dump-review/work'))
PIN={'Wow.exe':'1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a','wow_loader.dll':'c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'}
OP={0x440001:'CMSG_AUTH_SESSION',0x440003:'CMSG_AUTH_CONTINUED_SESSION',0x440005:'CMSG_ENTER_ENCRYPTED_MODE_ACK',0x4c0000:'SMSG_AUTH_CHALLENGE',0x4c0004:'SMSG_ENTER_ENCRYPTED_MODE'}
BANNERS=['WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2\n','WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2\n']
PATTERNS=BANNERS+[x[:-1] for x in BANNERS]+list(OP.values())+['WORLD OF WARCRAFT CONNECTION','ENTER_ENCRYPTED_MODE','AuthSession','WorldSocket','AUTH_CHALLENGE']
DUMPS={'2026-10-22_07.50.48_Crash_4760.dmp':'3dad4393b384c716b0b45b703524031ba268af2dde3555b34bfc1144e60aa6f2','2026-10-22_07.56.51_Crash_10768.dmp':'70216d653ee1d63574ea7771b1291f07994bf9bd63035dffb407fa9c4ceb9815'}
def h(b):return hashlib.sha256(b).hexdigest()
def hits(b,pattern):
 out=[];at=0
 while True:
  at=b.find(pattern,at)
  if at<0:return out
  out.append(at);at+=1
result={'capture_baseline_commit':'b57ae91fe8ba9827d03be8d1655c3cb2a87df57c','capture_exact_build_verified':False,'binaries':[],'existing_dump_checks':[]}
for name in ['Wow.exe','wow_loader.dll','libxell.dll']:
 p=PE(I/name);sha=h(p.b)
 if name in PIN:assert sha==PIN[name]
 pe=struct.unpack_from('<I',p.b,0x3c)[0];st=pe+24+struct.unpack_from('<H',p.b,pe+20)[0];sections=[]
 for i,s in enumerate(p.sections):
  flags=struct.unpack_from('<I',p.b,st+40*i+36)[0];sections.append({'name':s[0],'rva':s[2],'file_offset':s[4],'raw_size':s[3],'executable':bool(flags&0x20000000)})
 def locate(off,n):
  s=next((x for x in sections if x['file_offset']<=off and off+n<=x['file_offset']+x['raw_size']),None)
  return {'rva':s['rva']+off-s['file_offset'] if s else None,'section':s['name'] if s else None,'executable_section':bool(s and s['executable'])}
 strings=[]
 for text in PATTERNS:
  for enc in ['ascii','utf-16le']:
   raw=text.encode(enc);locs=[]
   for off in hits(p.b,raw):
    rec={'file_offset':off,**locate(off,len(raw))}
    if enc=='ascii':
     lo=p.b.rfind(b'\0',max(0,off-256),off)+1;hi=p.b.find(b'\0',off,min(len(p.b),off+256))
     if hi>=off:
      container=p.b[lo:hi]
      if all(x in [9,10,13] or 32<=x<127 for x in container):rec['ascii_container']=container.decode()
    locs.append(rec)
   strings.append({'pattern':text,'encoding':enc,'matches':locs})
 scalars=[]
 for op,label in OP.items():
  raw=struct.pack('<I',op);matches=[]
  for off in hits(p.b,raw):
   loc=locate(off,4);lo=max(0,off-16);hi=min(len(p.b),off+20)
   matches.append({'file_offset':off,**loc,'rva_mod4':loc['rva']%4 if loc['rva'] is not None else None,'context_file_offset':lo,'context_hex':p.b[lo:hi].hex(),'context_sha256':h(p.b[lo:hi])})
  scalars.append({'value':op,'label':label,'matches':matches,'count':len(matches),'executable_match_count':sum(x['executable_section'] for x in matches)})
 row={'name':name,'size_bytes':len(p.b),'sha256':sha,'previous_expected_hash_checked':name in PIN,'sections':sections,'strings':strings,'literal_dword_search':scalars}
 if name=='Wow.exe':
  # Proven local context only, not a complete type/handler-table reconstruction.
  slots=[0x487f1f0,0x487f208];relset=set();r,size=p.dirs[5];cur=0
  while cur<size:
   page,n=struct.unpack('<II',p.read(r+cur,8));assert n>=8 and cur+n<=size
   for q in range(8,n,2):
    v=p.u(r+cur+q,'<H')
    if v>>12==10:relset.add(page+(v&4095))
   cur+=n
  context=[]
  for slot in slots:
   dest=p.u(slot,'<Q')-p.base;value=p.text(dest);assert value in ['ERR_DUEL_REQUESTED','ERR_DUEL_CANCELLED'];assert slot in relset
   context.append({'pointer_slot_rva':slot,'dir64_present':True,'string_rva':dest,'string':value})
  component=[]
  for va in [0x414f148,0x414f178,0x414f200,0x414f250,0x414f2a0,0x414f300,0x414f370,0x414f3d0]:
   text=p.text(va);ispath='\\' in text and ':\\' in text
   component.append({'rva':va,'text_or_basename':text.replace('\\','/').rsplit('/',1)[-1] if ispath else text,'full_string_sha256':h(text.encode()+b'\0'),'build_path_redacted':ispath})
  row['network_component_context']={'nearby_strings':component,'code_ownership_proven':False,'adjacency_is_not_dataflow':True}
  row['single_auth_session_match_context']={'match_rva':0x487f1fe,'literal_bytes':'01004400','rva_mod4':2,'nearby_relocation_backed_strings':context,'network_handler_connection_proven':False}
 result['binaries'].append(row)
# Four narrow pattern checks on raw existing dump files. No memory attribution if absent.
for name,pin in DUMPS.items():
 f=DD/name
 if not f.exists():result['existing_dump_checks'].append({'name':name,'available':False});continue
 b=f.read_bytes();assert h(b)==pin;rows=[]
 for pattern in BANNERS+[x[:-1] for x in BANNERS]+['CMSG_ENTER_ENCRYPTED_MODE_ACK','SMSG_ENTER_ENCRYPTED_MODE']:
  for enc in ['ascii','utf-16le']:rows.append({'pattern':pattern,'encoding':enc,'raw_file_offsets':hits(b,pattern.encode(enc))})
 result['existing_dump_checks'].append({'name':name,'available':True,'sha256':pin,'size_bytes':len(b),'narrow_string_checks':rows})
result['limits']='Literal ASCII/UTF16 and complete little-endian DWORD representations only; not split immediates, computed/encoded identifiers, dynamic tables, self-modified code or arbitrary external modules. Absence does not prove protocol mismatch, wrong build, or encryption. Existing dump checks do not add absent pages or establish runtime state at capture time.'
(D/'reports/discovery.json').write_text(json.dumps(result,indent=2)+'\n')
for x in result['binaries']:print(x['name'],'string hits',sum(len(y['matches']) for y in x['strings']),'DWORD hits',sum(y['count'] for y in x['literal_dword_search']),'executable',sum(y['executable_match_count'] for y in x['literal_dword_search']))
