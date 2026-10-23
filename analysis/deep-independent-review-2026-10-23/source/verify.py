"""Independent standard-library byte/structure checks, not a behavior proof."""
from pathlib import Path
import struct,json,sys,hashlib,copy
from pe_manual import PE
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c';WPIN='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
def sha(b):return hashlib.sha256(b).hexdigest()
def check(p,w,r,crt):
 assert sha(p.b)==PIN==r['loader_sha256'] and sha(w.b)==WPIN==r['wow_sha256']
 assert r['schema']=='wlab-deep-independent-review-1' and r['source_image_base']==p.base
 assert set(r['claims'])=={'runtime_api_identity_confirmed','decrypted_target_code_recovered','decryption_algorithm_identified','cpu_bios_send_proven','cpu_bios_send_disproven','live_test_requested','target_binary_executed'} and not any(r['claims'].values())
 pdata,size=p.dirs[3];ranges={p.u(pdata+i,'<I'):p.u(pdata+i+4,'<I') for i in range(0,size,12)}
 assert [b['begin'] for b in r['bodies']]==[0x20062ec,0x2006080,0x2006134]
 for body in r['bodies']:
  begin,end=body['begin'],body['end'];assert ranges[begin]==end and sha(p.read(begin,end-begin))==body['sha256']
  cursor=begin
  for i in body['instructions']:
   raw=bytes.fromhex(i['bytes']);assert raw and i['rva']==cursor and p.read(cursor,len(raw))==raw;cursor+=len(raw)
  assert cursor==end and len(body['instructions'])==body['instruction_count']
 pair=struct.unpack('<QQ',p.read(0x2040a90,16));rec,ctx=[v-p.base for v in pair];er=r['exception_record']
 assert (er['pair_rva'],er['record_rva'],er['context_rva'])==(0x2040a90,rec,ctx)==(0x2040a90,0x2194730,0x21947d0)
 # Widths/alignment follow the documented EXCEPTION_RECORD64 definition.
 assert struct.calcsize('<IIQQI4x')==32
 offsets={'ExceptionCode':0,'ExceptionFlags':4,'NumberParameters':24,'ExceptionInformation':32};assert er['layout_offsets']==offsets
 assert len(er['writes'])==3
 for row,(site,field,value) in zip(er['writes'],[(0x2006195,'ExceptionCode',0xc0000409),(0x200619f,'ExceptionFlags',1),(0x20061a9,'NumberParameters',1)]):
  raw=p.read(site,10);assert raw[:2]==bytes.fromhex('c705');target=site+10+struct.unpack('<i',raw[2:6])[0];imm=struct.unpack('<I',raw[6:])[0]
  assert row=={'site':site,'bytes':raw.hex(),'field':field,'target':target,'offset':offsets[field],'value':value} and target==rec+offsets[field] and imm==value
 assert p.read(0x200614c,7).hex()==er['fastfail_code2_bytes']=='b902000000cd29' and er['fastfail_code2_site']==0x200614c
 raw=p.read(0x20061bc,7);assert raw[:3].hex()=='488d0d'
 assert er['information0_address']==0x20061bc+7+struct.unpack('<i',raw[3:])[0]==rec+32 and er['information0_value']==2
 assert p.read(0x20061b3,9).hex()=='b808000000486bc000' and p.read(0x20061c3,8).hex()=='48c7040102000000'
 assert len(er['caller_pair_references'])==2
 for row,site in zip(er['caller_pair_references'],[0x200610b,0x20061f5]):
  raw=p.read(site,12);assert raw[:3].hex()=='488d0d' and raw[7]==0xe8
  assert site+7+struct.unpack('<i',raw[3:7])[0]==0x2040a90 and site+12+struct.unpack('<i',raw[8:12])[0]==0x20062ec
  assert row=={'lea_site':site,'pair_rva':0x2040a90,'call_site':site+7,'wrapper_rva':0x20062ec}
 assert len(r['wrapper_slots'])==4
 for row,(site,n,prefix,target) in zip(r['wrapper_slots'],[(0x20062f7,6,'ff15',0x20a0750),(0x2006300,6,'ff15',0x20a07e8),(0x2006306,6,'ff15',0x20a0400),(0x2006319,7,'48ff25',0x20a0798)]):
  raw=p.read(site,n);assert raw.hex().startswith(prefix) and site+n+struct.unpack('<i',raw[-4:])[0]==target and row=={'site':site,'slot_rva':target}
 assert p.read(0x200630f,5).hex()=='ba090400c0' and p.read(0x20062f2,5).hex()=='488bd933c9' and p.read(0x20062fd,3).hex()=='488bcb' and p.read(0x200630c,3).hex()=='488bc8'
 pub=r['public_crt_match'];assert sha(crt)==pub['source_sha256']
 compact=''.join(crt.decode().split());positions=[compact.index(x) for x in pub['ordered_source_operations']];assert positions==sorted(positions)
 assert [x['name'] for x in r['eid_sections']]==['.eidsig','.eid']
 raws={}
 for row in r['eid_sections']:
  name,vs,va,rs,ro=next(x for x in p.sections if x[0]==row['name']);raw=p.b[ro:ro+rs];raws[name]=raw
  assert row=={'name':name,'rva':va,'virtual_size':vs,'raw_size':rs,'raw_sha256':sha(raw),'first8_hex':raw[:8].hex()}
 assert raws['.eidsig'][:7]==b'EIDOLON' and raws['.eidsig'][7]==0x0b
 expected=[]
 eidva=next(x[2] for x in p.sections if x[0]=='.eid')
 for target in [0x1b11190,0x1b14120,0x33068c0,0x1b11000,0x1b14000,0x3306000]:
  for kind,needle in [('rva32le',struct.pack('<I',target)),('preferred_va64le',struct.pack('<Q',w.base+target))]:
   raw=raws['.eid'];hits=[];cursor=0
   while True:
    i=raw.find(needle,cursor)
    if i<0:break
    hits.append(eidva+i);cursor=i+1
   expected.append({'target_rva':target,'encoding':kind,'hits_in_file_backed_eid':hits})
 assert r['eid_direct_target_reference_scan']==expected
 return True

def main():
 if len(sys.argv)!=5:raise SystemExit('usage: verify.py wow_loader.dll Wow.exe report.json NEW-QA.json')
 p,w=PE(Path(sys.argv[1])),PE(Path(sys.argv[2]));r=json.loads(Path(sys.argv[3]).read_text());crt=(Path(__file__).resolve().parents[1]/'reference/gs_support.c').read_bytes();check(p,w,r,crt)
 tests=[]
 for name,mutate in [
 ('input_hash',lambda x:x.__setitem__('loader_sha256','0'*64)),
 ('marker',lambda x:x['eid_sections'][0].__setitem__('first8_hex','00'*8)),
 ('record_offset',lambda x:x['exception_record']['layout_offsets'].__setitem__('NumberParameters',20)),
 ('record_value',lambda x:x['exception_record']['writes'][0].__setitem__('value',0)),
 ('pair_reference',lambda x:x['exception_record']['caller_pair_references'][0].__setitem__('pair_rva',0)),
 ('slot',lambda x:x['wrapper_slots'][0].__setitem__('slot_rva',0)),
 ('bytes',lambda x:x['bodies'][0]['instructions'][0].__setitem__('bytes','90')),
 ('invented_eid_reference',lambda x:x['eid_direct_target_reference_scan'][0].__setitem__('hits_in_file_backed_eid',[1])),
 ('source_hash',lambda x:x['public_crt_match'].__setitem__('source_sha256','0'*64)),
 ('runtime_identity_claim',lambda x:x['claims'].__setitem__('runtime_api_identity_confirmed',True)),
 ('decryption_claim',lambda x:x['claims'].__setitem__('decrypted_target_code_recovered',True)),
 ('send_claim',lambda x:x['claims'].__setitem__('cpu_bios_send_proven',True)),
 ('no_send_claim',lambda x:x['claims'].__setitem__('cpu_bios_send_disproven',True))]:
  altered=copy.deepcopy(r);mutate(altered)
  try:check(p,w,altered,crt)
  except (AssertionError,ValueError,KeyError):tests.append({'mutation':name,'rejected':True})
  else:raise AssertionError('corruption accepted: '+name)
 qa={'byte_structure_verifier':'PASS; stdlib PE parser, no pefile/Capstone import','report_checks':'PASS','mutation_tests':tests,'limits':['Does not independently verify every assembly mnemonic','Producer separately cross-checks boundaries with GNU objdump','Does not prove execution, callee semantics, API binding or decryption'],'target_executed':False,'live_probe_built_or_requested':False}
 out=Path(sys.argv[4]);assert not out.exists();out.write_text(json.dumps(qa,indent=2)+'\n');print('PASS: independent byte/structure checks and',len(tests),'rejected corruptions')
if __name__=='__main__':main()
