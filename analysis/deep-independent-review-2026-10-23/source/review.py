"""Pinned offline evidence review. Reads PE bytes only. Never loads or runs them."""
from pathlib import Path
import sys,struct,json,hashlib,re,ctypes,subprocess,tempfile
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ROOT=Path(__file__).resolve().parents[1]
PIN='c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c'
W_PIN='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
def digest(b):return hashlib.sha256(b).hexdigest()
def produce(loader,wow):
 b=Path(loader).read_bytes();w=Path(wow).read_bytes();assert digest(b)==PIN and digest(w)==W_PIN,'wrong input identity'
 p=pefile.PE(data=b);wp=pefile.PE(data=w);base=p.OPTIONAL_HEADER.ImageBase
 md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
 def read(r,n):return p.get_data(r,n)
 records={e.struct.BeginAddress:e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION}
 bodies=[]
 for start in [0x20062ec,0x2006080,0x2006134]:
  e=records[start];raw=read(start,e.EndAddress-start);inst=list(md.disasm(raw,start))
  assert inst and inst[-1].address+inst[-1].size==e.EndAddress
  # GNU objdump independently checks the same straight-line instruction boundaries.
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'data.bin';f.write_bytes(raw)
   text=subprocess.run(['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16','--adjust-vma='+hex(start),str(f)],capture_output=True,text=True,check=True).stdout
   dec=[]
   for line in text.splitlines():
    parts=line.split('\t')
    if len(parts)<3:continue
    try:a=int(parts[0].strip().rstrip(':'),16);ib=bytes.fromhex(parts[1].strip())
    except ValueError:continue
    dec.append((a,ib))
   assert dec==[(i.address,bytes(i.bytes)) for i in inst]
  bodies.append({'begin':start,'end':e.EndAddress,'sha256':digest(raw),'instruction_count':len(inst),'instructions':[{'rva':i.address,'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str} for i in inst]})
 class ER64(ctypes.LittleEndianStructure):
  _fields_=[('ExceptionCode',ctypes.c_uint32),('ExceptionFlags',ctypes.c_uint32),('ExceptionRecord',ctypes.c_uint64),('ExceptionAddress',ctypes.c_uint64),('NumberParameters',ctypes.c_uint32),('Alignment',ctypes.c_uint32),('ExceptionInformation',ctypes.c_uint64*15)]
 offsets={k:getattr(ER64,k).offset for k in ['ExceptionCode','ExceptionFlags','NumberParameters','ExceptionInformation']}
 pair_rva=0x2040a90;pair=struct.unpack('<QQ',read(pair_rva,16));rec,ctx=[v-base for v in pair]
 assert rec==0x2194730 and ctx==0x21947d0
 writes=[]
 for site,label,expected in [(0x2006195,'ExceptionCode',0xc0000409),(0x200619f,'ExceptionFlags',1),(0x20061a9,'NumberParameters',1)]:
  raw=read(site,10);assert raw[:2]==b'\xc7\x05';address=site+10+struct.unpack_from('<i',raw,2)[0];value=struct.unpack_from('<I',raw,6)[0]
  assert address==rec+offsets[label] and value==expected
  writes.append({'site':site,'bytes':raw.hex(),'field':label,'target':address,'offset':offsets[label],'value':value})
 raw=read(0x20061bc,7);assert raw[:3]==bytes.fromhex('488d0d');info=0x20061bc+7+struct.unpack_from('<i',raw,3)[0];assert info==rec+offsets['ExceptionInformation']
 # Locked arithmetic/store sequence: RAX=8*0, then qword [RCX+RAX]=2.
 assert read(0x20061b3,9).hex()=='b808000000486bc000'
 assert read(0x20061c3,8).hex()=='48c7040102000000'
 fast=read(0x200614c,7);assert fast.hex()=='b902000000cd29'
 refs=[]
 for site in [0x200610b,0x20061f5]:
  raw=read(site,7);assert raw[:3]==bytes.fromhex('488d0d');a=site+7+struct.unpack_from('<i',raw,3)[0];assert a==pair_rva
  call=read(site+7,5);assert call[0]==0xe8 and site+12+struct.unpack_from('<i',call,1)[0]==0x20062ec
  refs.append({'lea_site':site,'pair_rva':a,'call_site':site+7,'wrapper_rva':0x20062ec})
 slots=[]
 for site,n,prefix in [(0x20062f7,6,'ff15'),(0x2006300,6,'ff15'),(0x2006306,6,'ff15'),(0x2006319,7,'48ff25')]:
  raw=read(site,n);assert raw.hex().startswith(prefix);slots.append({'site':site,'slot_rva':site+n+struct.unpack('<i',raw[-4:])[0]})
 # Public source consistency, not an API-binding or exact compiler identity proof.
 crt=(ROOT/'reference/gs_support.c').read_text();tail=crt[crt.index('__report_gsfailure (ULONG_PTR StackCookie)'):]
 compact=re.sub(r'\s+','',tail)
 ordered=['GS_ExceptionRecord.ExceptionCode=STATUS_STACK_BUFFER_OVERRUN;','SetUnhandledExceptionFilter(NULL);','UnhandledExceptionFilter((EXCEPTION_POINTERS*)&GS_ExceptionPointers);','TerminateProcess(GetCurrentProcess(),STATUS_STACK_BUFFER_OVERRUN);']
 positions=[compact.index(x) for x in ordered];assert positions==sorted(positions)
 sections=[];needles=[]
 for name in [b'.eidsig',b'.eid']:
  s=next(s for s in p.sections if s.Name.rstrip(b'\0')==name);raw=s.get_data();sections.append({'name':name.decode(),'rva':s.VirtualAddress,'virtual_size':s.Misc_VirtualSize,'raw_size':s.SizeOfRawData,'raw_sha256':digest(raw),'first8_hex':raw[:8].hex()})
  if name==b'.eidsig':assert raw[:7]==b'EIDOLON'
  else:
   for target in [0x1b11190,0x1b14120,0x33068c0,0x1b11000,0x1b14000,0x3306000]:
    for kind,needle in [('rva32le',struct.pack('<I',target)),('preferred_va64le',struct.pack('<Q',wp.OPTIONAL_HEADER.ImageBase+target))]:
     hits=[];pos=0
     while (pos:=raw.find(needle,pos))>=0:hits.append(s.VirtualAddress+pos);pos+=1
     needles.append({'target_rva':target,'encoding':kind,'hits_in_file_backed_eid':hits})
 result={'schema':'wlab-deep-independent-review-1','loader_sha256':PIN,'wow_sha256':W_PIN,'source_image_base':base,'bodies':bodies,'exception_record':{'pair_rva':pair_rva,'record_rva':rec,'context_rva':ctx,'layout_offsets':offsets,'writes':writes,'information0_address':info,'information0_value':2,'fastfail_code2_site':0x200614c,'fastfail_code2_bytes':fast.hex(),'caller_pair_references':refs},'wrapper_slots':slots,'public_crt_match':{'source_url':'https://github.com/reactos/reactos/blob/fae4549cb0cd6d5867e65e61c2bc29985b57bc98/sdk/lib/crt/startup/gs_support.c','source_sha256':digest(crt.encode()),'ordered_source_operations':ordered,'classification':'Strong static consistency with CRT security-failure/fail-fast reporting; no exact symbol or runtime API binding established'},'eid_sections':sections,'eid_direct_target_reference_scan':needles,'scope_limits':['Direct byte-pattern scan of only file-backed .eid; encoded/compressed/relative relationships are not covered','EIDOLON magic observed; following 0x0b byte has no assigned format/version semantics','Instruction boundaries cross-checked, not complete execution or all callee-effects proof','No target code decrypted, key recovered or CPU/BIOS network path established'],'claims':{'runtime_api_identity_confirmed':False,'decrypted_target_code_recovered':False,'decryption_algorithm_identified':False,'cpu_bios_send_proven':False,'cpu_bios_send_disproven':False,'live_test_requested':False,'target_binary_executed':False},'decision':'Keep CRT/API detour out of direct decryptor search; .eid format remains a bounded unresolved research lead, not a found decoder'}
 return result
if __name__=='__main__':
 if len(sys.argv)!=4:raise SystemExit('usage: review.py wow_loader.dll Wow.exe NEW-report.json')
 result=produce(sys.argv[1],sys.argv[2]);out=Path(sys.argv[3]);assert not out.exists(),'use new output path';out.write_text(json.dumps(result,indent=2)+'\n');print('PASS: pinned inputs, exception record, public CRT sequence, EIDOLON marker; no execution/decryption/send claim')
