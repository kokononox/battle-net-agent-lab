"""Offline PE32+ evidence navigator. Never loads or executes the input image."""
from __future__ import annotations
import argparse, bisect, hashlib, json, re, struct, sys, time, zipfile
from collections import deque
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET, CS_AC_WRITE
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
VERSION='0.1.0'
KNOWN_SHA='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
LITERALS=['HARDWARE\\DESCRIPTION\\System\\BIOS','BIOSVersion','BIOSVendor','BIOSReleaseDate',
 'BaseBoardProduct','BaseBoardManufacturer','BaseBoardVersion','BiosMinorRelease',
 'HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0']
PROFILE_ANCHORS={'ClientEngineLogV2.prototype':0x4856510,'ClientEngineLogV2.ClassData':0x47cf7e0,
 'ClientEngineLogV2.parse_table':0x47cec08,'ClientEngineLogV2.registration':0x47cebb0}
FIELDS={0x60:'motherboardBiosVendorName',0x68:'motherboardBiosReleaseDate',0x70:'motherboardBiosVersion'}
REGISTRY_APIS={'RegGetValueW','RegGetValueA','RegQueryValueExW','RegQueryValueExA','RegOpenKeyExW','RegOpenKeyExA'}
LIMITS={'literal_occurrences':512,'raw_candidates':12000,'functions':160,'function_bytes':131072,
 'instructions_per_function':16000,'pointer_refs':12000}
class InputError(ValueError):pass
class Image:
 def __init__(self,path):
  p=Path(path)
  if not p.is_file():raise InputError('Input file not found.')
  if p.stat().st_size>1024**3:raise InputError('File exceeds the 1 GiB safety limit.')
  self.blob=p.read_bytes(); self.sha=hashlib.sha256(self.blob).hexdigest()
  try:self.pe=pefile.PE(data=self.blob,fast_load=True)
  except pefile.PEFormatError as e:raise InputError('Invalid PE: '+str(e)) from e
  if self.pe.FILE_HEADER.Machine!=0x8664 or self.pe.OPTIONAL_HEADER.Magic!=0x20b:
   raise InputError('Only x86-64 PE32+ images are supported. No input was executed.')
  self.base=self.pe.OPTIONAL_HEADER.ImageBase; self.sections=[]; self.warnings=[]
  for s in self.pe.sections:
   if s.PointerToRawData+s.SizeOfRawData>len(self.blob):raise InputError('Truncated section data.')
   if s.SizeOfRawData:self.sections.append((s.VirtualAddress,s.VirtualAddress+s.SizeOfRawData,s.PointerToRawData,s))
  self.sections.sort(key=lambda x:x[0])
  for a,b in zip(self.sections,self.sections[1:]):
   if a[1]>b[0]:raise InputError('Overlapping file-backed section RVAs are unsupported.')
  self.functions=[]
  d=self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
  if d.VirtualAddress and d.Size:
   if d.Size>32*1024*1024:raise InputError('Exception directory too large.')
   raw=self.read(d.VirtualAddress,d.Size)
   if len(raw)!=d.Size:raise InputError('Exception directory is not fully file-backed.')
   if d.Size%12:self.warnings.append('Exception directory length is not a multiple of 12.')
   for off in range(0,len(raw)-11,12):
    a,b,u=struct.unpack_from('<III',raw,off)
    if a<b and self.exec_section(a) and self.exec_section(b-1):self.functions.append((a,b,u))
  self.functions=sorted(set(self.functions)); self.starts=[x[0] for x in self.functions]
  if not self.functions:self.warnings.append('No supported pdata function entries; raw references cannot be locally CFG-validated.')
  self.imports={}
  try:
   self.pe.parse_data_directories(directories=[1])
   for mod in getattr(self.pe,'DIRECTORY_ENTRY_IMPORT',[]):
    dll=mod.dll.decode('ascii','replace')
    for ent in mod.imports:
     name=ent.name.decode('ascii','replace') if ent.name else '#'+str(ent.ordinal)
     self.imports[ent.address-self.base]=dll+'!'+name
  except Exception as e:self.warnings.append('Import parsing incomplete: '+str(e))
 def section(self,r):return next((x for x in self.sections if x[0]<=r<x[1]),None)
 def exec_section(self,r):
  x=self.section(r);return bool(x and x[3].Characteristics&0x20000000)
 def read(self,r,n):
  x=self.section(r)
  if not x:return b''
  k=min(n,x[1]-r);return self.blob[x[2]+r-x[0]:x[2]+r-x[0]+k]
 def rva(self,off):
  for a,b,p,s in self.sections:
   if p<=off<p+b-a:return a+off-p
  return None
 def function(self,r):
  i=bisect.bisect_right(self.starts,r)-1
  if i>=0 and self.functions[i][0]<=r<self.functions[i][1]:return self.functions[i]
  return None

def decoder():
 c=Cs(CS_ARCH_X86,CS_MODE_64);c.detail=True;return c

def cfg(image,fun,cs,cap=None):
 """Recursive local direct-flow decoding, not a proof of runtime reachability."""
 a,b,u=fun; queue=deque([a]); seen={}; spans={}; issues=[]; edges=[]
 limit=cap or LIMITS['instructions_per_function']
 if b-a>LIMITS['function_bytes']:return {},[],['Function exceeds byte budget; not decoded.']
 while queue and len(seen)<limit:
  cur=queue.popleft()
  while a<=cur<b and cur not in seen and len(seen)<limit:
   if cur in spans:
    issues.append('Overlapping instruction start at '+hex(cur));break
   ins=next(cs.disasm(image.read(cur,min(15,b-cur)),image.base+cur,count=1),None)
   if not ins:issues.append('Undecodable bytes at '+hex(cur));break
   if any(cur+j in spans for j in range(ins.size)):
    issues.append('Overlapping decode at '+hex(cur));break
   seen[cur]=ins
   for j in range(ins.size):spans[cur+j]=cur
   nxt=cur+ins.size
   if ins.group(CS_GRP_RET) or ins.mnemonic in ('int3','ud2','hlt','int','sysret','iretq'):break
   if ins.group(CS_GRP_JUMP):
    direct=bool(ins.operands and ins.operands[0].type==X86_OP_IMM)
    target=ins.operands[0].imm-image.base if direct else None
    edges.append({'from_rva':cur,'to_rva':target,'kind':ins.mnemonic})
    if direct and a<=target<b:queue.append(target)
    elif direct:issues.append('Branch leaves declared function at '+hex(cur))
    else:issues.append('Indirect branch unresolved at '+hex(cur))
    if ins.mnemonic=='jmp':break
   cur=nxt
 if queue or len(seen)>=limit:issues.append('Instruction budget reached; CFG coverage incomplete.')
 return seen,edges,sorted(set(issues))

def analyze(path,progress=lambda *_:None):
 started=time.monotonic();progress(3,'Reading PE; calculating SHA-256')
 im=Image(path);cs=decoder();bounded=[];anchors={};literals=[]
 for word in LITERALS:
  for encoding in ('utf-16le','ascii'):
   needle=(word+'\0').encode(encoding);pos=0;hits=[]
   while len(hits)<LIMITS['literal_occurrences']:
    off=im.blob.find(needle,pos)
    if off<0:break
    r=im.rva(off)
    if r is not None:hits.append({'rva':r,'file_offset':off});anchors.setdefault(r,[]).append(word+' ['+encoding+']')
    pos=off+len(needle)
   if len(hits)==LIMITS['literal_occurrences']:bounded.append('Literal occurrence budget: '+word)
   if hits:literals.append({'text':word,'encoding':encoding,'occurrences':hits})
 profile=im.sha==KNOWN_SHA
 if profile:
  for label,r in PROFILE_ANCHORS.items():anchors.setdefault(r,[]).append(label)
 progress(15,'Scanning RIP-relative candidates in executable sections')
 # Decode only candidate opcode sites. These may be data or an instruction interior.
 # Validation below distinguishes locally decoded sites; never treats raw hits as code proof.
 pat=re.compile(rb'(?=[\x40-\x4f]?[\x8b\x8d\x89\xff][\x05\x0d\x15\x1d\x25\x2d\x35\x3d][\s\S]{4})')
 hits=[];dedup=set();selected={};site_count=0
 for va,end,off,s in im.sections:
  if not s.Characteristics&0x20000000:continue
  code=im.blob[off:off+end-va]
  for m in pat.finditer(code):
   r=va+m.start();ins=next(cs.disasm(im.read(r,15),im.base+r,count=1),None)
   if not ins:continue
   for op in ins.operands:
    if op.type!=X86_OP_MEM or op.mem.base!=X86_REG_RIP:continue
    target=r+ins.size+op.mem.disp
    label=anchors.get(target)
    api=im.imports.get(target)
    is_registry_call=ins.mnemonic in ('call','jmp') and api and api.split('!')[-1] in REGISTRY_APIS
    if not label and not is_registry_call:continue
    key=(r,target)
    if key in dedup:continue
    dedup.add(key);fun=im.function(r)
    hits.append({'site_rva':r,'target_rva':target,'target_labels':label or [api],
     'kind':'import_registry_call' if is_registry_call else 'rip_relative_candidate',
     'bytes':ins.bytes.hex(),'instruction':ins.mnemonic+' '+ins.op_str,
     'function_start_rva':fun[0] if fun else None,'cfg_status':'not_checked'})
    if fun:selected[fun[0]]=fun
    if len(hits)>=LIMITS['raw_candidates']:break
   if len(hits)>=LIMITS['raw_candidates']:break
  site_count+=min(len(code),m.start()+8) if len(hits)>=LIMITS['raw_candidates'] else len(code)
  if len(hits)>=LIMITS['raw_candidates']:
   bounded.append('Raw candidate budget reached; remaining code sections not scanned.');break
 # Relocation-backed data pointers, not function calls or proof of use.
 progress(42,'Inspecting relocation-backed pointers')
 ptrs=[]
 try:
  im.pe.parse_data_directories(directories=[5])
  for block in getattr(im.pe,'DIRECTORY_ENTRY_BASERELOC',[]):
   for ent in block.entries:
    if ent.type!=10:continue
    raw=im.read(ent.rva,8)
    if len(raw)!=8:continue
    target=struct.unpack('<Q',raw)[0]-im.base
    if target in anchors:
     ptrs.append({'site_rva':ent.rva,'target_rva':target,'target_labels':anchors[target],'kind':'relocation_backed_data_pointer'})
     if len(ptrs)>=LIMITS['pointer_refs']:break
   if len(ptrs)>=LIMITS['pointer_refs']:bounded.append('Pointer reference budget reached.');break
 except Exception as e:im.warnings.append('Relocations incomplete: '+str(e))
 # Favor literal-anchored functions over broad registry-only functions.
 ordered=sorted(selected.values(),key=lambda f:(not any(h['function_start_rva']==f[0] and h['kind']=='rip_relative_candidate' for h in hits),f[0]))
 if len(ordered)>LIMITS['functions']:bounded.append('Function budget reached; extra functions not decoded.')
 funcs=[]
 for idx,fun in enumerate(ordered[:LIMITS['functions']]):
  progress(48+int(42*idx/max(1,min(len(ordered),LIMITS['functions']))),'Inspecting function '+hex(fun[0]))
  instructions,edges,issues=cfg(im,fun,cs);direct=[];imports=[];writes=[];lines=[]
  for r,ins in sorted(instructions.items()):
   lines.append(f'{r:08x}  {ins.bytes.hex():30}  {ins.mnemonic} {ins.op_str}')
   if ins.mnemonic in ('call','jmp'):
    for op in ins.operands:
     if op.type==X86_OP_IMM:direct.append({'site_rva':r,'target_rva':op.imm-im.base,'kind':ins.mnemonic})
     if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
      slot=r+ins.size+op.mem.disp
      imports.append({'site_rva':r,'iat_rva':slot,'name':im.imports.get(slot),'resolved':slot in im.imports})
   if profile:
    for op in ins.operands:
     if op.type==X86_OP_MEM and op.mem.base not in (0,X86_REG_RIP) and op.mem.disp in FIELDS and op.access&CS_AC_WRITE:
      writes.append({'site_rva':r,'offset':op.mem.disp,'candidate_field':FIELDS[op.mem.disp],
       'base_register':ins.reg_name(op.mem.base),'object_identity_proven':False,
       'caution':'Offset-only coincidence; base register NOT proven to be a message object.'})
  for h in hits:
   if h['function_start_rva']==fun[0]:
    ins=instructions.get(h['site_rva'])
    h['cfg_status']='locally_decoded_from_pdata_entry' if ins and ins.bytes.hex()==h['bytes'] else 'not_reached_in_bounded_local_cfg'
  funcs.append({'start_rva':fun[0],'end_rva':fun[1],'unwind_info_rva':fun[2],
   'decoded_instruction_count':len(instructions),'issues':issues,'branches':edges,
   'direct_calls_or_tail_jumps':direct,'indirect_import_sites':imports,
   'offset_only_write_candidates':writes,'disassembly':'\n'.join(lines)})
 progress(94,'Building evidence and explicit coverage report')
 result={'tool':'WLab BIOS Path','version':VERSION,'input':{'name':Path(path).name,'sha256':im.sha,'size':len(im.blob),'image_base':im.base,'architecture':'x86-64'},
  'profile':{'matched':profile,'known_build':'12.1.5.70448' if profile else None,
   'message_layout_hints_enabled':profile,'source_commit':'c7efc17bd4adf3d6cf48278233075b74a879e486' if profile else None},
  'literals':literals,'code_candidates':hits,'data_pointer_candidates':ptrs,'functions':funcs,
  'coverage':{'scope':'Offline, exact anchor starts, RIP-relative opcode patterns and relocation-backed pointers; bounded intraprocedural direct-flow decoding.',
   'exception_function_entries':len(im.functions),'executable_bytes_pattern_scanned':site_count,
   'functions_selected':len(ordered),'functions_decoded':len(funcs),'limits':LIMITS,'budget_limits_hit':bounded,'warnings':im.warnings,
   'not_covered':['Runtime reachability and actual values','Packed/encrypted code recovery','Indirect call graph and dynamic imports','Interior string pointers and encoded pointers','Whole-program data flow or message object identity','Network payload or destination/port binding','Delayed imports are not resolved']},
  'claims':{'input_executed':False,'input_modified':False,'hardware_read_executed_proven':False,'hardware_population_proven':False,
   'serialization_of_hardware_proven':False,'runtime_send_proven':False,'destination_or_port_3724_binding_proven':False},
  'elapsed_seconds':round(time.monotonic()-started,3)}
 from verify_report import verify
 result['verification']=verify(path,result)
 return result

def write_outputs(result,out):
 out=Path(out);out.parent.mkdir(parents=True,exist_ok=True);out.mkdir(exist_ok=False)
 (out/'QA.json').write_text(json.dumps(result['verification'],ensure_ascii=False,indent=2),encoding='utf-8')
 (out/'evidence.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 rows=['# WLab BIOS Path — گزارش بررسی آفلاین','',
 '**نتیجه دربارهٔ ارسال CPU/BIOS روی 3724: نامشخص.**',
 'این ابزار فایل ورودی را اجرا، بارگذاری به‌عنوان کتابخانه یا تغییر نمی‌دهد. یافته‌ها سرنخ تحلیل ایستا هستند، نه اثبات رفتار زمان اجرا.','',
 '## ورودی','نام: `'+result['input']['name']+'`','SHA-256: `'+result['input']['sha256']+'`',
 'پروفایل بیلد شناخته‌شده: '+('تطبیق دارد؛ راهنمای آفست‌ها فعال است.' if result['profile']['matched'] else 'تطبیق ندارد؛ راهنمای آفست پیام غیرفعال است.'),'',
 '## یافته‌ها',f"- رشته‌ها: {sum(len(x['occurrences']) for x in result['literals'])}",
 f"- نامزد ارجاع کد: {len(result['code_candidates'])}",f"- ارجاع داده: {len(result['data_pointer_candidates'])}",
 f"- بدنه‌های بررسی‌شده: {len(result['functions'])}",
 '- «locally_decoded» فقط یعنی محل ارجاع در گراف محلیِ ساخته‌شده از ورودی pdata دیکد شده است؛ صحت کل تابع یا اجرای واقعی ثابت نشده.',
 '- نوشتن در آفست مشابه، هویت شیء ClientEngineLogV2 را ثابت نمی‌کند.', '', '## مرز پوشش']
 rows+=['- '+x for x in result['coverage']['warnings']+result['coverage']['budget_limits_hit']+result['coverage']['not_covered']]
 rows+=['','## محدودیت‌های بدنه‌های منتخب']
 for f in result['functions']:
  if f['issues']:rows.append('- '+hex(f['start_rva'])+': '+'; '.join(f['issues']))
 rows+=['','## قدم بعدی','ارجاع‌های معتبر محلی را در Ghidra با بایت‌های فایل تطبیق دهید؛ منشأ رجیستر پایه و خروجی خواندن رجیستری را بررسی کنید. اگر کد محافظت‌شده یا فراخوانی غیرمستقیم مانع شد، شاهد تازه لازم است؛ اسکن بی‌نتیجه نبود ارسال را ثابت نمی‌کند.','','## ارجاع‌های کد','| RVA | هدف | وضعیت |','|---|---|---|']
 rows += [f"| {hex(h['site_rva'])} | {'; '.join(h['target_labels'])} | {h['cfg_status']} |" for h in result['code_candidates']]
 (out/'report.fa.md').write_text('\n'.join(rows)+'\n',encoding='utf-8')
 d=out/'functions';d.mkdir(exist_ok=True)
 for f in result['functions']:(d/(f"{f['start_rva']:08x}.asm")).write_text(f['disassembly']+'\n',encoding='utf-8')
 # Only generated snippets/reports are included; never original PE bytes or full file path.
 with zipfile.ZipFile(out/'evidence.zip','w',zipfile.ZIP_DEFLATED) as z:
  for p in [out/'evidence.json',out/'QA.json',out/'report.fa.md',*sorted(d.glob('*.asm'))]:z.write(p,p.relative_to(out))
 return out/'evidence.zip'

def main():
 ap=argparse.ArgumentParser();ap.add_argument('input');ap.add_argument('--out',required=True);a=ap.parse_args()
 try:
  r=analyze(a.input,lambda p,t:print(f'{p}% {t}',flush=True));print(write_outputs(r,a.out));return 0
 except Exception as e:print('ERROR: '+str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
