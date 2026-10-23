"""Independent pefile address/relocation checks; not a second full RIP scanner."""
from pathlib import Path
import json,struct,hashlib,re
import pefile
D=Path(__file__).resolve().parents[1];r=json.loads((D/'reports/references.json').read_text());p=pefile.PE('/data/wlab-inputs/Wow.exe');b=bytes(p.__data__);base=p.OPTIONAL_HEADER.ImageBase
assert hashlib.sha256(b).hexdigest()==r['binary_sha256']
anchors=r['anchors'];checks=[]
for a in anchors:
 assert p.get_data(a['rva'],a['length_including_nul'])==a['text'].encode()+b'\0'
 checks.append(dict(text=a['text'],rva=a['rva'],sha256=hashlib.sha256(p.get_data(a['rva'],a['length_including_nul'])).hexdigest()))
spans=[(s['name'],s['begin'],s['end']) for s in r['target_spans']];ptrs=[]
for block in p.DIRECTORY_ENTRY_BASERELOC:
 for e in block.entries:
  if e.type!=10:continue
  target=struct.unpack('<Q',p.get_data(e.rva,8))[0]-base;labels=[n for n,lo,hi in spans if lo<=target<hi]
  if labels:ptrs.append(dict(slot_rva=e.rva,target_rva=target,target_spans=labels))
assert sorted(ptrs,key=lambda x:x['slot_rva'])==sorted(r['relocation_pointer_candidates'],key=lambda x:x['slot_rva'])
rawmatches=[]
for a in anchors:
 for typ,value,fmt in [('rva32',a['rva'],'<I'),('preferred_va64',base+a['rva'],'<Q')]:
  pat=struct.pack(fmt,value)
  for m in re.finditer(b'(?='+re.escape(pat)+b')',b):rawmatches.append(dict(anchor=a['text'],encoding=typ,file_offset=m.start()))
assert sorted((x['anchor'],x['encoding'],x['file_offset']) for x in rawmatches)==sorted((x['anchor'],x['encoding'],x['file_offset']) for x in r['literal_anchor_address_matches'])
for x in r['rip_candidates']:
 raw=bytes.fromhex(x['bytes']);assert p.get_data(x['rva'],len(raw))==raw
 assert x['rva']+len(raw)+struct.unpack_from('<i',raw,x['disp_offset'])[0]==x['target_rva']
# Read neighboring [numeric code, VA-to-text] records. The pattern itself does not name an API call.
records=[]
for slot in range(0x3ea6d10,0x3ea6d90,16):
 code,va=struct.unpack('<QQ',p.get_data(slot,16));target=va-base
 raw=p.get_data(target,160).split(b'\0',1)[0];text=raw.decode('ascii');assert all(32<=c<127 for c in raw)
 records.append(dict(record_rva=slot,numeric_code=code,string_pointer_slot=slot+8,string_rva=target,text=text))
assert any(x['string_pointer_slot']==0x3ea6d48 and x['text']=='WSAStartup' for x in records)
# Bounded page context: redact embedded build machine roots; store original hash.
context=[]
raw=p.get_data(0x4249000,0x350)
for m in re.finditer(rb'[ -~]{8,}\x00',raw):
 text=m.group()[:-1].decode();row=dict(rva=0x4249000+m.start(),sha256=hashlib.sha256(m.group()[:-1]).hexdigest())
 if ':\\' in text:
  row.update(text='[build-root-redacted]\\'+('msquic\\2.6.0.13\\src\\platform\\tls_openssl.c' if 'msquic' in text else 'openssl\\3.5.7.0\\ssl\\ssl_init.c'),embedded_path_redacted=True)
 else:row['text']=text
 context.append(row)
out=dict(input_sha256=r['binary_sha256'],anchor_checks=checks,relocation_agreement=True,raw_literal_agreement=True,candidate_displacement_arithmetic_agreement=True,independent_full_rip_scan=False,pointer_record_context=records,nearby_static_context=context,limits='Record pattern and nearby dependency paths are static evidence only. No runtime invocation, live algorithm choice, API resolution or V2 dataflow established.')
(D/'reports/verification.json').write_text(json.dumps(out,indent=2)+'\n')
print('Verified 4 anchors; 300 relocation pointers; 1 exact raw address; 2 positive-control RIP decodes. No full independent RIP rescan.')
print('Record',next(x for x in records if x['text']=='WSAStartup'))
