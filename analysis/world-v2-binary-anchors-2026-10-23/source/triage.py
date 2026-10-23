"""Context classification for adjacent pointers; no new CFG or semantic reference claim."""
from pathlib import Path
import os,json,hashlib
from pe_manual import PE
D=Path(__file__).resolve().parents[1];p=PE(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe');r=json.loads((D/'reports/references.json').read_text());contexts=[]
for x in r['relocation_pointer_candidates']:
 if 'adjacent_banner_page' not in x['target_spans']:continue
 text=p.text(x['target_rva']);assert text.startswith('CG');contexts.append({**x,'target_text':text,'inside_either_banner':any(a['rva']<=x['target_rva']<a['rva']+a['length_including_nul'] for a in r['anchors'])})
context_rip=[]
for x in r['rip_candidates']:
 if 'adjacent_banner_page' not in x['target_spans']:continue
 off=p.loc(x['target_rva'])['file_offset'];lo=p.b.rfind(b'\0',off-256,off)+1;hi=p.b.find(b'\0',off,off+256);text=p.b[lo:hi].decode('ascii');context_rip.append({**x,'target_container':text,'target_offset_within_container':off-lo,'network_banner_reference_proven':False})
result={'adjacent_page_relocation_contexts':contexts,'adjacent_page_rip_contexts':context_rip,'decision':'Only normalized V2 strings and nearby NetClient/type diagnostics are identified. No banner consumer, dispatcher or encryption-entry function is recovered. Do not follow neighbouring CG object-type strings as if they were V2 handlers.','scope':'No CFG was reconstructed from the single non-banner RIP candidate. Loader XOR immediate is a numeric match without protocol dataflow evidence.'}
(D/'reports/triage.json').write_text(json.dumps(result,indent=2)+'\n');print('Adjacent CG string pointers:',len(contexts),'non-banner RIP candidates:',len(context_rip))
