"""Archive availability audit. Reads/hashes data only; never executes/extracts input members."""
from pathlib import Path
from zipfile import ZipFile
from html.parser import HTMLParser
import json,hashlib,collections,sys
D=Path(__file__).resolve().parents[1]
class Plain(HTMLParser):
 def __init__(self):super().__init__();self.parts=[]
 def handle_data(self,s):self.parts.append(s)
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def magic(b):
 if b.startswith(b'MDMP'):return 'minidump_signature_only'
 if b.startswith((b'Microsoft C/C++ MSF',b'BSJB')):return 'symbol_container_signature_only'
 if b.startswith(b'MZ'):return 'pe_candidate'
 if b.startswith((b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a')):return 'packet_capture_signature_only'
 if b.startswith(b'PK\x03\x04'):return 'nested_zip_signature'
 return None
def safe_analysis(j):
 out={k:j[k] for k in ['tool','status','read_calls','memory_bytes_requested','memory_bytes_returned','sending_on_3724'] if k in j}
 if 'page_reads' in j:
  out['page_read_record_count']=len(j['page_reads']);out['page_read_statuses']=[x.get('status') for x in j['page_reads']]
 error=str(j.get('error','')).lower();out['error_class']='win32_1006' if '1006' in error else 'guard_or_noaccess' if 'no-access' in error or 'guard' in error else 'mapping_or_identity_gate' if 'mapping' in error or 'mem_image' in error else 'other_or_not_recorded'
 return out

def audit(manifest):
 archives=[];texts=[];standalone=[];errors=[];total=0
 for spec in manifest['inputs']:
  path=Path(spec['path']);row={'label':spec['label'],'category':spec['category'],'size_bytes':path.stat().st_size,'sha256':digest(path)}
  if path.suffix.lower()=='.zip':
   members=[];analyses=[];count=0
   with ZipFile(path) as z:
    for i in z.infolist():
     if i.is_dir():continue
     if i.flag_bits&1:errors.append({'label':row['label'],'member':i.filename,'reason':'encrypted'});continue
     if i.file_size>128*1024*1024 or total+i.file_size>512*1024*1024:errors.append({'label':row['label'],'member':i.filename,'reason':'size_limit'});continue
     h=hashlib.sha256();first=b'';data=bytearray();size=0
     with z.open(i) as f:
      for b in iter(lambda:f.read(1024*1024),b''):
       if len(first)<64:first=(first+b)[:64]
       h.update(b);size+=len(b)
       if i.file_size<=8*1024*1024:data.extend(b)
     assert size==i.file_size;total+=size;count+=1
     rec={'name':i.filename,'size_bytes':size,'sha256':h.hexdigest(),'leading_signature':magic(first),'suffix':Path(i.filename).suffix.lower()}
     members.append(rec)
     if Path(i.filename).name=='analysis.json':
      try:analyses.append({'member':i.filename,'summary':safe_analysis(json.loads(data.decode('utf-8-sig')))})
      except (ValueError,UnicodeDecodeError):errors.append({'label':row['label'],'member':i.filename,'reason':'analysis_json_parse'})
   row.update({'members':members,'members_fully_read':count,'analysis_summaries':analyses});archives.append(row)
  elif spec['category']=='conversation_export':
   raw=path.read_text();p=Plain();p.feed(raw);text='\n'.join(p.parts)
   needles=['gg.pcapng','.dmp','.etl','.pdb','ReadProcessMemory','base64','WORLD OF WARCRAFT CONNECTION']
   row.update({'plain_text_characters':len(text),'term_occurrences':{n:text.lower().count(n.lower()) for n in needles},'content_not_republished':True});texts.append(row)
  else:
   b=path.read_bytes();row['leading_signature']=magic(b[:64]);standalone.append(row)
 counts=collections.Counter((m['leading_signature'] or 'other') for a in archives for m in a['members'])
 suffixes=collections.Counter(m['suffix'] for a in archives for m in a['members'])
 result={'scope':'Explicit frozen manifest of available session ZIPs, original retail ZIP, conversation exports and selected local provenance/test files; NOT all historic uploads, all GitHub branches or user computer.','archives':archives,'conversation_exports':texts,'standalone_files':standalone,'errors_or_unread':errors,'counts':{'archives':len(archives),'archive_members_fully_read':sum(a['members_fully_read'] for a in archives),'conversation_exports':len(texts),'standalone_files':len(standalone),'archive_signature_counts':dict(counts),'archive_suffix_counts':dict(suffixes),'archive_uncompressed_bytes_read':total},'claims':{'new_build_matched_runtime_code_found':False,'field_population_trace_found':False,'matched_game_symbols_found':False,'hardware_send_proven':False},'caveats':['Signatures/extensions only identify candidates, not origin or build.','Synthetic test dumps are not runtime game evidence.','A log referring to a local dump is not the dump itself.','Conversation claims are not original binary artifacts.','Absence from available scope does not prove nonexistence on user machine or elsewhere.']}
 return result
if __name__=='__main__':
 manifest=json.loads(Path(sys.argv[1]).read_text());r=audit(manifest);(D/'reports/inventory.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r['counts'],indent=2));print('UNREAD',r['errors_or_unread'])
