"""Read all ZIP members with bounded sizes; publish no account paths or raw values."""
from pathlib import Path
import os,zipfile,hashlib,json,re,collections
D=Path(__file__).resolve().parents[1];Z=Path(os.environ.get('ARCHIVE','_retail_a.zip'))
(D/'reports').mkdir(exist_ok=True);(D/'work').mkdir(exist_ok=True)
def sha(b):return hashlib.sha256(b).hexdigest()
manifest=[];logrows=[];binary=[];exts=collections.Counter();groups=collections.Counter();total=0;texts={}
magiclist={'minidump':b'MDMP','PE_DOS':b'MZ','ELF':b'\x7fELF','zip':b'PK\x03\x04','pcapng':bytes.fromhex('0a0d0d0a'),'pcap_le':bytes.fromhex('d4c3b2a1'),'pcap_be':bytes.fromhex('a1b2c3d4'),'PDB':b'Microsoft C/C++ MSF'}
with zipfile.ZipFile(Z) as z:
 members=z.infolist();assert len(members)<10000 and len({m.filename for m in members})==len(members)
 assert sum(m.file_size for m in members)<512*1024*1024
 for idx,m in enumerate(members):
  assert not m.flag_bits&1 and m.file_size<128*1024*1024
  b=z.read(m);assert len(b)==m.file_size;total+=len(b)
  group=m.filename.split('/')[0];groups[group]+=1
  ext=Path(m.filename).suffix.lower() if not m.is_dir() else '<directory>';exts[ext]+=1
  signatures=[label for label,magic in magiclist.items() if b.startswith(magic)]
  manifest.append({'entry_index':idx,'path_sha256':sha(m.filename.encode()),'top_level':group,'directory':m.is_dir(),'extension':ext,'size_bytes':len(b),'sha256':sha(b),'initial_signatures':signatures})
  if signatures:binary.append({'entry_index':idx,'safe_name':m.filename if group=='D3D12' else '<private-path>','signatures':signatures,'size_bytes':len(b)})
  if group=='Logs' and not m.is_dir():
   text=b.decode('utf-8-sig',errors='replace');texts[m.filename]=text
   pats={'bios':r'\bbios\b','smbios':r'\bsmbios\b','client_engine_log':r'ClientEngineLog','warden':r'\bwarden\b','port_literal_3724':r'(?<!\d)3724(?!\d)','serialize_word':r'serializ','telemetry_word':r'telemetry'}
   logrows.append({'name':m.filename,'sha256':sha(b),'size_bytes':len(b),'lines':len(text.splitlines()),'keyword_line_numbers':{k:[i for i,l in enumerate(text.splitlines(),1) if re.search(p,l,re.I)] for k,p in pats.items()}})
 gx=texts['Logs/gx.log'].splitlines();cpu=texts['Logs/cpu.log'].splitlines()
 assert '12.1.5.70448' in gx[2] and 'Motherboard:' in gx[9] and all(x in gx[9] for x in ['BIOS:','version:','date:'])
 assert all(any(k in l for l in cpu) for k in ['vendor:','branding:','features:','sockets:','cores:','threads:'])
 findings={'gx_version':{'file':'Logs/gx.log','line':3,'version':'12.1.5.70448'},'cpu_local_fields':{'file':'Logs/cpu.log','lines':[1,2,3,4,5,6],'fields':['vendor','branding','features','sockets','cores','threads'],'raw_values_published':False},'gx_cpu_fields':{'file':'Logs/gx.log','lines':[5,6,7,8,9],'fields':['cpu_model','sockets','cores','threads','hybrid','frequency','vendor','microcode','family','model','stepping','features']},'gx_motherboard_bios_fields':{'file':'Logs/gx.log','line':10,'redacted_shape':'Motherboard: <model> by <manufacturer> (BIOS:<vendor> version:<version> date:<date>)','serial_number_or_uuid_on_this_line':False},'network_log_scope':{'files':['Logs/Connection.log','Logs/WowConnection.log'],'port_literal_3724_present':False,'payload_or_hardware_field_send_demonstrated':False},'time_caveat':'cpu.log dates are 10/20; gx and connection logs are 10/23 without timezone/year on each line. Do not join them or previous crash events into a single proven session.'}
result={'archive_sha256':sha(Z.read_bytes()),'archive_bytes':Z.stat().st_size,'member_count':len(manifest),'file_count':sum(not x['directory'] for x in manifest),'uncompressed_bytes_read':total,'top_level_entry_counts':dict(groups),'extensions':dict(exts),'initial_signature_matches':binary,'runtime_artifact_extensions':[x for x in manifest if x['extension'] in ['.dmp','.etl','.pdb','.pcap','.pcapng','.exe']],'logs':logrows,'findings':findings,'members':manifest,'limits':'Initial file signatures and names classify artifacts, not arbitrary embedded data. All members read and hashed, only Logs interpreted for hardware/connection findings; SavedVariables Lua not executed.'}
(D/'reports/inventory.json').write_text(json.dumps(result,indent=2)+'\n')
print('members',len(manifest),'files',result['file_count'],'bytes',total,'magic matches',binary,'runtime extensions',len(result['runtime_artifact_extensions']))
print('BIOS local fields verified; connection logs 3724 absent:',not any(re.search(r'(?<!\d)3724(?!\d)',texts[n]) for n in findings['network_log_scope']['files']))
