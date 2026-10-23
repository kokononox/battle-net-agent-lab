"""Hash-pinned offline debug-identity/export inventory. No PE is executed."""
import argparse,hashlib,json,struct,uuid
from pathlib import Path
import pefile
SHA='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
def audit(path):
 b=Path(path).read_bytes();assert hashlib.sha256(b).hexdigest()==SHA,'Wrong input build'
 pe=pefile.PE(data=b,fast_load=True);pe.parse_data_directories(directories=[6,0])
 r={'source_sha256':SHA,'codeview':[],'exports':[],'input_executed':False,'claims':{'hardware_population_recovered':False,'serialization_path_recovered':False,'network_send_proven':False,'pdb_available_proven':False}}
 for d in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
  if d.struct.Type!=2:continue
  start=d.struct.PointerToRawData;size=d.struct.SizeOfData;assert 0<size<=65536 and start+size<=len(b)
  raw=b[start:start+size];e={'signature':raw[:4].decode('ascii',errors='replace'),'debug_entry_file_offset':d.struct.get_file_offset(),'data_file_offset':start,'data_size':size}
  if raw.startswith(b'RSDS'):
   assert len(raw)>=25 and b'\0' in raw[24:]
   e.update(guid=str(uuid.UUID(bytes_le=raw[4:20])).upper(),age=struct.unpack_from('<I',raw,20)[0],pdb_path=raw[24:].split(b'\0',1)[0].decode('utf-8'))
  r['codeview'].append(e)
 for x in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[]):
  r['exports'].append({'name':x.name.decode() if x.name else None,'rva':hex(x.address)})
 return r
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('input');a.add_argument('output');v=a.parse_args();Path(v.output).write_text(json.dumps(audit(v.input),indent=2)+'\n')
