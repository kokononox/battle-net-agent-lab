"""Independent struct/section based verifier, no pefile and no input execution."""
import argparse,copy,hashlib,json,struct,uuid
from pathlib import Path
from pe_manual import PE
SHA='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
def verify(path,r):
 p=PE(Path(path));b=p.b;assert hashlib.sha256(b).hexdigest()==SHA==r['source_sha256']
 assert r['input_executed'] is False and r['claims']=={k:False for k in ['hardware_population_recovered','serialization_path_recovered','network_send_proven','pdb_available_proven']}
 start,size=p.dirs[6];assert size%28==0;out=[]
 for i in range(size//28):
  at=start+28*i;row=struct.unpack('<IIHHIIII',p.read(at,28));typ,sz,raw_rva,raw_off=row[4:]
  if typ!=2:continue
  assert 0<sz<=65536 and p.loc(raw_rva,sz)['file_offset']==raw_off
  raw=p.read(raw_rva,sz);e={'signature':raw[:4].decode(),'debug_entry_file_offset':p.loc(at,28)['file_offset'],'data_file_offset':raw_off,'data_size':sz}
  if raw[:4]==b'RSDS':
   assert len(raw)>=25 and b'\0' in raw[24:]
   e.update(guid=str(uuid.UUID(bytes_le=raw[4:20])).upper(),age=struct.unpack_from('<I',raw,20)[0],pdb_path=raw[24:].split(b'\0',1)[0].decode())
  out.append(e)
 assert out==r['codeview'],'debug identity mismatch'
 start,_=p.dirs[0];raw=p.read(start,40);nfunc,nnames,funcs,names,ords=struct.unpack_from('<IIIII',raw,20);assert nnames<=nfunc<=4096
 exports=[]
 for i in range(nnames):
  ordinal=p.u(ords+2*i,'<H');assert ordinal<nfunc
  exports.append({'name':p.text(p.u(names+4*i,'<I')),'rva':hex(p.u(funcs+4*ordinal,'<I'))})
 assert sorted(exports,key=lambda x:x['name'])==sorted(r['exports'],key=lambda x:x['name'])
 return {'accepted':True,'independent_PE_reader':'struct/sections, no pefile','codeview_records':len(out),'export_names_matched':len(exports),'scope':'report byte consistency only; not runtime, PDB availability or recovered hardware behavior'}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('input');a.add_argument('report');a.add_argument('output');v=a.parse_args();r=json.loads(Path(v.report).read_text());q=verify(v.input,r)
 changes=[]
 for kind in ['guid','age','offset','export','send_claim','availability_claim']:
  bad=copy.deepcopy(r)
  if kind=='guid':bad['codeview'][0]['guid']='00000000-0000-0000-0000-000000000000'
  elif kind=='age':bad['codeview'][0]['age']+=1
  elif kind=='offset':bad['codeview'][0]['data_file_offset']+=1
  elif kind=='export':bad['exports'][0]['rva']='0x0'
  elif kind=='send_claim':bad['claims']['network_send_proven']=True
  else:bad['claims']['pdb_available_proven']=True
  rejected=False
  try:verify(v.input,bad)
  except (AssertionError,ValueError,KeyError):rejected=True
  assert rejected,kind;changes.append(kind)
 q['mutations_rejected']=changes;Path(v.output).write_text(json.dumps(q,indent=2)+'\n');print(json.dumps(q))
