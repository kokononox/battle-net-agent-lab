"""Reject deliberately corrupted reports; not tests of game behavior."""
from pathlib import Path
import argparse,json,subprocess,sys,tempfile,copy
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=Path('/data/raw/wow-retail-20261022/Wow.exe'));p.add_argument('--out',type=Path,default=Path(__file__).parent);a=p.parse_args();w=a.out
verify=Path(__file__).parent/'verify_message_layout.py';good=json.loads((w/'message-layout.json').read_text());cases=[]
x=copy.deepcopy(good);x['messages'][1]['fields'][0]['candidate_object_offset']='0x999';cases.append(('wrong_field_offset',x))
x=copy.deepcopy(good);x['messages'][1]['fields'][0]['candidate_hasbit_index']=97;cases.append(('wrong_presence_bit',x))
x=copy.deepcopy(good);x['selected_message_network_binding_proven']=True;cases.append(('unsupported_send_claim',x))
subprocess.run([sys.executable,str(verify),'--input',str(a.input),'--out',str(w)],check=True,stdout=subprocess.DEVNULL)
res=[]
for name,obj in cases:
 with tempfile.NamedTemporaryFile(mode='w',suffix='.json') as f:
  json.dump(obj,f);f.flush();r=subprocess.run([sys.executable,str(verify),'--input',str(a.input),'--out',str(w),'--report',f.name],capture_output=True)
  assert r.returncode!=0,name;res.append({'mutation':name,'rejected':True})
(w/'mutation-tests.json').write_text(json.dumps(res,indent=2)+'\n');print('Valid report accepted; all three corrupted reports rejected.')
