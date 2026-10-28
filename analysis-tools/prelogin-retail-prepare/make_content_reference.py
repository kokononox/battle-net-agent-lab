"""Offline extraction from independently fetched small public config/IN manifest.
No network, game-file reads/writes, or executable output. IN format: wowdev TACT.
"""
import hashlib,io,json,struct,sys,threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'downloader'))
import target_metadata,decoded_payload
ALLOWED={'utils/wowvoiceproxy.exe':'voice_proxy','utils/wowwindowsexceptionhandler.dll':'exception_handler','wow.exe':'client_executable','wow_loader.dll':'client_loader'}

def parse(data):
 if type(data)is not bytes or not 10<=len(data)<=1048576 or data[:4]!=b'IN\x01\x10':raise ValueError('header')
 tags,entries=struct.unpack_from('>HI',data,4)
 if not 0<tags<=128 or not 0<entries<=4096:raise ValueError('counts')
 pos=10
 def take(n):
  nonlocal pos
  if n<0 or pos+n>len(data):raise ValueError('bounds')
  b=data[pos:pos+n];pos+=n;return b
 def string():
  nonlocal pos
  end=data.find(b'\0',pos,min(len(data),pos+512))
  if end<0:raise ValueError('string')
  b=take(end-pos);take(1);return b.decode('utf-8')
 for _ in range(tags):string();take(2+(entries+7)//8)
 matches={k:[]for k in ALLOWED.values()}
 for _ in range(entries):
  name=string().replace('\\','/').casefold();key=take(16).hex();size=int.from_bytes(take(4),'big')
  if name in ALLOWED and 0<size<=128*1024**2:
   entry=dict(ckey=key,size=size)
   if entry not in matches[ALLOWED[name]]:matches[ALLOWED[name]].append(entry)
 if pos!=len(data)or any(not v or len(v)>4 for v in matches.values()):raise ValueError('entries')
 return matches

def build(config,encoded,build_key):
 c=target_metadata.config(config,build_key)
 if c.get('build-uid')!=['wow']or c.get('build-name')!=['WOW-70575patch12.1.5_Retail']:raise ValueError('target')
 ck,ek=c['install'];ds,es=map(int,c['install-size'])
 if not 0<ds<=1048576 or not 0<es<=1048576 or len(encoded)!=es:raise ValueError('limit')
 sink=io.BytesIO();proof=decoded_payload.extract(io.BytesIO(encoded),es,ds,bytes.fromhex(ck),bytes.fromhex(ek),threading.Event(),sink)
 if proof['status']!='content_verified':raise ValueError('manifest_integrity')
 return dict(schema='bnet-retail-content-reference-1',build_config=build_key,version='12.1.5.70575',install_ckey=ck,install_ekey=ek,install_encoded_bytes=es,install_decoded_bytes=ds,install_full_ekey_and_ckey_verified=True,components=parse(sink.getvalue()),source_config_url='https://level3.ssl.blizzard.com/tpr/wow/config/'+build_key[:2]+'/'+build_key[2:4]+'/'+build_key,source_install_url='https://level3.ssl.blizzard.com/tpr/wow/data/'+ek[:2]+'/'+ek[2:4]+'/'+ek,install_policy_tags_applied=False)
if __name__=='__main__':
 r=build(Path(sys.argv[1]).read_bytes(),Path(sys.argv[2]).read_bytes(),'d718abcc42604d8efbd35aecfa5bb75b');Path(sys.argv[3]).write_text(json.dumps(r,indent=2)+'\n')
