"""Offline size audit of a bounded, checksum-verified public build config.
No fetch, payload download, Agent interaction, arbitrary-field export or game IO.
"""
import hashlib,json,re,sys
from pathlib import Path
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'downloader'))
import target_metadata

def analyze(raw,expected_key,url):
 if type(raw)is not bytes or len(raw)>1048576:raise ValueError('size')
 target_metadata.key(expected_key);p=urlsplit(url)
 suffix='/tpr/wow/config/'+expected_key[:2]+'/'+expected_key[2:4]+'/'+expected_key
 if p.scheme!='https'or p.hostname!='level3.ssl.blizzard.com'or p.netloc!='level3.ssl.blizzard.com'or p.path!=suffix or p.query or p.fragment:raise ValueError('source')
 c=target_metadata.config(raw,expected_key)
 if c.get('build-uid')!=['wow']or len(c.get('build-name',[]))!=1 or re.fullmatch(r'WOW-[0-9]{1,10}patch[0-9.]{1,30}_Retail',c['build-name'][0])is None:raise ValueError('retail')
 manifests={}
 for name in ('encoding','download','install'):
  keys=c.get(name);sizes=c.get(name+'-size')
  if type(keys)is not list or len(keys)!=2 or any(target_metadata.key(k)!=k for k in keys):raise ValueError('keys')
  if type(sizes)is not list or len(sizes)!=2 or any(re.fullmatch('[0-9]{1,16}',n)is None or not 0<int(n)<=2**50 for n in sizes):raise ValueError('sizes')
  manifests[name]=dict(content_key=keys[0],encoding_key=keys[1],decoded_bytes=int(sizes[0]),encoded_bytes=int(sizes[1]))
 return dict(schema='bnet-public-manifest-budget-1',config_url=url,build_config=expected_key,build_name=c['build-name'][0],config_bytes=len(raw),config_md5_verified=True,config_sha256=hashlib.sha256(raw).hexdigest(),manifests=manifests,phase_threshold_bytes=67108864,encoding_object_exceeds_phase_threshold=manifests['encoding']['encoded_bytes']>67108864,comparison_condition='only_if_entire_object_needed_within_armed_phase',actual_agent_object_transfer_identified=False,game_payload_requested=False,guard_limits_changed=False)

if __name__=='__main__':
 key='d718abcc42604d8efbd35aecfa5bb75b';url='https://level3.ssl.blizzard.com/tpr/wow/config/d7/18/'+key
 r=analyze(Path(sys.argv[1]).read_bytes(),key,url);p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
