"""Bind dynamic release to two small config objects, never metadata/game data blobs."""
from dataclasses import dataclass,asdict
import hashlib,re,urllib.request
from release_core import InvalidRelease,need,ck,version,CAP,TargetSnapshot,NoRedirect,digest

def config(raw,expected):
 ck(expected);need(type(raw)is bytes and 0<len(raw)<=CAP and hashlib.md5(raw).hexdigest()==expected,'config_identity_conflict')
 try:lines=raw.decode('utf-8-sig').splitlines()
 except UnicodeError:raise InvalidRelease('config_encoding') from None
 fields={}
 for line in lines:
  if not line.strip() or line.lstrip().startswith('#'):continue
  need('=' in line,'config_syntax');k,v=line.split('=',1);k=k.strip();need(re.fullmatch('[A-Za-z0-9_-]{1,80}',k) and k not in fields,'config_duplicate_or_invalid_field');fields[k]=v.split()
 return fields

@dataclass(frozen=True)
class ManifestDescriptor:
 name:str
 ckey:str
 ekey:str
 decoded_size:int
 encoded_size:int
 def __post_init__(self):
  need(self.name in ('install','download','encoding'),'unsupported_manifest');ck(self.ckey);ck(self.ekey);need(type(self.decoded_size)is int and type(self.encoded_size)is int and 0<self.decoded_size<=512*1024**2 and 0<self.encoded_size<=512*1024**2,'manifest_size_limit')
 def public(self):return asdict(self)

def descriptor(build,name):
 need(name in ('install','download','encoding'),'unsupported_manifest');keys=build.get(name,[]);sizes=build.get(name+'-size',[])
 need(len(keys)==2,'manifest_requires_full_key_pair_or_future_encoding_lookup');need(len(sizes)==2 and all(re.fullmatch('[0-9]{1,12}',s) for s in sizes),'manifest_size_pair')
 return ManifestDescriptor(name,keys[0],keys[1],int(sizes[0]),int(sizes[1]))

def bind(target,raw_build,raw_cdn):
 need(type(target)is TargetSnapshot,'target_type');build=config(raw_build,target.build_config);cdn=config(raw_cdn,target.cdn_config)
 expected='WOW-'+str(target.build_id)+'patch'+target.version.rsplit('.',1)[0]+'_Retail'
 need(build.get('build-uid')==['wow'] and build.get('build-name')==[expected],'target_build_name_conflict')
 if 'builds' in cdn:
  need(all(type(s)is str and re.fullmatch('[0-9a-f]{32}',s) for s in cdn['builds']) and target.build_config in cdn['builds'],'cdn_build_membership_conflict')
 specs=tuple(descriptor(build,n) for n in ('install','download','encoding'))
 return {'format':'dynamic-config-binding-1','target':target.public(),'build_config_md5_verified':True,'cdn_config_md5_verified':True,'build_config_sha256':digest(raw_build),'cdn_config_sha256':digest(raw_cdn),'build_config_bytes':len(raw_build),'cdn_config_bytes':len(raw_cdn),'cdn_explicit_build_membership_checked':'builds' in cdn,'manifest_descriptors':[s.public() for s in specs],'manifest_blobs_fetched':False,'game_assets_fetched':0,'vendor_required_set_proven':False,'publisher_signature_verified':False,'installation_ready':False,'apply_authorized':False}

def config_urls(target):
 need(type(target)is TargetSnapshot,'target_type')
 return tuple(target.origins[0]+'/tpr/wow/config/'+k[:2]+'/'+k[2:4]+'/'+k for k in (target.build_config,target.cdn_config))
class ConfigTransport:
 """Two exact, already-resolved config URLs only; no /data/ payload access."""
 def __init__(self,target):self.allowed=config_urls(target);self.requested=set();self.bytes_read=0
 def fetch(self,url):
  need(url in self.allowed and url not in self.requested,'config_request_not_allowed');self.requested.add(url)
  req=urllib.request.Request(url,headers={'User-Agent':'WoW-Updater-Metadata-Research/0.5','Accept-Encoding':'identity'})
  with urllib.request.build_opener(NoRedirect).open(req,timeout=30) as r:
   need(r.status==200 and r.geturl()==url and not r.headers.get('Content-Range') and r.headers.get('Content-Encoding','identity').lower() in ('','identity'),'config_response_invalid');length=r.headers.get('Content-Length');need(length is None or (re.fullmatch('[0-9]+',length) and int(length)<=CAP),'config_response_size');raw=r.read(CAP+1);need(0<len(raw)<=CAP and (length is None or len(raw)==int(length)),'config_response_truncated_or_large');self.bytes_read+=len(raw);return raw
