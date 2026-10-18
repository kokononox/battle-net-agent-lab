"""Version-independent WoW Retail release identity; NO asset download or installer.

The pure resolver consumes bounded official-table bytes. HTTPS transport below is
restricted to the two official release-table URLs, not game/CDN payload objects.
"""
from dataclasses import dataclass,asdict
import hashlib,json,re,datetime,urllib.request
from urllib.parse import urlsplit,parse_qsl
from installed_identity import validate as validate_installed
CAP=4*1024*1024
KEY=re.compile(r'[0-9a-f]{32}')
VER=re.compile(r'[0-9]{1,10}(?:\.[0-9]{1,10}){3}')
REGIONS=frozenset(('eu','us','kr','tw','cn'))
VERSIONS_URL='https://us.version.battle.net/v2/products/wow/versions'
CDNS_URL='https://us.version.battle.net/v2/products/wow/cdns'
class InvalidRelease(ValueError):pass
def need(ok,msg):
 if not ok:raise InvalidRelease(msg)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def ck(v):need(type(v)is str and KEY.fullmatch(v),'invalid_key');return v
def version(v):need(type(v)is str and VER.fullmatch(v),'invalid_version');return tuple(map(int,v.split('.')))
def sha(v):need(type(v)is str and re.fullmatch('[0-9a-f]{64}',v),'invalid_sha256');return v
def strict_json(raw):
 need(type(raw)is bytes and 0<len(raw)<=65536,'checkpoint_size')
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate_json_key');d[k]=v
  return d
 try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite_json'))
 except (UnicodeError,json.JSONDecodeError):raise InvalidRelease('invalid_json') from None

def table(raw):
 need(type(raw)is bytes and 0<len(raw)<=CAP,'table_size')
 try:lines=[l.strip() for l in raw.decode('utf-8-sig').splitlines() if l.strip() and not l.lstrip().startswith('#')]
 except UnicodeError:raise InvalidRelease('table_encoding') from None
 need(2<=len(lines)<=10000,'table_rows');cols=[v.split('!',1)[0] for v in lines[0].split('|')]
 need(1<=len(cols)<=256 and len(set(cols))==len(cols) and all(re.fullmatch('[A-Za-z][A-Za-z0-9_ ]{0,63}',v) for v in cols),'table_header')
 out=[]
 for line in lines[1:]:
  vals=line.split('|');need(len(vals)==len(cols),'table_row_width');out.append(dict(zip(cols,vals)))
 return out

def only(rows,col,value):
 matches=[r for r in rows if r.get(col)==value];need(len(matches)==1,'scope_row_missing_or_ambiguous');return matches[0]

@dataclass(frozen=True)
class Scope:
 product:str='wow'
 branch:str='retail'
 region:str='eu'
 def __post_init__(self):need(self.product=='wow' and self.branch=='retail' and self.region in REGIONS,'unsupported_scope')

def advertised_origins(row):
 need(row.get('Path')=='tpr/wow','cdn_product_path');origins=[]
 for value in row.get('Servers','').split():
  try:
   p=urlsplit(value);port=p.port;hints=parse_qsl(p.query,keep_blank_values=True,strict_parsing=True);host=p.hostname or ''
  except ValueError:continue
  if len(dict(hints))!=len(hints) or any(not ((k=='maxhosts' and re.fullmatch('[0-9]{1,2}',v) and 1<=int(v)<=64) or (k=='fallback' and v in ('0','1'))) for k,v in hints):continue
  if p.scheme!='https' or p.username or p.password or port not in (None,443) or p.path not in ('','/') or p.fragment:continue
  if not re.fullmatch('[a-zA-Z0-9.-]+',host) or '.' not in host or host.replace('.','').isdigit() or host.lower().endswith(('.local','.localhost')):continue
  origin='https://'+host.lower()
  if origin not in origins:origins.append(origin)
 need(bool(origins),'no_supported_advertised_https_origin');return tuple(origins)

@dataclass(frozen=True)
class TargetSnapshot:
 scope:Scope
 version:str
 build_id:int
 build_config:str
 cdn_config:str
 origins:tuple
 versions_sha256:str
 cdns_sha256:str
 def __post_init__(self):
  need(type(self.scope)is Scope,'scope_type');parts=version(self.version);need(type(self.build_id)is int and self.build_id==parts[-1] and self.build_id>0,'version_build_conflict');ck(self.build_config);ck(self.cdn_config);sha(self.versions_sha256);sha(self.cdns_sha256)
  need(type(self.origins)is tuple and 1<=len(self.origins)<=64,'origin_count')
  for o in self.origins:
   need(type(o)is str and len(o)<=512,'origin_type');need(advertised_origins({'Path':'tpr/wow','Servers':o})==(o,),'invalid_pinned_origin')
 def identity(self):return (self.scope.product,self.scope.branch,self.scope.region,self.version,self.build_id,self.build_config,self.cdn_config)
 def public(self):
  d=asdict(self);d['origins']=list(self.origins);return d
 @classmethod
 def restore(cls,d):
  need(type(d)is dict and set(d)=={'scope','version','build_id','build_config','cdn_config','origins','versions_sha256','cdns_sha256'},'target_shape');d=dict(d);need(type(d['scope'])is dict and set(d['scope'])=={'product','branch','region'},'scope_shape');d['scope']=Scope(**d['scope']);need(type(d['origins'])is list,'origins_shape');d['origins']=tuple(d['origins']);return cls(**d)

def resolve(versions_raw,cdns_raw,scope):
 need(type(scope)is Scope,'scope_type');v=only(table(versions_raw),'Region',scope.region);c=only(table(cdns_raw),'Name',scope.region)
 name=v.get('VersionsName','');parts=version(name);bid=v.get('BuildId','');need(re.fullmatch('[0-9]{1,10}',bid) and int(bid)==parts[-1],'version_build_conflict')
 return TargetSnapshot(scope,name,int(bid),ck(v.get('BuildConfig')),ck(v.get('CDNConfig')),advertised_origins(c),digest(versions_raw),digest(cdns_raw))

@dataclass(frozen=True)
class Baseline:
 scope:Scope
 version:str
 build_config:str
 info_sha256:str
 config_sha256:str
 def __post_init__(self):need(type(self.scope)is Scope,'baseline_scope');version(self.version);ck(self.build_config);sha(self.info_sha256);sha(self.config_sha256)
 def public(self):return asdict(self)
 @classmethod
 def restore(cls,d):
  need(type(d)is dict and set(d)=={'scope','version','build_config','info_sha256','config_sha256'},'baseline_shape');d=dict(d);need(type(d['scope'])is dict and set(d['scope'])=={'product','branch','region'},'scope_shape');d['scope']=Scope(**d['scope']);return cls(**d)

def read_baseline_bytes(info,config,scope):
 need(type(scope)is Scope,'scope_type');r=validate_installed(info,config);need(r['profile_from_uploaded_metadata']['region'].lower()==scope.region,'installed_region_conflict')
 return Baseline(scope,r['installed_version_from_uploaded_metadata'],r['installed_build_config_md5'],r['build_info_sha256'],r['build_config_sha256'])

def decision(baseline,target):
 need(type(baseline)is Baseline and type(target)is TargetSnapshot,'identity_types');need(baseline.scope==target.scope,'baseline_target_scope_conflict')
 old=version(baseline.version);new=version(target.version)
 if target.build_config==baseline.build_config:
  need(target.version==baseline.version,'same_build_key_version_conflict');return 'up_to_date_metadata_only'
 if new[-1]<old[-1] or new[:3]<old[:3]:return 'downgrade_blocked'
 if new[-1]==old[-1]:return 'same_build_republication_requires_review'
 return 'new_release_detected'

@dataclass(frozen=True)
class RunCheckpoint:
 baseline:Baseline
 target:TargetSnapshot
 def __post_init__(self):need(decision(self.baseline,self.target)=='new_release_detected','checkpoint_requires_new_release')
 def serialize(self):return (json.dumps({'format':'dynamic-release-checkpoint-1','baseline':self.baseline.public(),'target':self.target.public()},sort_keys=True,separators=(',',':'))+'\n').encode()
 @classmethod
 def restore(cls,raw):
  d=strict_json(raw);need(type(d)is dict and set(d)=={'format','baseline','target'} and d['format']=='dynamic-release-checkpoint-1','checkpoint_format');return cls(Baseline.restore(d['baseline']),TargetSnapshot.restore(d['target']))
 def resume(self,current_baseline,latest=None):
  need(type(current_baseline)is Baseline and current_baseline==self.baseline,'baseline_changed_replan_required')
  if latest is not None:need(type(latest)is TargetSnapshot and latest.scope==self.target.scope,'latest_scope_conflict')
  return {'status':'resume_original_pinned_target','pinned_target':self.target.public(),'different_release_advertised':latest is not None and latest.identity()!=self.target.identity(),'target_automatically_replaced':False,'game_content_resume_implemented':False,'installation_ready':False}

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):raise InvalidRelease('metadata_redirect_not_allowed')
class OfficialTableTransport:
 """Metadata-only HTTPS, fixed allowlist, maximum 8 MiB across two tables."""
 def __init__(self):self.requests=0;self.bytes_read=0
 def fetch(self,url):
  need(url in (VERSIONS_URL,CDNS_URL),'url_not_release_table');need(self.requests<2,'table_request_budget');self.requests+=1
  opener=urllib.request.build_opener(NoRedirect);req=urllib.request.Request(url,headers={'User-Agent':'WoW-Updater-Metadata-Research/0.5','Accept-Encoding':'identity'})
  with opener.open(req,timeout=30) as r:
   need(r.status==200 and r.geturl()==url and not r.headers.get('Content-Range') and r.headers.get('Content-Encoding','identity').lower() in ('','identity'),'response_invalid')
   length=r.headers.get('Content-Length');need(length is None or (re.fullmatch('[0-9]+',length) and int(length)<=CAP),'response_size')
   data=r.read(CAP+1);need(0<len(data)<=CAP and (length is None or len(data)==int(length)),'response_truncated_or_large');self.bytes_read+=len(data);return data

def metadata_report(baseline,target,source):
 return {'format':'dynamic-release-observation-1','source':source,'baseline':baseline.public(),'target':target.public(),'decision':decision(baseline,target),'installed_copies_are_not_live_snapshot':True,'target_build_config_fetched_and_verified':False,'target_manifests_fetched':False,'publisher_manifest_signature_verified':False,'vendor_required_set_proven':False,'required_download_bytes':None,'asset_requests':0,'game_files_read':0,'game_files_written':0,'installation_ready':False,'apply_authorized':False}
