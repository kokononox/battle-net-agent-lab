"""Read only fresh vendor log candidates; publish fixed classes/codes, never raw lines."""
import os,re,time
from pathlib import Path
TARGETS={'level3.blizzard.com','us.version.battle.net'}
PHRASES={
 'dns_resolution':('resolve host','resolve name','name resolution','getaddrinfo','dns'),
 'network_unreachable':('network is unreachable','network unreachable','no network','not connected to','internet connection'),
 'connection_failure':('connection failed','connect failed','failed to connect','connection refused','could not connect'),
 'timeout':('timed out','timeout'),
 'proxy':('proxy',), 'certificate':('certificate','cert verify','schannel'),
 'permission_denied':('access denied','access is denied','permission denied'),
 'file_missing':('file not found','cannot find the file','path not found','cannot find the path'),
 'file_creation':('createfile','create file','create directory','createdirectory','mkdir'),
 'process_launch':('createprocess','launch process','launch agent','start agent','spawn'),
 'extraction':('extract','decompress','unpack'),
 'signature':('signature','authenticode','winverifytrust'),
 'wininet':('wininet',), 'winhttp':('winhttp',),
 'http_error':('http error','http status','status code'),
 'agent':('agent',), 'bootstrap':('bootstrap','setup'),
 'download':('download',),'unsupported_os':('unsupported operating','unsupported os','operating system not supported'),
 'service':('service',), 'fatal':('fatal','critical'),
}
CODE=re.compile(r'\bBLZ[A-Z0-9]{4,40}\b',re.I)
HEX=re.compile(r'(?i)\b(?:error(?:code| code)?|hresult|status(?:code| code)?)\s*[:=\[(]\s*(0x[0-9a-f]{8})\b')
NUMBER=re.compile(r'(?i)\b(error(?:code| code)?|errno|hresult|win32(?:error| error)?|status(?:code| code)?)\s*[:=\[(]\s*(-?\d{1,10})\b')
def classify_line(line):
 low=line.lower()
 codes=sorted(set(x.upper() for x in CODE.findall(line)))
 if not codes and not re.search(r'(?i)\b(error|failed|failure|fatal|critical|warning|warn)\b',line):return None
 classes=sorted(k for k,phrases in PHRASES.items() if any(x in low for x in phrases))
 # Numeric diagnostics are accepted only from explicit named error/status assignments.
 nums=sorted(set((m.group(1).lower().replace(' ',''),int(m.group(2))) for m in NUMBER.finditer(line)))[:12]
 return {'classes':classes,'blizzard_error_codes':codes[:8],'hex_error_tokens':sorted(set(HEX.findall(line)))[:8],
         'named_numeric_diagnostics':[{'field':k,'value':v} for k,v in nums],
         'approved_host_mentions':sorted(h for h in TARGETS if h in low),'raw_line_exported':False}
def roots():
 result=[]
 for env in ('PROGRAMDATA','LOCALAPPDATA','APPDATA'):
  if os.environ.get(env):
   for vendor in ('Battle.net','Blizzard Entertainment'):result.append((env+'_'+vendor,Path(os.environ[env])/vendor,5,False))
 if os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_TEMP'):result.append(('bootstrap_private',Path(os.environ['RUNNER_TEMP'])/'g68-private',4,False))
 if os.environ.get('TEMP'):result.append(('TEMP_vendor_candidates',Path(os.environ['TEMP']),3,True))
 return result

def candidates():
 seen=set();result=[];walked=0;limited=False
 for role,root,depth,temp in roots():
  if not root.is_dir():continue
  for base,dirs,files in os.walk(root,followlinks=False):
   walked+=1
   if walked>400:limited=True;break
   rel=Path(base).relative_to(root);level=len(rel.parts)
   dirs[:]=[x for x in sorted(dirs) if not (Path(base)/x).is_symlink() and not ((Path(base)/x).stat().st_file_attributes & 0x400 if hasattr((Path(base)/x).stat(),'st_file_attributes') else False)] if level<depth else []
   if temp and level==0:dirs[:]=[x for x in dirs if any(y in x.lower() for y in ('battle','blizzard','bnet'))]
   for name in sorted(files):
    p=Path(base)/name
    if p.suffix.lower() not in ('.log','.txt'):continue
    if temp and level==0 and not any(y in name.lower() for y in ('battle','blizzard','bnet')):continue
    if p.is_symlink():continue
    try:
     st=p.stat()
     if hasattr(st,'st_file_attributes') and st.st_file_attributes&0x400:continue
     key=str(p.resolve()).lower()
     if key not in seen:result.append((role,p,st));seen.add(key)
    except OSError:continue
    if len(result)>=64:limited=True;break
   if limited:break
  if limited:break
 return result,limited

def baseline():
 rows,limited=candidates();return {str(p): (s.st_mtime_ns,s.st_size) for _,p,s in rows}
def collect(before,started):
 rows,limited=candidates();out=[];total=0;errors=0
 for role,p,st in rows:
  if before.get(str(p))==(st.st_mtime_ns,st.st_size) or st.st_mtime<started-2:continue
  if total>=2097152:limited=True;break
  n=min(st.st_size,262144,2097152-total)
  try:
   with p.open('rb') as f:
    if st.st_size>n:f.seek(st.st_size-n)
    b=f.read(n)
  except OSError:errors+=1;continue
  total+=len(b)
  # BOM/zero-byte patterns support Windows UTF-16 logs as well as UTF-8.
  enc='utf-16-le' if b.startswith(b'\xff\xfe') or b[:256].count(b'\x00')>len(b[:256])//4 else 'utf-8'
  text=b.decode(enc,errors='replace');events=[];skipped=0
  for line in text.splitlines():
   row=classify_line(line[:8192])
   if row is not None:
    if len(events)<80:events.append(row)
    else:skipped+=1
  out.append({'root_role':role,'file_kind':'log' if p.suffix.lower()=='.log' else 'txt','file_index':len(out)+1,'size_bytes':st.st_size,'read_bytes':len(b),'tail_only':st.st_size>n,'decode':enc,'diagnostic_rows':events,'additional_diagnostic_lines':skipped,'raw_path_exported':False,'raw_text_exported':False})
 return {'files':out,'candidate_cap_or_walk_limit':limited,'total_bytes_read':total,'read_errors':errors,'only_new_or_changed_since_baseline':True,'raw_paths_exported':False,'raw_lines_exported':False,'coverage_complete':False}
