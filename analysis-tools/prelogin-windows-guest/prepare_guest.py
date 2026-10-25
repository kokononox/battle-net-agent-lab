"""One-shot ephemeral GitHub Linux preparation. No Windows boot or target launch.
Deletes only fixed unused tool directories; never follows symlinks or workspace.
Only allowlisted summary is exported, not media, disks, private logs or paths.
"""
import argparse,hashlib,json,os,re,shutil,socket,subprocess,sys,tempfile,time,urllib.request,xml.etree.ElementTree as ET
from pathlib import Path
ISO_URL='https://software-static.download.prss.microsoft.com/dbazure/998969d5-f34g-4e03-ac9d-1f9786c66749/26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso'
ISO_BYTES=8152356864
ISO_SHA256='7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51'
DISK_BYTES=64*1024**3
# Preparation only: ISO + extracted WIM + tools; no OS installation here.
MIN_FREE=32*1024**3
CLEANUP={'android':Path('/usr/local/lib/android'),'dotnet':Path('/usr/share/dotnet'),'ghcup':Path('/usr/local/.ghcup'),'ghc':Path('/opt/ghc'),'swift':Path('/usr/share/swift'),'codeql':Path('/opt/hostedtoolcache/CodeQL'),'powershell':Path('/usr/local/share/powershell')}
ERRORS={None,'capacity_insufficient','apt_failed','tool_missing','download_failed','media_size_mismatch','media_xml_failed','media_extract_failed','xml_command_failed','media_hash_mismatch','image_not_unique','qemu_failed','bounded_preparation_failed','guard_failed'}
LIMITS=dict(windows_guest_booted=False,windows_guest_reboot_tested=False,target_launched=False,host_rebooted=False,tls_validation_changed=False,device_permissions_changed=False,raw_identifiers_exported=False,private_logs_or_disks_exported=False)
def blank(source,run):
 return dict(schema='bnet-windows-guest-preparation-1',source_commit=source,run_id=run,status='stopped',error_code=None,cleanup_labels=[],disk_free_before_bytes=0,disk_free_after_cleanup_bytes=0,disk_free_final_bytes=0,apt_tools_installed=False,qemu_version=None,image=dict(url=ISO_URL,expected_bytes=ISO_BYTES,downloaded_bytes=0,sha256=None,download_complete=False,source_authentication='verified_https_microsoft_published_url_not_published_checksum',images=[],selected_index=None),disk=dict(format='qcow2',virtual_bytes=DISK_BYTES,created=False,actual_bytes=None,temporary_only=True),qemu=dict(qmp_responded=False,kvm_enabled=False,paused=False,disk_attached=False,iso_attached=False,clean_shutdown=False),limits=dict(LIMITS))

def number(x,hi=2**50):
 if type(x) is not int or not 0<=x<=hi:raise ValueError('number')
def boolean(x):
 if type(x) is not bool:raise ValueError('boolean')
def validate(r):
 if type(r) is not dict or set(r)!=set(blank('','')) or r['schema']!='bnet-windows-guest-preparation-1':raise ValueError('schema')
 if not isinstance(r['source_commit'],str) or not re.fullmatch('[a-f0-9]{40}',r['source_commit']):raise ValueError('source')
 if not isinstance(r['run_id'],str) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('run')
 if r['status'] not in ('stopped','prepared_paused_no_windows_boot') or r['error_code'] not in ERRORS:raise ValueError('status')
 if r['limits']!=LIMITS or any(type(v) is not bool for v in r['limits'].values()):raise ValueError('limits')
 if type(r['cleanup_labels']) is not list or len(r['cleanup_labels'])!=len(set(r['cleanup_labels'])) or not set(r['cleanup_labels'])<=set(CLEANUP):raise ValueError('cleanup')
 for k in ('disk_free_before_bytes','disk_free_after_cleanup_bytes','disk_free_final_bytes'):number(r[k])
 boolean(r['apt_tools_installed'])
 if r['qemu_version'] is not None and (not isinstance(r['qemu_version'],str) or not re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,3}){1,3}',r['qemu_version'])):raise ValueError('version')
 image=r['image'];template=blank('','')['image']
 if type(image) is not dict or set(image)!=set(template) or any(image[k]!=template[k] for k in ('url','expected_bytes','source_authentication')):raise ValueError('image')
 number(image['downloaded_bytes'],ISO_BYTES);boolean(image['download_complete'])
 if image['sha256'] is not None and (not isinstance(image['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',image['sha256'])):raise ValueError('media_hash')
 if image['download_complete'] and not(image['downloaded_bytes']==ISO_BYTES and image['sha256']):raise ValueError('download')
 if type(image['images']) is not list or len(image['images'])>16:raise ValueError('images')
 for x in image['images']:
  if type(x) is not dict or set(x)!={'index','architecture','edition','installation_type','build'}:raise ValueError('image_fields')
  number(x['index'],16);number(x['architecture'],20);number(x['build'],1000000)
  if x['edition'] not in ('ServerStandardEval','ServerDatacenterEval','unknown') or x['installation_type'] not in ('Server','Server Core','unknown'):raise ValueError('edition')
 if image['selected_index'] is not None:
  number(image['selected_index'],16)
  selected=[x for x in image['images'] if x['index']==image['selected_index'] and x['architecture']==9 and x['edition']=='ServerStandardEval' and x['installation_type']=='Server']
  if len(selected)!=1:raise ValueError('selection')
 d=r['disk'];t=blank('','')['disk']
 if type(d) is not dict or set(d)!=set(t) or d['format']!='qcow2' or d['virtual_bytes']!=DISK_BYTES or d['temporary_only'] is not True:raise ValueError('disk')
 boolean(d['created'])
 if d['actual_bytes'] is not None:number(d['actual_bytes'])
 if d['created'] and d['actual_bytes'] is None:raise ValueError('disk_size')
 q=r['qemu']
 if type(q) is not dict or set(q)!=set(blank('','')['qemu']):raise ValueError('qemu')
 for v in q.values():boolean(v)
 if r['status']=='prepared_paused_no_windows_boot':
  if not(r['error_code'] is None and r['disk_free_after_cleanup_bytes']>=MIN_FREE and r['apt_tools_installed'] and r['qemu_version'] and image['download_complete'] and image['selected_index'] is not None and d['created'] and all(q.values())):raise ValueError('ready_gate')
 return r

class ProbeError(Exception):pass

def guard():
 return sys.platform.startswith('linux') and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1' and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')=='refs/heads/research/prelogin-telemetry-wow-data-provenance' and os.environ.get('BNET_WINDOWS_PREP')=='owned-windows-prep-d3'

def safe_cleanup_path(label,path,workspace):
 return label in CLEANUP and path==CLEANUP[label] and path.is_dir() and not path.is_symlink() and path.resolve()==path and workspace!=path and path not in workspace.parents and workspace not in path.parents

def cleanup(r,workspace):
 r['disk_free_before_bytes']=shutil.disk_usage(workspace).free
 for label,path in CLEANUP.items():
  if shutil.disk_usage(workspace).free>=MIN_FREE:break
  if safe_cleanup_path(label,path,workspace):shutil.rmtree(path);r['cleanup_labels'].append(label)
 r['disk_free_after_cleanup_bytes']=shutil.disk_usage(workspace).free
 if r['disk_free_after_cleanup_bytes']<MIN_FREE:raise ProbeError('capacity_insufficient')

def command(argv,log,timeout=120,env=None):
 try:return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=log,timeout=timeout,check=True,env=env)
 except (OSError,subprocess.SubprocessError):raise ProbeError('bounded_preparation_failed')

class MicrosoftRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  from urllib.parse import urlsplit
  p=urlsplit(newurl)
  if p.scheme!='https' or not p.hostname or not(p.hostname=='microsoft.com' or p.hostname.endswith('.microsoft.com')):raise ProbeError('download_failed')
  return super().redirect_request(req,fp,code,msg,headers,newurl)

def download(dest,r):
 opener=urllib.request.build_opener(MicrosoftRedirect());total=0;digest=hashlib.sha256();started=time.monotonic()
 try:
  with opener.open(urllib.request.Request(ISO_URL,headers={'User-Agent':'BattleNetAgentLab-Research-MediaPreparation/1.0'}),timeout=60) as response, dest.open('xb') as out:
   if response.status!=200:raise ProbeError('download_failed')
   length=response.headers.get('Content-Length')
   if length is not None and int(length)!=ISO_BYTES:raise ProbeError('media_size_mismatch')
   while True:
    chunk=response.read(1024*1024)
    if not chunk:break
    total+=len(chunk)
    if total>ISO_BYTES or time.monotonic()-started>720:raise ProbeError('download_failed')
    out.write(chunk);digest.update(chunk);r['image']['downloaded_bytes']=total
  if total!=ISO_BYTES:raise ProbeError('media_size_mismatch')
  if digest.hexdigest()!=ISO_SHA256:raise ProbeError('media_hash_mismatch')
  r['image'].update(downloaded_bytes=total,sha256=digest.hexdigest(),download_complete=True)
 except ProbeError:raise
 except (OSError,ValueError):raise ProbeError('download_failed')

def image_metadata(raw):
 if len(raw)>1048576:raise ProbeError('media_xml_failed')
 try:
  text=raw.decode('utf-16') if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else raw.decode('utf-8-sig')
  if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():raise ProbeError('media_xml_failed')
  root=ET.fromstring(text)
 except (ET.ParseError,UnicodeError):raise ProbeError('media_xml_failed')
 images=[]
 for node in root.findall('IMAGE'):
  try:
   edition=node.findtext('WINDOWS/EDITIONID','unknown');installation=node.findtext('WINDOWS/INSTALLATIONTYPE','unknown')
   images.append(dict(index=int(node.attrib['INDEX']),architecture=int(node.findtext('WINDOWS/ARCH','0')),edition=edition if edition in ('ServerStandardEval','ServerDatacenterEval') else 'unknown',installation_type=installation if installation in ('Server','Server Core') else 'unknown',build=int(node.findtext('WINDOWS/VERSION/BUILD','0'))))
  except (KeyError,ValueError):raise ProbeError('media_xml_failed')
 if not 0<len(images)<=16 or len({x['index'] for x in images})!=len(images):raise ProbeError('media_xml_failed')
 selected=[x['index'] for x in images if x['architecture']==9 and x['edition']=='ServerStandardEval' and x['installation_type']=='Server']
 if len(selected)!=1:raise ProbeError('image_not_unique')
 return images,selected[0]

class QMP:
 def __init__(self,path):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect(str(path));self.stream=self.sock.makefile('rwb',buffering=0);self.read();self.execute('qmp_capabilities')
 def read(self):
  raw=self.stream.readline(262145)
  if not raw or len(raw)>262144:raise ProbeError('qemu_failed')
  return json.loads(raw)
 def execute(self,cmd):
  self.stream.write((json.dumps({'execute':cmd})+'\n').encode())
  for _ in range(32):
   r=self.read()
   if 'error' in r:raise ProbeError('qemu_failed')
   if 'return' in r:return r['return']
  raise ProbeError('qemu_failed')
 def close(self):self.stream.close();self.sock.close()

def paused_qemu(work,iso,disk,r,log):
 path=work/'qmp.sock';p=None;q=None
 try:
  argv=['qemu-system-x86_64','-accel','kvm','-machine','q35','-cpu','host','-smp','2','-m','4096','-display','none','-nodefaults','-S','-no-reboot','-drive','file='+str(disk)+',format=qcow2,if=ide,id=labdisk','-drive','file='+str(iso)+',format=raw,media=cdrom,readonly=on,if=ide,id=labiso','-qmp','unix:'+str(path)+',server=on,wait=off']
  p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
  for _ in range(100):
   if path.exists():break
   if p.poll() is not None:raise ProbeError('qemu_failed')
   time.sleep(.1)
  q=QMP(path);r['qemu']['qmp_responded']=True
  kvm=q.execute('query-kvm');status=q.execute('query-status');blocks=q.execute('query-block')
  r['qemu'].update(kvm_enabled=kvm.get('enabled') is True,paused=status.get('running') is False and status.get('status') in ('prelaunch','paused'),disk_attached=any(x.get('device')=='labdisk' and 'inserted' in x for x in blocks),iso_attached=any(x.get('device')=='labiso' and 'inserted' in x for x in blocks))
  q.execute('quit');p.wait(timeout=10);r['qemu']['clean_shutdown']=p.returncode==0
  if not all(r['qemu'].values()):raise ProbeError('qemu_failed')
 except (OSError,ValueError,subprocess.SubprocessError):raise ProbeError('qemu_failed')
 finally:
  if q:q.close()
  if p and p.poll() is None:
   p.terminate()
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)

def main():
 if not guard():raise SystemExit('owned_ephemeral_host_once_required')
 r=blank(os.environ['GITHUB_SHA'],os.environ['GITHUB_RUN_ID']);out=Path('output');out.mkdir(exist_ok=True);workspace=Path(os.environ['GITHUB_WORKSPACE']).resolve()
 try:
  cleanup(r,workspace)
  with tempfile.TemporaryDirectory(prefix='owned-windows-prep-',dir=os.environ['RUNNER_TEMP']) as tmp:
   work=Path(tmp);iso=work/'official-eval.iso';disk=work/'guest.qcow2';wim=work/'install.wim';xml=work/'images.xml'
   with (work/'private-preparation.log').open('wb') as log:
    env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')
    try:
     command(['apt-get','update','-qq'],log,timeout=180,env=env)
     command(['apt-get','install','-y','--no-install-recommends','qemu-system-x86','qemu-utils','ovmf','p7zip-full','wimtools'],log,timeout=300,env=env)
    except ProbeError:raise ProbeError('apt_failed')
    r['apt_tools_installed']=True
    try:
     v=subprocess.check_output(['qemu-system-x86_64','--version'],timeout=10).decode();m=re.search(r'version ([0-9]+(?:\.[0-9]+){1,3})',v)
     if not m:raise ValueError('version')
     r['qemu_version']=m[1]
    except (OSError,ValueError,subprocess.SubprocessError):raise ProbeError('tool_missing')
    download(iso,r)
    try:
     try:
      with wim.open('xb') as out:
       subprocess.run(['7z','e','-so','-y','-ssc-',str(iso),'sources/install.wim'],stdin=subprocess.DEVNULL,stdout=out,stderr=log,timeout=300,check=True)
      if not 1024**3<wim.stat().st_size<=ISO_BYTES:raise ProbeError('media_extract_failed')
     except (OSError,subprocess.SubprocessError):raise ProbeError('media_extract_failed')
     try:command(['wimlib-imagex','info',str(wim),'--extract-xml='+str(xml)],log,timeout=60)
     except ProbeError:raise ProbeError('xml_command_failed')
     if xml.stat().st_size>1048576:raise ValueError('size')
     images,index=image_metadata(xml.read_bytes());r['image'].update(images=images,selected_index=index)
    except (OSError,ValueError,ProbeError) as exc:
     if isinstance(exc,ProbeError) and str(exc) in ('image_not_unique','media_extract_failed','xml_command_failed'):raise
     raise ProbeError('media_xml_failed')
    wim.unlink();xml.unlink()
    command(['qemu-img','create','-f','qcow2',str(disk),str(DISK_BYTES)],log,timeout=30)
    info=json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(disk)],timeout=10))
    if info.get('format')!='qcow2' or info.get('virtual-size')!=DISK_BYTES:raise ProbeError('qemu_failed')
    r['disk'].update(created=True,actual_bytes=info['actual-size'])
    paused_qemu(work,iso,disk,r,log)
    r['status']='prepared_paused_no_windows_boot'
 except ProbeError as exc:r['error_code']=str(exc) if str(exc) in ERRORS else 'bounded_preparation_failed'
 except Exception:r['error_code']='bounded_preparation_failed'
 finally:
  r['disk_free_final_bytes']=shutil.disk_usage(workspace).free
  if r['status']!='prepared_paused_no_windows_boot' and r['error_code'] is None:r['error_code']='bounded_preparation_failed'
  validate(r);(out/'windows-guest-preparation.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'error_code':r['error_code'],'windows_booted':False}))
if __name__=='__main__':
 if len(sys.argv)==4 and sys.argv[1]=='validate':
  r=validate(json.loads(Path(sys.argv[2]).read_text()));p=Path(sys.argv[3]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
 else:main()
