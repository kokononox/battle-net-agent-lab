"""Read-only metadata of a suspended refused child; never permission to resume it."""
import hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
NAMES=set('agenthelper.exe cmd.exe conhost.exe dllhost.exe rundll32.exe reg.exe sc.exe net.exe net1.exe powershell.exe pwsh.exe schtasks.exe taskkill.exe msiexec.exe wermgr.exe werfault.exe unsecapp.exe cscript.exe wscript.exe explorer.exe certutil.exe ctfmon.exe consent.exe backgroundtaskhost.exe runtimebroker.exe csc.exe update.exe uninstall.exe bnetinstaller.exe battle.net.exe battle.net-setup.exe agent.exe'.split())|{'battle.net setup.exe','blizzard update agent.exe'}
PUBLISHERS={'blizzard','microsoft','other_verified','unverified'}
REGIONS={'windows_system32','windows_syswow64','windows_other','runner_temp','battle_net_programdata','other'}
KEYS={'status','basename_class','path_class','image_bytes','image_file_sha256','authenticode_valid','publisher_class','winverifytrust_status','blocked_before_resume','execution_authorized'}
def region(path,env):
    env={k.upper():v for k,v in env.items()}
    path=path.resolve()
    roots=[('windows_system32',Path(env['SYSTEMROOT'])/'System32'),('windows_syswow64',Path(env['SYSTEMROOT'])/'SysWOW64'),('windows_other',Path(env['SYSTEMROOT']))]
    if os.environ.get('RUNNER_TEMP'):roots.append(('runner_temp',Path(os.environ['RUNNER_TEMP'])))
    if env.get('PROGRAMDATA'):roots.append(('battle_net_programdata',Path(env['PROGRAMDATA'])/'Battle.net'))
    for label,root in roots:
        if path.is_relative_to(root.resolve()):return label
    return 'other'
def parse_signature(raw):
    if len(raw)>1024:raise ValueError('size')
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise ValueError('duplicate')
            d[k]=v
        return d
    d=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs)
    if type(d) is not dict or set(d)!={'trust_status','publisher_class'}:raise ValueError('signature_keys')
    if type(d['trust_status']) is not int or not -2**31<=d['trust_status']<2**31 or d['publisher_class'] not in PUBLISHERS:raise ValueError('signature_values')
    if d['trust_status']!=0 and d['publisher_class']!='unverified':raise ValueError('untrusted_publisher')
    return d

def native_signature(path,env):
    env={k.upper():v for k,v in env.items()}
    with tempfile.TemporaryDirectory(prefix='refused-signature-',dir=os.environ['RUNNER_TEMP']) as tmp:
        exe=Path(tmp)/'ReadOnlySignature.exe'
        compiler=Path(env['SYSTEMROOT'])/'Microsoft.NET'/'Framework64'/'v4.0.30319'/'csc.exe'
        p=subprocess.run([str(compiler),'/nologo','/warn:0','/target:exe','/platform:x64','/out:'+str(exe),str(Path(__file__).with_name('refused_signature.cs'))],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False)
        if p.returncode or not exe.is_file():raise ValueError('compile')
        # Data-only path via private env; no shell, no command line from target.
        p=subprocess.run([str(exe)],env=dict(env,BNET_READ_ONLY_SIGNATURE_PATH=str(path.resolve())),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
        if p.returncode:raise ValueError('signature')
        return parse_signature(p.stdout)

def inspect_refused(path,env,is_reparse):
    d=dict(status='metadata_failed',basename_class=path.name.lower() if path.name.lower() in NAMES else 'other',path_class='other',image_bytes=0,image_file_sha256=None,authenticode_valid=False,publisher_class='unverified',winverifytrust_status=None,blocked_before_resume=True,execution_authorized=False)
    try:
        d['path_class']=region(path,env)
        if is_reparse(path):return validate(d)
        before=path.stat()
        if not 0<before.st_size<=128*1024*1024:return validate(d)
        image=path.read_bytes()
        if len(image)!=before.st_size or image[:2]!=b'MZ':return validate(d)
        digest=hashlib.sha256(image).hexdigest()
        sig=native_signature(path,env)
        after=path.stat()
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            d['status']='unstable_image';return validate(d)
        d.update(status='metadata_complete',image_bytes=len(image),image_file_sha256=digest,authenticode_valid=sig['trust_status']==0,publisher_class=sig['publisher_class'],winverifytrust_status=sig['trust_status'])
    except Exception:pass
    return validate(d)

def validate(d):
    if type(d) is not dict or set(d)!=KEYS:raise ValueError('refused_metadata_schema')
    if d['status'] not in ('metadata_failed','unstable_image','metadata_complete') or d['basename_class'] not in NAMES|{'other'} or d['path_class'] not in REGIONS:raise ValueError('refused_metadata_labels')
    if type(d['image_bytes']) is not int or not 0<=d['image_bytes']<=128*1024*1024:raise ValueError('image_bytes')
    if d['image_file_sha256'] is not None and (type(d['image_file_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',d['image_file_sha256'])):raise ValueError('image_hash')
    if type(d['authenticode_valid']) is not bool or d['publisher_class'] not in PUBLISHERS:raise ValueError('publisher')
    c=d['winverifytrust_status']
    if c is not None and (type(c) is not int or not -2**31<=c<2**31):raise ValueError('trust')
    if d['blocked_before_resume'] is not True or type(d['blocked_before_resume']) is not bool or d['execution_authorized'] is not False or type(d['execution_authorized']) is not bool:raise ValueError('no_execution')
    if d['status']=='metadata_complete':
        if not d['image_file_sha256'] or not d['image_bytes'] or c is None or d['authenticode_valid']!=(c==0):raise ValueError('metadata_completeness')
    elif d['image_bytes'] or d['image_file_sha256'] is not None or d['authenticode_valid'] or d['publisher_class']!='unverified' or c is not None:raise ValueError('failed_metadata_claim')
    if not d['authenticode_valid'] and d['publisher_class']!='unverified':raise ValueError('untrusted_publisher')
    return d
