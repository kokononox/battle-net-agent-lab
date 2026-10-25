"""Read-only candidate storage search. Never export content, UUIDs or their hashes.
A matching config value is evidence of presence, not proof the provider read it.
"""
import json,os,re,hashlib
from pathlib import Path
FILE_LIMIT=4*1024*1024
TOTAL_LIMIT=32*1024*1024
FIXED={'Agent','Battle.net','Blizzard Entertainment','Logs','logs','Telemetry','telemetry','Cache','cache','data','config','agent.db','Agent.db','product.db','Battle.net.config','battle.net.config','agent.config','config.json','settings.json','source_id','host_id','client_id','ClientId','ClientID','Identity','Client','Launcher','Install','Application','AgentHelper'}
PINNED_IMAGES={'f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6','7d20ba6ef1d34a3cedbd7d3fd7c14228f173668a9a1e338351d529048de45079','b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5','a3a444e6bd163732a648967c01a5fd509f7f33d6963b381c19bdffb604138651'}
def name_shape(name):
    return bool(isinstance(name,str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9 ._-]{0,63}',name) and not re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}',name))
def find_literal(name,image):
    if not name_shape(name):return None
    for encoding in ('ascii','utf-16-le'):
        n=name.encode(encoding).lower();zero='\0'.encode(encoding);slash='\\'.encode(encoding);data=image.lower()
        if any(prefix+n+suffix in data for prefix in (zero,slash) for suffix in (zero,slash)):return encoding
    return None

def registry_locator(parts,report,images):
    safe=[]
    for part in parts:
        if part in FIXED or re.fullmatch(r'Agent\.[0-9]{1,8}',part):safe.append(part);continue
        hit=next((dict(name=part,image_sha256=sha,encoding=kind) for sha,image in images.items() if (kind:=find_literal(part,image)) is not None),None)
        if hit is not None:
            if hit not in report['registry_literal_names']:
                if len(report['registry_literal_names'])>=32:report['budget_reached']=True;safe.append('*');continue
                report['registry_literal_names'].append(hit)
            safe.append(part)
        else:safe.append('*')
    return '/'.join(safe[:12]) or '*'

ROOTS={'programdata_battlenet','programdata_blizzard','localappdata_battlenet','appdata_battlenet','hkcu_blizzard','hkcu_battlenet','hklm_blizzard_32','hklm_blizzard_64','hklm_battlenet_32','hklm_battlenet_64'}
KEYS={'schema','phase','status','files_visited','files_read','bytes_read','skipped_reparse','skipped_large','file_errors','registry_keys_read','registry_values_read','registry_bytes_read','registry_errors','budget_reached','matches','observed_uuid_count','read_only','provider_read_source_proven','raw_values_or_hashes_exported','registry_literal_names'}
MATCHES={'kind','root','locator','category','uuid_exact','uuid_casefold','source_id_key_exact','source_id_key_casefold','source_id_literal_present'}

def safe_locator(parts):
    out=[]
    for part in parts:
        if part in FIXED or re.fullmatch(r'Agent\.[0-9]{1,8}',part):out.append(part)
        else:out.append('*')
    return '/'.join(out[:12]) or '*'

def flags(raw,values):
    exact=fold=False;key_exact=key_fold=False
    for v in values:
        for needle in (v,v.decode('ascii').encode('utf-16-le')):
            exact|=needle in raw;fold|=needle.lower() in raw.lower()
    try:
        def unique(pairs):
            d={}
            for k,v in pairs:
                if k in d:raise ValueError('duplicate')
                d[k]=v
            return d
        text=raw.decode('utf-8-sig') if not raw.startswith((b'\xff\xfe',b'\xfe\xff')) else raw.decode('utf-16')
        data=json.loads(text,object_pairs_hook=unique)
        def visit(x,depth=0):
            nonlocal key_exact,key_fold
            if depth>24:return
            if isinstance(x,dict):
                for k,v in x.items():
                    if k=='source_id' and isinstance(v,str):
                        key_exact|=any(v.encode('utf-8')==n for n in values)
                        key_fold|=any(v.lower().encode('utf-8')==n.lower() for n in values)
                    visit(v,depth+1)
            elif isinstance(x,list):
                for v in x[:10000]:visit(v,depth+1)
        visit(data)
    except (ValueError,UnicodeError,RecursionError):pass
    return dict(uuid_exact=exact,uuid_casefold=fold,source_id_key_exact=key_exact,source_id_key_casefold=key_fold,source_id_literal_present=(b'source_id' in raw or 'source_id'.encode('utf-16-le') in raw))

def add_match(report,kind,root,locator,category,f):
    if not (f['uuid_casefold'] or f['source_id_literal_present']):return
    if len(report['matches'])>=64:report['budget_reached']=True;return
    report['matches'].append(dict(kind=kind,root=root,locator=locator,category=category,**f))

def is_reparse(path):
    try:return path.is_symlink() or bool(getattr(path.lstat(),'st_file_attributes',0)&1024)
    except OSError:return True

def files(report,roots,values):
    visited=set()
    for label,root in roots:
        if not root.exists():continue
        if is_reparse(root):report['skipped_reparse']+=1;continue
        for folder,dirs,names in os.walk(root,followlinks=False):
            kept=[]
            for d in dirs:
                if is_reparse(Path(folder)/d):report['skipped_reparse']+=1
                else:kept.append(d)
            dirs[:]=sorted(kept)
            for name in sorted(names):
                path=Path(folder)/name
                # Deduplicate overlapping application roots privately.
                normalized=str(path.absolute()).lower()
                if normalized in visited:continue
                visited.add(normalized);report['files_visited']+=1
                if report['files_visited']>3000:report['budget_reached']=True;return
                ext=path.suffix.lower()
                if ext in {'.exe','.dll','.pdb','.zip','.mpq','.idx','.data','.etl','.pcapng'}:continue
                if is_reparse(path):report['skipped_reparse']+=1;continue
                try:
                    size=path.stat().st_size
                    if not 0<size<=FILE_LIMIT:report['skipped_large']+=1;continue
                    if report['bytes_read']+size>TOTAL_LIMIT:report['budget_reached']=True;return
                    with path.open('rb') as f:raw=f.read(FILE_LIMIT+1)
                    if len(raw)!=size or len(raw)>FILE_LIMIT:report['file_errors']+=1;continue
                    report['files_read']+=1;report['bytes_read']+=len(raw)
                    category='log' if ext in {'.log','.txt'} or 'logs' in [x.lower() for x in path.relative_to(root).parts[:-1]] else 'configuration_candidate'
                    add_match(report,'file',label,safe_locator(path.relative_to(root).parts),category,flags(raw,values))
                except OSError:report['file_errors']+=1

def registry(report,values,images):
    import winreg as w
    specs=[('hkcu_blizzard',w.HKEY_CURRENT_USER,r'SOFTWARE\Blizzard Entertainment',0),('hkcu_battlenet',w.HKEY_CURRENT_USER,r'SOFTWARE\Battle.net',0)]
    for name,path in [('blizzard',r'SOFTWARE\Blizzard Entertainment'),('battlenet',r'SOFTWARE\Battle.net')]:
        specs.extend([('hklm_'+name+'_32',w.HKEY_LOCAL_MACHINE,path,w.KEY_WOW64_32KEY),('hklm_'+name+'_64',w.HKEY_LOCAL_MACHINE,path,w.KEY_WOW64_64KEY)])
    for label,hive,root,view in specs:
        queue=[(root,[],0)]
        while queue:
            path,parts,depth=queue.pop(0)
            if report['registry_keys_read']>=128:report['budget_reached']=True;return
            try:key=w.OpenKey(hive,path,0,w.KEY_READ|view)
            except FileNotFoundError:continue
            except OSError:report['registry_errors']+=1;continue
            with key:
                report['registry_keys_read']+=1
                for index in range(128):
                    try:name,value,typ=w.EnumValue(key,index)
                    except OSError as e:
                        if getattr(e,'winerror',259)!=259:report['registry_errors']+=1
                        break
                    report['registry_values_read']+=1
                    if isinstance(value,str):raw=value.encode('utf-8')
                    elif isinstance(value,bytes):raw=value
                    else:continue
                    if len(raw)>1024*1024:report['registry_errors']+=1;continue
                    if report['registry_bytes_read']+len(raw)>8*1024*1024:report['budget_reached']=True;return
                    report['registry_bytes_read']+=len(raw);f=flags(raw,values)
                    if name=='source_id':
                        f['source_id_literal_present']=True
                        f['source_id_key_exact']=any(raw==n for n in values)
                        f['source_id_key_casefold']=any(raw.lower()==n.lower() for n in values)
                    add_match(report,'registry',label,registry_locator(parts+[name],report,images),'registry_value',f)
                else:report['budget_reached']=True
                if depth>=8:continue
                for index in range(64):
                    try:sub=w.EnumKey(key,index)
                    except OSError:break
                    queue.append((path+'\\'+sub,parts+[sub],depth+1))
                else:report['budget_reached']=True

def blank(phase):
    return dict(schema='bnet-host-storage-scan-2',phase=phase,status='not_scanned',files_visited=0,files_read=0,bytes_read=0,skipped_reparse=0,skipped_large=0,file_errors=0,registry_keys_read=0,registry_values_read=0,registry_bytes_read=0,registry_errors=0,budget_reached=False,matches=[],registry_literal_names=[],observed_uuid_count=0,read_only=True,provider_read_source_proven=False,raw_values_or_hashes_exported=False)

def scan(values,env,phase,images=None):
    from identity_compare import UUID4
    r=blank(phase);r['observed_uuid_count']=len(values)
    if len(values)!=1 or any(not isinstance(v,bytes) or not UUID4.fullmatch(v) for v in values):return validate(r)
    env={k.upper():v for k,v in env.items()}
    roots=[]
    for label,key,tail in [('programdata_battlenet','PROGRAMDATA','Battle.net'),('programdata_blizzard','PROGRAMDATA','Blizzard Entertainment'),('localappdata_battlenet','LOCALAPPDATA','Battle.net'),('appdata_battlenet','APPDATA','Battle.net')]:
        if env.get(key):roots.append((label,Path(env[key])/tail))
    try:
        files(r,roots,values)
        verified_images={sha:image for sha,image in (images or {}).items() if sha in PINNED_IMAGES and hashlib.sha256(image).hexdigest()==sha}
        if os.name=='nt':registry(r,values,verified_images)
        r['status']='bounded' if r['budget_reached'] else 'scan_complete'
    except Exception:r['status']='scan_failed'
    return validate(r)

def validate(r):
    if type(r) is not dict or set(r)!=KEYS or r['schema']!='bnet-host-storage-scan-2' or r['phase'] not in ('after_first','after_second'):raise ValueError('storage_schema')
    if r['status'] not in ('not_scanned','scan_complete','bounded','scan_failed'):raise ValueError('storage_status')
    for k in ('files_visited','files_read','bytes_read','skipped_reparse','skipped_large','file_errors','registry_keys_read','registry_values_read','registry_bytes_read','registry_errors','observed_uuid_count'):
        if type(r[k]) is not int or not 0<=r[k]<=64*1024*1024:raise ValueError('storage_number')
    if r['files_read']>r['files_visited'] or r['bytes_read']>TOTAL_LIMIT or r['registry_bytes_read']>8*1024*1024:raise ValueError('storage_limits')
    if r['read_only'] is not True or r['provider_read_source_proven'] is not False or r['raw_values_or_hashes_exported'] is not False:raise ValueError('storage_scope')
    if any(type(r[k]) is not bool for k in ('read_only','provider_read_source_proven','raw_values_or_hashes_exported','budget_reached')):raise ValueError('storage_boolean')
    if type(r['registry_literal_names']) is not list or len(r['registry_literal_names'])>32:raise ValueError('storage_literal_names')
    literal_names=set()
    for p in r['registry_literal_names']:
        if type(p) is not dict or set(p)!={'name','image_sha256','encoding'} or not name_shape(p['name']) or p['image_sha256'] not in PINNED_IMAGES or p['encoding'] not in ('ascii','utf-16-le'):raise ValueError('storage_literal_proof')
        literal_names.add(p['name'])
    if type(r['matches']) is not list or len(r['matches'])>64:raise ValueError('storage_matches')
    for m in r['matches']:
        if type(m) is not dict or set(m)!=MATCHES or m['kind'] not in ('file','registry') or m['root'] not in ROOTS or m['category'] not in ('configuration_candidate','log','registry_value'):raise ValueError('storage_match')
        if type(m['locator']) is not str or not 0<len(m['locator'])<=256 or any(p!='*' and p not in FIXED and p not in literal_names and not re.fullmatch(r'Agent\.[0-9]{1,8}',p) for p in m['locator'].split('/')):raise ValueError('storage_locator')
        if any(type(m[k]) is not bool for k in MATCHES-{'kind','root','locator','category'}):raise ValueError('storage_flags')
        if (m['uuid_exact'] and not m['uuid_casefold']) or (m['source_id_key_exact'] and not m['source_id_key_casefold']):raise ValueError('storage_flag_ladder')
    return r
