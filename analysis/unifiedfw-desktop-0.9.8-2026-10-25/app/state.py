"""Portable configuration store. Only package-local JSON files are written."""
from __future__ import annotations
import contextlib,copy,hashlib,json,os,stat,struct,uuid
from pathlib import Path
from policy import PolicyError,windows_path,path_key,program_id,new_config,validate,blacklist_entry,interval,compile_plan,whitelist_spec,whitelist_text

def assert_local_tree(path):
    path=Path(path).absolute()
    for p in (path,*path.parents):
        if p.exists() or p.is_symlink():
            st=p.lstat()
            if p.is_symlink() or getattr(st,'st_file_attributes',0)&0x400:raise PolicyError('state_reparse_path')
    return path

def atomic_json(path,obj):
    path=Path(path);assert_local_tree(path)
    tmp=path.with_name(path.name+'.next-'+uuid.uuid4().hex)
    try:
        with tmp.open('x',encoding='utf-8') as f:
            json.dump(obj,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if tmp.exists():tmp.unlink()

@contextlib.contextmanager
def locked(path):
    assert_local_tree(path)
    with Path(path).open('a+b') as f:
        if os.name=='nt':
            import msvcrt
            f.seek(0,2)
            if f.tell()==0:f.write(b'0');f.flush()
            f.seek(0)
            try:msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
            except OSError as e:raise PolicyError('another_config_operation_running') from e
            try:yield
            finally:f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
        else:
            import fcntl
            try:fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as e:raise PolicyError('another_config_operation_running') from e
            try:yield
            finally:fcntl.flock(f.fileno(),fcntl.LOCK_UN)

def inspect_file(path):
    """Checks an actual file. Used by the Windows path wrapper and cross-platform tests."""
    path=assert_local_tree(path)
    if not path.is_file():raise PolicyError('program_file_missing')
    with path.open('rb') as f:
        before=os.fstat(f.fileno());header=f.read(64)
        if len(header)<64 or header[:2]!=b'MZ':raise PolicyError('not_a_pe_executable')
        offset=struct.unpack_from('<I',header,60)[0]
        if offset<64 or offset>min(before.st_size-4,1048576):raise PolicyError('invalid_pe_header')
        f.seek(offset)
        if f.read(4)!=b'PE\0\0':raise PolicyError('not_a_pe_executable')
        f.seek(0);h=hashlib.sha256()
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
        after=os.fstat(f.fileno());current=path.stat()
        fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
        if fields(before)!=fields(after) or fields(before)!=fields(current):raise PolicyError('program_changed_during_read')
    return h.hexdigest()

def inspect_executable(text):
    text=windows_path(text)
    if os.name!='nt':raise PolicyError('program_registration_requires_windows')
    return dict(path=text,sha256=inspect_file(Path(text)))

class Store:
    def __init__(self,root,inspector=inspect_executable):
        self.root=assert_local_tree(root);self.root.mkdir(parents=True,exist_ok=True)
        self.file=self.root/'settings.json';self.lock=self.root/'config.lock';self.inspector=inspector
    def _read(self):
        assert_local_tree(self.file)
        if not self.file.exists():
            value=dict(schema='unified-firewall-state-1',owner=uuid.uuid4().hex,config=new_config());atomic_json(self.file,value)
        if self.file.stat().st_size>2097152:raise PolicyError('state_too_large')
        try:value=json.loads(self.file.read_text('utf-8-sig'))
        except (OSError,ValueError) as e:raise PolicyError('state_invalid_keep_files') from e
        if not isinstance(value,dict) or set(value)!={'schema','owner','config'} or value['schema']!='unified-firewall-state-1':raise PolicyError('state_schema')
        import re
        if not isinstance(value['owner'],str) or not re.fullmatch('[a-f0-9]{32}',value['owner']):raise PolicyError('state_owner')
        validate(value['config']);return value
    def read(self):
        with locked(self.lock):return self._read()
    def update(self,generation,change,*,backup_reason="before_config_update",backup_extra=None):
        with locked(self.lock):
            state=self._read();c=copy.deepcopy(state['config'])
            if type(generation) is not int or generation!=c['generation']:raise PolicyError('config_changed_reload_required')
            change(c);c['generation']+=1;validate(c)
            from policy_backups import create_backup
            self.last_backup_id=create_backup(self,state,reason=backup_reason,ui_snapshot=backup_extra)
            state['config']=c;atomic_json(self.file,state);return state
    def register(self,paths,generation):
        if not isinstance(paths,list) or not paths or len(paths)>32:raise PolicyError('program_selection_limit')
        inspected={}
        for path in paths:
            checked=self.inspector(windows_path(path))
            if path_key(checked['path'])!=path_key(path):raise PolicyError('resolved_program_identity_mismatch')
            inspected[path_key(path)]=dict(id=program_id(checked['path']),path=windows_path(checked['path']),sha256=checked['sha256'],enabled=True)
        def change(c):
            bypath={path_key(p['path']):p for p in c['programs']};bypath.update(inspected);c['programs']=list(bypath.values())
        return self.update(generation,change)
    def remove(self,ids,generation):
        if not isinstance(ids,list) or not ids:raise PolicyError('program_selection_required')
        def change(c):
            known={p['id'] for p in c['programs']}
            if any(p not in known for p in ids):raise PolicyError('unknown_program')
            c['programs']=[p for p in c['programs'] if p['id'] not in ids]
            entries=[]
            for e in c['blacklist']:
                keep=[p for p in e['program_ids'] if p not in ids]
                if keep:entries.append(blacklist_entry(keep,e['target'],e['protocol'],e['port']))
            c['blacklist']=entries
        return self.update(generation,change)
    def configure(self,mode,whitelist,generation):
        if not isinstance(whitelist,list) or any(not isinstance(x,str) for x in whitelist):raise PolicyError('whitelist_string_array_required')
        def change(c):c.update(mode=mode,whitelist=sorted({(whitelist_text(whitelist_spec(x)) if '|' in x else interval(x).text()) for x in whitelist if isinstance(x,str) and x.strip()}))
        return self.update(generation,change)
    def add_blacklist(self,ids,target,protocol,port,generation):
        entry=blacklist_entry(ids,target,protocol,port)
        def change(c):
            c['blacklist']=[e for e in c['blacklist'] if e['id']!=entry['id']]+[entry]
        return self.update(generation,change)
    def delete_blacklist(self,ids,generation):
        def change(c):
            if not ids or any(i not in {e['id'] for e in c['blacklist']} for i in ids):raise PolicyError('blacklist_selection_required')
            c['blacklist']=[e for e in c['blacklist'] if e['id'] not in ids]
        return self.update(generation,change)
    def verified_programs(self,ids=None):
        s=self.read();enabled=[p for p in s['config']['programs'] if p['enabled']]
        if ids is not None:
            if not isinstance(ids,list) or not ids or any(i not in {p['id'] for p in enabled} for i in ids):raise PolicyError('program_selection_required')
            enabled=[p for p in enabled if p['id'] in ids]
        if not enabled:raise PolicyError('program_selection_required')
        for p in enabled:
            now=self.inspector(p['path'])
            if path_key(now['path'])!=path_key(p['path']) or now['sha256']!=p['sha256']:raise PolicyError('program_binary_changed_reselect_required')
        return s,enabled
    def preview(self):
        s=self.read()
        if any(p['enabled'] for p in s['config']['programs']):s,_=self.verified_programs()
        return compile_plan(s['config'],s['owner'])
