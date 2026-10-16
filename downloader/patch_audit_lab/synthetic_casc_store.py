"""Owned NEW synthetic storage only. Custom generation/pointer transaction model.

No WoW installation, shmem, .build.info or vendor activation implementation.
OS file locks serialize cooperating fixture tools. fsync is not a power-loss proof.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
import source_binding as b
import encoding_target as enc
import synthetic_casc_format as fmt
import patch_audit as a

MARKER='SYNTHETIC-STORAGE-ONLY.json'
GEN=re.compile(r'g[0-9a-f]{32}');TX=re.compile(r'tx-[0-9a-f]{32}')
MAX_OBJECTS=32;MAX_TOTAL=16*1024**2
PHASES=('stage_data_written','stage_indexes_written','stage_manifest_written','prepared','generation_renamed','publishing_recorded','pointer_replaced','readback_verified','committed_recorded')

def need(v,code):fmt.need(v,code)
def raw_json(obj):return (json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n').encode()
def read(path,limit=MAX_TOTAL):
    p=b.safe(path,True);before=b.fp(p.stat());need(before[2]<=limit,'fixture_file_limit')
    with p.open('rb') as f:
        need(b.fp(os.fstat(f.fileno()))==before,'fixture_source_changed');data=f.read(limit+1)
        need(b.fp(os.fstat(f.fileno()))==before,'fixture_source_changed')
    need(len(data)==before[2] and b.fp(p.stat())==before,'fixture_source_changed');return data

def obj(path):return b.json_object(read(path,512*1024))
def sync_dir(path):
    if os.name!='nt':
        fd=os.open(str(b.safe(path)),os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

def write_new(path,data):
    b.safe(Path(path).parent)
    need(not Path(path).exists() and not Path(path).is_symlink(),'fixture_refuse_overwrite')
    with Path(path).open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())

def atomic(path,data):
    path=Path(path);b.safe(path.parent)
    if path.exists() or path.is_symlink():b.safe(path,True)
    tmp=path.with_name('.fixture-'+uuid.uuid4().hex+'.tmp')
    write_new(tmp,data);os.replace(tmp,path);sync_dir(path.parent)

def no_game_ancestors(path):
    for p in (Path(path),*Path(path).parents):
        need(p.name.casefold() not in ('_retail_','world of warcraft','wtf','interface','screenshots'),'fixture_game_path_rejected')
        need(not (p/'.build.info').exists() and not (p/'.build.db').exists(),'fixture_game_path_rejected')

class Store:
    @classmethod
    def create(cls,root,archive_limit=4096):
        root=Path(root).absolute();no_game_ancestors(root);b.safe(root.parent)
        need(not root.exists() and not root.is_symlink(),'new_synthetic_root_required')
        need(type(archive_limit)is int and 128<=archive_limit<=1024**2,'synthetic_archive_limit')
        root.mkdir();(root/'generations').mkdir();(root/'transactions').mkdir()
        workspace=uuid.uuid4().hex
        write_new(root/MARKER,raw_json({'format':'synthetic-casc-store-1','workspace':workspace,'archive_limit':archive_limit,'real_game_installation':False}))
        write_new(root/'LOCK',b'\0')
        name='g'+'0'*32;folder=root/'generations'/name;folder.mkdir()
        manifest={'format':'synthetic-generation-1','workspace':workspace,'generation':name,'objects':{},'archives':{},'indexes':{}}
        data=raw_json(manifest);write_new(folder/'manifest.json',data);sync_dir(folder);sync_dir(root/'generations')
        write_new(root/'active.json',raw_json({'format':'synthetic-active-1','workspace':workspace,'generation':name,'manifest_sha256':a.sha256(data)}));sync_dir(root)
        return cls(root)
    def __init__(self,root):
        self.root=b.safe(root);no_game_ancestors(self.root)
        marker=obj(self.root/MARKER)
        need(set(marker)=={'format','workspace','archive_limit','real_game_installation'} and marker['format']=='synthetic-casc-store-1' and marker['real_game_installation']is False and re.fullmatch('[0-9a-f]{32}',str(marker['workspace'])) and type(marker['archive_limit'])is int and 128<=marker['archive_limit']<=1024**2,'synthetic_marker_required')
        self.workspace=marker['workspace'];self.limit=marker['archive_limit']
        need(set(os.listdir(self.root))=={MARKER,'LOCK','active.json','generations','transactions'},'synthetic_root_layout')
        for name in ('generations','transactions'):need(b.safe(self.root/name).is_dir(),'fixture_directory_required')
        b.safe(self.root/'LOCK',True);need((self.root/'LOCK').stat().st_size==1,'fixture_lock_shape')
    @contextmanager
    def lock(self):
        # Lock file is pre-created by exclusive Store.create; never creates in an arbitrary root.
        b.safe(self.root/'LOCK',True)
        with (self.root/'LOCK').open('r+b') as f:
            if os.name=='nt':
                import msvcrt
                try:msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
                except OSError:raise fmt.FormatError('synthetic_store_busy') from None
            else:
                import fcntl
                try:fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                except OSError:raise fmt.FormatError('synthetic_store_busy') from None
            try:yield
            finally:
                if os.name=='nt':f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
                else:fcntl.flock(f.fileno(),fcntl.LOCK_UN)
    def pointer(self):
        p=obj(self.root/'active.json')
        need(set(p)=={'format','workspace','generation','manifest_sha256'} and p['format']=='synthetic-active-1' and p['workspace']==self.workspace and isinstance(p['generation'],str) and GEN.fullmatch(p['generation']) and re.fullmatch('[0-9a-f]{64}',str(p['manifest_sha256'])),'synthetic_pointer_shape')
        return p
    def generation(self,ptr,folder=None):
        need(ptr['workspace']==self.workspace and GEN.fullmatch(ptr['generation']),'generation_identity')
        folder=b.safe(folder or self.root/'generations'/ptr['generation'])
        raw=read(folder/'manifest.json',512*1024);need(a.sha256(raw)==ptr['manifest_sha256'],'generation_manifest_hash')
        m=b.json_object(raw)
        need(set(m)=={'format','workspace','generation','objects','archives','indexes'} and m['format']=='synthetic-generation-1' and m['workspace']==self.workspace and m['generation']==ptr['generation'],'generation_manifest_shape')
        need(all(isinstance(m[k],dict) for k in ('objects','archives','indexes')) and len(m['objects'])<=MAX_OBJECTS and len(m['archives'])<=MAX_OBJECTS and len(m['indexes'])<=16,'generation_count_limit')
        need(set(os.listdir(folder))==set(m['archives'])|set(m['indexes'])|{'manifest.json'},'generation_unexpected_file')
        files={};total=0
        for group in ('archives','indexes'):
            for name,proof in m[group].items():
                need(isinstance(name,str) and re.fullmatch(r'data\.[0-9]{3}' if group=='archives' else r'[0-9a-f]{2}00000001\.idx',name),'generation_filename')
                need(isinstance(proof,dict) and set(proof)=={'size','sha256'},'generation_file_proof')
                raw=read(folder/name);total+=len(raw);need(total<=MAX_TOTAL,'generation_total_limit')
                need(proof=={'size':len(raw),'sha256':a.sha256(raw)},'generation_file_hash')
                if group=='archives':need(len(raw)<=self.limit,'generation_archive_limit')
                files[name]=raw
        indexrows={}
        for name in m['indexes']:
            which=int(name[:2],16);need(which<16,'generation_bucket')
            for row in fmt.read_index(files[name],which):
                need(row['prefix'] not in indexrows,'generation_duplicate_prefix');indexrows[row['prefix']]=row
        need(len(indexrows)==len(m['objects']),'generation_index_count')
        spans={};decoded={}
        for ek,row in m['objects'].items():
            a.key(ek);need(isinstance(row,dict) and set(row)=={'ckey','decoded_size','archive','offset','span'},'generation_object_shape')
            need(type(row['decoded_size'])is int and 0<row['decoded_size']<=256*1024 and type(row['archive'])is int and 0<=row['archive']<1024 and type(row['offset'])is int and type(row['span'])is int and row['offset']>=0 and row['span']>30,'generation_object_bounds')
            idx=indexrows.get(ek[:18]);need(idx=={'prefix':ek[:18],'archive':row['archive'],'offset':row['offset'],'span':row['span']},'generation_index_relation')
            name=f"data.{row['archive']:03d}";need(name in m['archives'] and row['offset']+row['span']<=len(files[name]),'generation_archive_reference')
            span=files[name][row['offset']:row['offset']+row['span']]
            value,_=fmt.read_span(span,ek,row['decoded_size'],row['ckey'],row['archive'],row['offset'])
            decoded[ek]=value;spans.setdefault(name,[]).append((row['offset'],row['span']))
        need(set(spans)==set(m['archives']),'generation_unreferenced_archive')
        for name,rows in spans.items():
            at=0
            for off,n in sorted(rows):need(off==at,'generation_overlap_or_gap');at+=n
            need(at==len(files[name]),'generation_unindexed_tail')
        return m,files,decoded
    def view(self):
        with self.lock():self._recover();ptr=self.pointer();return self.generation(ptr)[2]
    def _write_generation(self,folder,name,old,files,payloads,failpoint):
        need(isinstance(payloads,list) and 0<len(payloads)<=MAX_OBJECTS,'synthetic_payload_count')
        need(len(old['objects'])+len(payloads)<=MAX_OBJECTS,'synthetic_object_limit')
        objects={k:dict(v) for k,v in old['objects'].items()}
        archives={int(n[5:]):bytearray(files[n]) for n in old['archives']}
        prefixes={k[:18] for k in objects}
        for item in payloads:
            need(isinstance(item,tuple) and len(item)==2,'synthetic_payload_spec')
            data,spec=item;need(isinstance(data,bytes) and 0<len(data)<=256*1024 and isinstance(spec,str),'synthetic_payload_bounds')
            encoded=enc.encode(data,spec);hs=int.from_bytes(encoded[4:8],'big');ek=a.md5(encoded[:hs] if hs else encoded)
            need(ek not in objects and ek[:18] not in prefixes,'synthetic_duplicate_or_prefix_collision')
            aid=max(archives,default=0);offset=len(archives.get(aid,b''))
            if offset+30+len(encoded)>self.limit:aid+=1;offset=0
            need(aid<1024 and 30+len(encoded)<=self.limit,'synthetic_archive_capacity')
            span=fmt.make_span(encoded,ek,len(data),aid,offset);archives.setdefault(aid,bytearray()).extend(span)
            objects[ek]={'ckey':a.md5(data),'decoded_size':len(data),'archive':aid,'offset':offset,'span':len(span)};prefixes.add(ek[:18])
        need(sum(map(len,archives.values()))<=MAX_TOTAL,'synthetic_generation_budget')
        archiveproof={};indexproof={}
        for aid,data in sorted(archives.items()):
            filename=f'data.{aid:03d}';raw=bytes(data);write_new(folder/filename,raw);archiveproof[filename]={'size':len(raw),'sha256':a.sha256(raw)}
        failpoint('stage_data_written')
        bybucket={}
        for ek,row in objects.items():bybucket.setdefault(fmt.bucket(ek),[]).append({'ekey':ek,**row})
        for which,rows in sorted(bybucket.items()):
            raw=fmt.make_index(rows,which);filename=f'{which:02x}00000001.idx';write_new(folder/filename,raw);indexproof[filename]={'size':len(raw),'sha256':a.sha256(raw)}
        failpoint('stage_indexes_written')
        m={'format':'synthetic-generation-1','workspace':self.workspace,'generation':name,'objects':objects,'archives':archiveproof,'indexes':indexproof}
        raw=raw_json(m);write_new(folder/'manifest.json',raw);sync_dir(folder);failpoint('stage_manifest_written')
        ptr={'format':'synthetic-active-1','workspace':self.workspace,'generation':name,'manifest_sha256':a.sha256(raw)}
        self.generation(ptr,folder);return ptr
    def add(self,payloads,failpoint=lambda _:None):
        with self.lock():
            self._recover();oldptr=self.pointer();old,files,_=self.generation(oldptr)
            txname='tx-'+uuid.uuid4().hex;tx=self.root/'transactions'/txname;tx.mkdir();sync_dir(tx.parent)
            stage=tx/'stage';stage.mkdir();name='g'+uuid.uuid4().hex
            newptr=self._write_generation(stage,name,old,files,payloads,failpoint)
            journal={'format':'synthetic-tx-1','workspace':self.workspace,'tx':txname,'state':'prepared','old':oldptr,'new':newptr}
            atomic(tx/'journal.json',raw_json(journal));failpoint('prepared')
            dest=self.root/'generations'/name;need(not dest.exists(),'generation_collision');os.rename(stage,dest);sync_dir(dest.parent);sync_dir(tx);failpoint('generation_renamed')
            journal['state']='publishing';atomic(tx/'journal.json',raw_json(journal));failpoint('publishing_recorded')
            need(self.pointer()==oldptr,'synthetic_pointer_changed');self.generation(newptr)
            atomic(self.root/'active.json',raw_json(newptr));failpoint('pointer_replaced')
            self.generation(self.pointer());failpoint('readback_verified')
            journal['state']='committed';atomic(tx/'journal.json',raw_json(journal));failpoint('committed_recorded')
            return newptr
    def _recover(self):
        transactions=list((self.root/'transactions').iterdir());need(len(transactions)<=1024,'synthetic_tx_limit')
        pending=[];reports=[]
        for tx in sorted(transactions):
            need(TX.fullmatch(tx.name) and b.safe(tx).is_dir(),'synthetic_tx_directory')
            if not (tx/'journal.json').exists():reports.append('preparation_incomplete_retained');continue
            j=obj(tx/'journal.json')
            need(set(j)=={'format','workspace','tx','state','old','new'} and j['format']=='synthetic-tx-1' and j['workspace']==self.workspace and j['tx']==tx.name and j['state'] in ('prepared','publishing','committed','rolled_back'),'synthetic_journal_shape')
            for p in (j['old'],j['new']):
                need(isinstance(p,dict) and set(p)=={'format','workspace','generation','manifest_sha256'} and p['format']=='synthetic-active-1' and p['workspace']==self.workspace and isinstance(p['generation'],str) and GEN.fullmatch(p['generation']) and re.fullmatch('[0-9a-f]{64}',str(p['manifest_sha256'])),'synthetic_journal_pointer')
            need(j['old']!=j['new'],'synthetic_journal_same_generation')
            if j['state'] in ('committed','rolled_back'):reports.append(j['state']);continue
            pending.append((tx,j))
        need(len(pending)<=1,'multiple_pending_transactions_conflict')
        for tx,j in pending:
            current=self.pointer();need(current==j['old'] or current==j['new'],'recovery_unrelated_pointer_preserved')
            self.generation(j['old']) # Verify complete rollback destination BEFORE any pointer change.
            if current==j['new']:atomic(self.root/'active.json',raw_json(j['old']))
            j['state']='rolled_back';atomic(tx/'journal.json',raw_json(j));reports.append('rolled_back')
        return reports
    def recover(self):
        with self.lock():return self._recover()
