"""Bounded, read-only installed Retail identity. No network, Agent or game writes.

Only whitelisted .build.info fields are used. Full raw rows, paths and possible
keyring/auth-related columns never enter public reports. Identity is NOT proof
that all files promised by an installed build actually exist or are healthy.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import re
import threading
import repair_core as core
import target_metadata as meta

MAX_INFO=1024*1024
MAX_CONFIG=4*1024*1024
VERSION=re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
TAG_VALUES={'Windows','OSX','x86_32','x86_64','ARM64','EU','US','KR','TW','CN','code','speech','text',
            'enUS','enGB','deDE','esES','esMX','frFR','itIT','koKR','ptBR','ptPT','ruRU','zhCN','zhTW'}


def read_bounded(path,cap,cancel):
    path=core.regular(path);fp=core.fingerprint(path.stat())
    if fp[2]>cap:raise core.RepairError('installed_metadata_size_limit')
    core.check(cancel)
    with path.open('rb') as f:
        if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('installed_metadata_changed')
        raw=f.read(cap+1)
        if core.fingerprint(os.fstat(f.fileno()))!=fp:raise core.RepairError('installed_metadata_changed')
    if len(raw)!=fp[2] or core.fingerprint(core.regular(path).stat())!=fp:raise core.RepairError('installed_metadata_changed')
    core.check(cancel);return raw,fp


def select_row(raw):
    try:text=raw.decode('utf-8-sig')
    except UnicodeError:raise core.RepairError('build_info_invalid_encoding') from None
    lines=[s for s in text.splitlines() if s.strip() and not s.lstrip().startswith('#')]
    if not 2<=len(lines)<=2049:raise core.RepairError('build_info_row_count')
    fields=[]
    for name in lines[0].split('|'):
        name=name.split('!',1)[0].replace(' ','').lower()
        if not re.fullmatch('[a-z][a-z0-9_]{0,63}',name):raise core.RepairError('build_info_invalid_header')
        fields.append(name)
    if len(set(fields))!=len(fields) or not {'active','buildkey'}<=set(fields):raise core.RepairError('build_info_missing_or_duplicate_header')
    selected=[]
    for line in lines[1:]:
        values=line.split('|')
        if len(values)!=len(fields):raise core.RepairError('build_info_row_width')
        row=dict(zip(fields,values))
        if row['active']!='1':continue
        if 'product' in row and row['product']!='wow':continue
        selected.append({k:row.get(k,'') for k in ('buildkey','cdnkey','version','tags','branch','product')})
    if len(selected)!=1:raise core.RepairError('installed_retail_active_row_missing_or_ambiguous')
    row=selected[0];meta.key(row['buildkey'])
    if row['cdnkey']:meta.key(row['cdnkey'])
    if row['version'] and not VERSION.fullmatch(row['version']):raise core.RepairError('installed_version_invalid')
    if len(row['tags'])>4096 or any(ord(c)<32 for c in row['tags']):raise core.RepairError('installed_tags_invalid')
    return row


@dataclass
class Installed:
    root:Path
    storage:Path
    row:dict
    build:dict
    version:str
    watches:dict

    def check(self):
        for p,fp in self.watches.items():
            if core.fingerprint(core.regular(p).stat())!=fp:raise core.RepairError('installed_metadata_changed')

    def public(self):
        tokens=set(re.findall('[A-Za-z0-9_]+',self.row['tags']))
        return {'product':'wow','version':self.version,'build_config_md5_verified':True,
                'active_build_row_selected':True,'identity_source':'local_build_info_and_md5_bound_config','publisher_authentication_proven':False,'known_tag_tokens':sorted(tokens&TAG_VALUES),
                'tags_used_as_install_policy':False,'installed_files_health_proven':False,
                'active_casc_journal_generation_proven':False}


def read(root,cancel=None):
    cancel=cancel or threading.Event();core.check(cancel);root=core.safe(root)
    raw,fp=read_bounded(root/'.build.info',MAX_INFO,cancel);row=select_row(raw)
    key=row['buildkey'];path=root/'Data'/'config'/key[:2]/key[2:4]/key
    config,cfp=read_bounded(path,MAX_CONFIG,cancel);build=meta.config(config,key)
    if build.get('build-uid')!=['wow']:raise core.RepairError('installed_config_not_retail_wow')
    name=build.get('build-name',[])
    match=re.fullmatch(r'WOW-([0-9]+)patch([0-9]+\.[0-9]+\.[0-9]+)_Retail',name[0]) if len(name)==1 else None
    if not match:raise core.RepairError('installed_build_name_unsupported')
    version=match[2]+'.'+match[1]
    if row['version'] and row['version']!=version:raise core.RepairError('installed_version_config_conflict')
    storage=core.safe(root/'Data'/'data')
    if not storage.is_dir():raise core.RepairError('installed_storage_directory_missing')
    result=Installed(root,storage,row,build,version,{root/'.build.info':fp,path:cfp});result.check();return result


def download_descriptor(build):
    keys=build.get('download',[]);sizes=build.get('download-size',[])
    if len(keys)!=2:raise core.RepairError('installed_download_full_key_pair_required')
    ck,ek=(meta.key(v) for v in keys)
    if len(sizes)!=2 or any(not re.fullmatch('[0-9]{1,12}',v) for v in sizes):raise core.RepairError('installed_download_size_pair_required')
    ds,es=map(int,sizes)
    if not 0<ds<=256*1024**2 or not 0<es<=256*1024**2:raise core.RepairError('installed_download_manifest_size_limit')
    return {'ckey':ck,'ekey':ek,'decoded_size':ds,'encoded_size':es}
