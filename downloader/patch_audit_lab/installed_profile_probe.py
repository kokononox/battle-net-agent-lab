"""Approved TWO-FILE installed Retail metadata probe. No archive/Lab/network IO.

Reads .build.info (<=1 MiB), then exactly its named build-config (<=4 MiB).
Exports only whitelisted identity/profile data. This is NOT an updater or
publisher authentication, install health, active-CASC or vendor-policy proof.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,stat,sys,time,uuid
VERSION='installed-profile-probe-1'
MAX_INFO=1024**2
MAX_CONFIG=4*1024**2
TARGET_BUILD='334a36cf5f3c32a5f7a167405487fa14'
TARGET_VERSION='12.1.5.70391'
LOCALES={'deDE','enUS','enGB','esES','esMX','frFR','itIT','koKR','ptBR','ptPT','ruRU','zhCN','zhTW'}
SUPPORTED_LOCALES=LOCALES-{'enGB','ptPT'}
PLATFORMS={'Windows','OSX'}
ARCHITECTURES={'x86_32','x86_64','ARM64'}
REGIONS={'EU','US','KR','TW','CN'}
KNOWN=LOCALES|PLATFORMS|ARCHITECTURES|REGIONS|{'code','speech','text'}
TAG_FIELDS=('token_count','optional_suffix_count','known_token_count','account_qualifier_count',
            'geoip_qualifier_count','unknown_plain_count','unknown_optional_count','malformed_token_count')
PHASES={'start','select_game_root','read_build_info','select_active_row','read_named_build_config',
        'verify_build_config','parse_profile_tags','final_input_recheck','prepare_report_output',
        'write_pending_report','publish_report_noreplace','postpublication_recheck','complete'}
class ProbeError(ValueError):pass

def need(ok,code):
    if not ok:raise ProbeError(code)

def fingerprint(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_nlink]

def safe(path,regular=False):
    p=Path(os.path.abspath(str(path)))
    for item in reversed((p,*p.parents)):
        s=item.lstat();need(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'link_or_reparse_point')
        if item!=p:need(stat.S_ISDIR(s.st_mode),'non_directory_ancestor')
    if regular:
        s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'regular_unshared_file_required')
    return p

class Watch:
    def __init__(self):self.files={};self.read_bytes=0
    def check(self):
        for p,before in self.files.items():need(fingerprint(safe(p,True).stat())==before,'installed_metadata_changed')
    def read(self,path,cap):
        p=safe(path,True);before=fingerprint(p.stat());need(before[2]<=cap,'installed_metadata_size_limit');self.files[p]=before
        with p.open('rb') as f:
            need(fingerprint(os.fstat(f.fileno()))==before,'installed_metadata_changed')
            raw=f.read(before[2]);self.read_bytes+=len(raw)
            need(fingerprint(os.fstat(f.fileno()))==before,'installed_metadata_changed')
        need(len(raw)==before[2],'installed_metadata_short_read');self.check();return raw

class Progress:
    def __init__(self):self.stage='start'
    def mark(self,stage):need(stage in PHASES,'invalid_probe_phase');self.stage=stage

def public_error(ex,stage='start'):
    q={'status':'stopped_safely','probe_version':VERSION,'error_type':type(ex).__name__,
       'stage':stage if stage in PHASES else 'start','installation_ready':False}
    if isinstance(ex,ProbeError) and re.fullmatch('[a-z0-9_]{1,100}',str(ex)):q['code']=str(ex)
    if isinstance(ex,OSError):
        for k in ('errno','winerror'):
            v=getattr(ex,k,None)
            if type(v)is int:q[k]=v
    return q

def select_row(raw):
    try:text=raw.decode('utf-8-sig')
    except UnicodeError:raise ProbeError('build_info_invalid_encoding') from None
    lines=[s for s in text.splitlines() if s.strip() and not s.lstrip().startswith('#')]
    need(2<=len(lines)<=2049,'build_info_row_count')
    fields=[s.split('!',1)[0].replace(' ','').lower() for s in lines[0].split('|')]
    need(len(fields)<=256 and all(re.fullmatch('[a-z][a-z0-9_]{0,63}',s) for s in fields),'build_info_invalid_header')
    need(len(set(fields))==len(fields) and {'active','buildkey'}<=set(fields),'build_info_missing_or_duplicate_header')
    selected=[]
    for line in lines[1:]:
        values=line.split('|');need(len(values)==len(fields),'build_info_row_width');row=dict(zip(fields,values))
        if row['active']!='1' or 'product' in row and row['product']!='wow':continue
        selected.append({k:row.get(k,'') for k in ('buildkey','cdnkey','version','tags')})
    need(len(selected)==1,'installed_retail_active_row_missing_or_ambiguous');row=selected[0]
    need(re.fullmatch('[0-9a-f]{32}',row['buildkey']) is not None,'installed_build_key_invalid')
    need(not row['cdnkey'] or re.fullmatch('[0-9a-f]{32}',row['cdnkey']) is not None,'installed_cdn_key_invalid')
    need(not row['version'] or re.fullmatch(r'[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}',row['version']) is not None,'installed_version_invalid')
    need(len(row['tags'])<=4096 and all(ord(c)>=32 for c in row['tags']),'installed_tags_invalid')
    return row

def verify_config(raw,key,version):
    need(hashlib.md5(raw).hexdigest()==key,'installed_config_md5_mismatch')
    try:text=raw.decode('utf-8-sig')
    except UnicodeError:raise ProbeError('installed_config_encoding') from None
    fields={};seen=set()
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        need('=' in line,'installed_config_syntax');name,value=line.split('=',1);name=name.strip()
        need(re.fullmatch('[A-Za-z0-9_-]{1,80}',name) is not None and name not in seen,'installed_config_syntax');seen.add(name)
        if name not in ('build-uid','build-name'):continue
        need(name not in fields,'installed_config_duplicate_identity');fields[name]=value.strip().split()
    need(fields.get('build-uid')==['wow'],'installed_config_not_retail_wow')
    names=fields.get('build-name',[]);m=re.fullmatch(r'WOW-([0-9]{1,10})patch([0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10})_Retail',names[0]) if len(names)==1 else None
    need(m is not None,'installed_build_name_unsupported');actual=m[2]+'.'+m[1]
    need(not version or version==actual,'installed_version_config_conflict');return actual

def profile_details(raw):
    counts=dict.fromkeys(TAG_FIELDS,0);tokens=set()
    if not raw or any(not c.strip() for c in raw.split(':')):
        return None,counts,'installed_tags_empty_or_malformed'
    for clause in raw.split(':'):
        for token in clause.split():
            counts['token_count']+=1;optional=token.endswith('?');counts['optional_suffix_count']+=int(optional)
            name=token[:-1] if optional else token
            if re.fullmatch('[A-Za-z0-9_]+',name) and name in KNOWN:
                counts['known_token_count']+=1;tokens.add(name)
            elif optional and re.fullmatch('acct-[A-Za-z0-9_]{1,32}',name):counts['account_qualifier_count']+=1
            elif optional and re.fullmatch('geoip-[A-Za-z0-9_]{1,32}',name):counts['geoip_qualifier_count']+=1
            else:
                counts['unknown_optional_count' if optional else 'unknown_plain_count']+=1
                if not re.fullmatch(r'[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*',name):counts['malformed_token_count']+=1
    if counts['unknown_plain_count'] or counts['unknown_optional_count']:
        return None,counts,'unknown_installed_tag_no_guess'
    choices=[tokens&v for v in (PLATFORMS,ARCHITECTURES,REGIONS)];locales=tokens&LOCALES
    if any(len(v)!=1 for v in choices) or not locales:return None,counts,'installed_profile_missing_or_ambiguous'
    platform,architecture,region=(next(iter(v)) for v in choices)
    if (platform,architecture,region)!=('Windows','x86_64','EU') or not locales<=SUPPORTED_LOCALES:
        return None,counts,'unsupported_installed_profile_no_fallback'
    return {'platform':platform,'architecture':architecture,'region':region,'locales':sorted(locales)},counts,None

def read(root,*,cancel=lambda:False,progress=lambda _:None):
    root=safe(root);need(root.is_dir(),'game_root_directory_required');w=Watch();started=time.monotonic()
    def checked():need(not cancel() and time.monotonic()-started<=120,'profile_probe_cancelled_or_time_limit');w.check()
    checked();progress('read_build_info');raw=w.read(root/'.build.info',MAX_INFO)
    progress('select_active_row');row=select_row(raw);checked();key=row['buildkey']
    progress('read_named_build_config');config=w.read(root/'Data'/'config'/key[:2]/key[2:4]/key,MAX_CONFIG)
    checked();progress('verify_build_config');version=verify_config(config,key,row['version'])
    progress('parse_profile_tags');profile,counts,error=profile_details(row['tags'])
    report={'format':'readonly-installed-profile-probe-1','probe_version':VERSION,
            'status':'identity_verified_profile_projected' if profile else 'identity_verified_profile_unresolved',
            'installed_identity':{'product':'wow','version':version,'build_config_md5':key,
                 'active_build_row_selected':True,'build_config_md5_verified':True,
                 'publisher_authentication_proven':False,'source':'local_build_info_and_named_config'},
            'profile':profile,'profile_error':error,'tag_syntax_counts':counts,
            'profile_source':'whitelisted_active_row_tag_projection_not_vendor_policy',
            'optional_suffix_is_recognized_syntax_not_vendor_selection_proof':True,
            'account_and_geoip_qualifiers_used_for_profile':False,
            'research_target_comparison':{'pinned_version':TARGET_VERSION,'same_build_config':key==TARGET_BUILD,
                                         'same_version':version==TARGET_VERSION,'version_order_evaluated':False},
            'scope':{'game_metadata_files_read':2,'game_metadata_bytes_read':w.read_bytes,
                     'max_build_info_bytes':MAX_INFO,'max_named_config_bytes':MAX_CONFIG,
                     'archive_payload_bytes_read':0,'archives_enumerated':False,'Lab_read_or_modified':False,
                     'raw_paths_or_account_labels_exported':False},
            'target_Download_tag_projection_computed':False,'actual_required_install_set_known':False,
            'bound_to_existing_Lab_snapshot':False,'profile_report_is_not_importable_content_proof':True,
            'installed_files_health_proven':False,'active_CASC_generation_proven':False,
            'network_requests':0,'game_files_modified':False,'apply_authorized':False,
            'required_network_download_bytes':None,'installation_ready':False,
            'consistency_model':'regular_file_stat_fingerprints_not_OS_snapshot_or_hostile_writer_protection'}
    progress('final_input_recheck');checked();return report,{'root':root,'watch':w}

def publish_noreplace(src,dst):
    if sys.platform=='win32':os.rename(src,dst)
    else:os.link(src,dst)

def publish(report,private,out,*,progress=lambda _:None):
    progress('prepare_report_output');out=Path(os.path.abspath(str(out)));root=private['root'];w=private['watch']
    need(out!=root and root not in out.parents and out not in root.parents,'profile_output_overlaps_game')
    existing=out
    while not existing.exists() and not existing.is_symlink():
        need(existing.parent!=existing,'profile_output_parent_missing');existing=existing.parent
    safe(existing);need(not out.exists() and not out.is_symlink(),'profile_new_output_required')
    for p in (out,*out.parents):
        need(not (p/'.build.info').exists() and not (p/'.build.db').exists() and not (p/'LAB-ONLY.json').exists(),'profile_output_in_game_or_Lab')
    w.check();out.mkdir(parents=True);tmp=out/('profile-'+uuid.uuid4().hex+'.pending');final=out/'INSTALLED-PROFILE-to-share.json';published=False
    try:
        progress('write_pending_report')
        with tmp.open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
        w.check();progress('publish_report_noreplace');publish_noreplace(tmp,final);published=True
        progress('postpublication_recheck');w.check()
    except BaseException:
        if published:final.unlink()
        raise
    finally:
        if tmp.exists():tmp.unlink()
    return final

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--game-root',type=Path,required=True);p.add_argument('--out-new',type=Path);x=p.parse_args();progress=Progress()
    try:
        q,private=read(x.game_root,progress=progress.mark)
        if x.out_new is not None:publish(q,private,x.out_new,progress=progress.mark)
        print(json.dumps(q,indent=2));return 0
    except KeyboardInterrupt:print(json.dumps({'status':'cancelled_safely','installation_ready':False}));return 130
    except (ProbeError,OSError,KeyError,TypeError,ValueError) as ex:print(json.dumps(public_error(ex,progress.stage)));return 1
if __name__=='__main__':raise SystemExit(main())
