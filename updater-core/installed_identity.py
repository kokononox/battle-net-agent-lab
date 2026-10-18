"""Validate two uploaded metadata copies; no live installation IO or network."""
import hashlib
import json
import re

LOCALES=set('deDE enUS enGB esES esMX frFR itIT koKR ptBR ptPT ruRU zhCN zhTW'.split())
PLATFORMS={'Windows','OSX'}
ARCHITECTURES={'x86_32','x86_64','ARM64'}
REGIONS={'EU','US','KR','TW','CN'}
KNOWN=LOCALES|PLATFORMS|ARCHITECTURES|REGIONS|{'code','speech','text'}

class InvalidMetadata(ValueError):pass

def need(ok,code):
    if not ok:raise InvalidMetadata(code)

def select_active(raw):
    need(type(raw) is bytes and 0<len(raw)<=1048576,'build_info_size_limit')
    lines=[l for l in raw.decode('utf-8-sig').splitlines() if l.strip() and not l.lstrip().startswith('#')]
    need(2<=len(lines)<=2049,'build_info_row_count')
    cols=[c.split('!',1)[0].replace(' ','').lower() for c in lines[0].split('|')]
    need(len(set(cols))==len(cols) and len(cols)<=256 and {'active','buildkey'}<=set(cols),'invalid_header')
    rows=[]
    for line in lines[1:]:
        vals=line.split('|');need(len(vals)==len(cols),'invalid_row_width')
        row=dict(zip(cols,vals))
        if row['active']=='1' and ('product' not in row or row['product']=='wow'):
            rows.append({k:row.get(k,'') for k in ('buildkey','version','tags')})
    need(len(rows)==1,'active_retail_row_missing_or_ambiguous')
    row=rows[0];need(re.fullmatch('[0-9a-f]{32}',row['buildkey']) is not None,'invalid_build_key')
    need(not row['version'] or re.fullmatch(r'[0-9]{1,10}(?:\.[0-9]{1,10}){3}',row['version']) is not None,'invalid_version')
    return row

def profile(raw):
    need(type(raw) is str and 0<len(raw)<=4096,'tags_size_or_empty')
    need(all(ord(c)>=32 and ord(c)!=127 for c in raw),'tags_control_character')
    need(all(c.strip() for c in raw.split(':')),'tags_empty_clause')
    tokens=set();withheld=0
    for clause in raw.split(':'):
        for token in clause.split():
            optional=token.endswith('?');name=token[:-1] if optional else token
            if name in KNOWN:tokens.add(name)
            elif optional and re.fullmatch(r'(?:acct|geoip)-[A-Za-z0-9_]{1,32}',name):withheld+=1
            else:raise InvalidMetadata('unknown_tag_no_guess')
    groups=[tokens&s for s in (PLATFORMS,ARCHITECTURES,REGIONS)]
    need(all(len(g)==1 for g in groups) and bool(tokens&LOCALES),'ambiguous_profile')
    platform,architecture,region=(next(iter(g)) for g in groups)
    return {'platform':platform,'architecture':architecture,'region':region,'locales':sorted(tokens&LOCALES)},withheld

def validate(info,config):
    row=select_active(info)
    need(type(config) is bytes and 0<len(config)<=4194304,'config_size_limit')
    need(hashlib.md5(config).hexdigest()==row['buildkey'],'config_md5_conflict')
    fields={}
    for line in config.decode('utf-8-sig').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        need('=' in line,'config_syntax')
        k,v=line.split('=',1);k=k.strip()
        need(k not in fields and re.fullmatch('[A-Za-z0-9_-]{1,80}',k) is not None,'config_duplicate_or_invalid_key')
        fields[k]=v.strip().split()
    need(fields.get('build-uid')==['wow'],'config_not_wow')
    names=fields.get('build-name',[])
    m=re.fullmatch(r'WOW-([0-9]{1,10})patch([0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10})_Retail',names[0]) if len(names)==1 else None
    need(m is not None,'config_not_retail')
    version=m[2]+'.'+m[1]
    need(not row['version'] or row['version']==version,'version_conflict')
    p,count=profile(row['tags'])
    return {'format':'uploaded-installed-baseline-1','status':'UPLOADED_METADATA_COPIES_VALIDATED',
        'installed_version_from_uploaded_metadata':version,'profile_from_uploaded_metadata':p,
        'installed_build_config_md5':row['buildkey'],
        'build_info_bytes':len(info),'build_config_bytes':len(config),
        'build_info_sha256':hashlib.sha256(info).hexdigest(),
        'build_config_sha256':hashlib.sha256(config).hexdigest(),
        'private_optional_qualifiers_withheld':count,
        'raw_tags_or_account_qualifiers_exported':False,
        'build_info_config_identity_consistent':True,
        'target_version':None,'uploaded_copies_only':True,
        'live_installation_state_revalidated':False,
        'vendor_install_selection_policy_proven':False,
        'payload_health_verified':False,'installation_ready':False,'apply_authorized':False,
        'required_network_download_bytes':None,
        'assistant_live_game_or_lab_access':False,'assistant_game_downloads':0,'assistant_game_writes':0}
