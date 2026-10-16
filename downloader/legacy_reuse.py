"""Bounded import of old cache claims. Claims are NOT proof and never authorize install.

Only explicit caller-chosen roots; absolute paths/origins in old JSON are ignored.
Historical version equality is not required: full CURRENT content binding is later
required by reuse_coordinator. No game files, recursive discovery or execution.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import unicodedata
import repair_core as core

MAX_JSON=4*1024**2
MAX_CLAIMS=4096
HEX=re.compile(r'^[0-9a-f]{32}$')
SHA=re.compile(r'^[0-9a-f]{64}$')


@dataclass(frozen=True)
class Import:
    kind: str  # decoded_v030, download_v025, supply_cache
    manifest: Path
    root: Path


@dataclass(frozen=True)
class Claim:
    kind: str
    path: Path
    ckey: str
    decoded_size: int
    ekey: object = None
    encoded_size: object = None
    sha256: object = None


def relative(name):
    if not isinstance(name,str) or not name or len(name)>240:
        raise core.RepairError('legacy_relative_path_invalid')
    for p in name.split('/'):
        if (not p or p in ('.','..') or p[-1:] in (' ','.') or
                re.search(r'[\\:<>"|?*\x00-\x1f]',p) or
                p.split('.')[0].upper() in {'CON','PRN','AUX','NUL',
                    *('COM'+str(i) for i in range(10)),*('LPT'+str(i) for i in range(10))}):
            raise core.RepairError('legacy_relative_path_invalid')
    return name


def _pairs(items):
    out={}
    for k,v in items:
        if k in out:raise core.RepairError('legacy_duplicate_json_key')
        out[k]=v
    return out


def load(path,cancel):
    path=core.regular(path);fp=list(core.fingerprint(path.stat()))
    if fp[2]>MAX_JSON:raise core.RepairError('legacy_json_size_limit')
    with path.open('rb') as f:
        if list(core.fingerprint(os.fstat(f.fileno())))!=fp:
            raise core.RepairError('legacy_manifest_changed')
        core.check(cancel);raw=f.read(MAX_JSON+1)
        if list(core.fingerprint(os.fstat(f.fileno())))!=fp:
            raise core.RepairError('legacy_manifest_changed')
    if len(raw)!=fp[2] or list(core.fingerprint(core.regular(path).stat()))!=fp:
        raise core.RepairError('legacy_manifest_changed')
    try:
        obj=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=_pairs,
            parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except (ValueError,UnicodeError,RecursionError):
        raise core.RepairError('legacy_json_invalid') from None
    if not isinstance(obj,dict):raise core.RepairError('legacy_json_object_required')
    return obj,fp


def _key(value):
    if not isinstance(value,str) or not HEX.fullmatch(value):
        raise core.RepairError('legacy_full_content_key_required')
    return value


def _size(value):
    if type(value) is not int or not 0<=value<=2*1024**3:
        raise core.RepairError('legacy_content_size_invalid')
    return value


def read(item,cancel):
    """Return only claims and manifest identity; no payload opened here."""
    root=core.safe(item.root)
    if not root.is_dir():raise core.RepairError('legacy_explicit_root_required')
    obj,fp=load(item.manifest,cancel)
    files=obj.get('files')
    if not isinstance(files,list) or not 1<=len(files)<=MAX_CLAIMS:
        raise core.RepairError('legacy_claim_count_limit')
    if item.kind=='decoded_v030':
        if (obj.get('tool')!='WoW Retail Verified Decoded Staging 0.30' or
            obj.get('status')!='all_listed_outputs_staged_and_verified' or
            obj.get('copy_or_activation_authorized') is not False):
            raise core.RepairError('legacy_v030_manifest_shape_invalid')
    elif item.kind not in ('download_v025','supply_cache'):
        raise core.RepairError('unsupported_legacy_import_kind')
    claims=[];seen={}
    def add(kind,rel,ck,ds,ek=None,es=None,sha=None):
        rel=relative(rel)
        if sha is not None and (not isinstance(sha,str) or not SHA.fullmatch(sha)):
            raise core.RepairError('legacy_sha256_invalid')
        normalized=unicodedata.normalize('NFC',rel).casefold()
        key=(kind,normalized)
        path=core.safe(root/rel)
        claim=Claim(kind,path,_key(ck),_size(ds),
            _key(ek) if ek is not None else None,_size(es) if es is not None else None,sha)
        if key in seen:
            # Old supply plans repeat an identical decoded candidate for each
            # EKey alternative. Collapse only EXACT identical claims, not case
            # aliases or conflicting content/size claims.
            if item.kind=='supply_cache' and seen[key]==(rel,claim):return
            raise core.RepairError('legacy_duplicate_normalized_source')
        seen[key]=(rel,claim)
        claims.append(claim)
        if len(claims)>MAX_CLAIMS:raise core.RepairError('legacy_claim_count_limit')
    for record in files:
        core.check(cancel)
        if not isinstance(record,dict):raise core.RepairError('legacy_claim_object_required')
        if item.kind=='decoded_v030':
            if record.get('decoded_sha256') is None:raise core.RepairError('legacy_sha256_required')
            add('decoded',record.get('relative_output'),record.get('ckey'),record.get('decoded_bytes'),sha=record['decoded_sha256'])
        elif item.kind=='download_v025':
            ek=_key(record.get('ekey'));rel=record.get('relative_output')
            if not isinstance(rel,str) or not re.fullmatch(r'Targeted-Staging-[0-9a-f]{16}/'+ek+r'\.blte',rel):
                raise core.RepairError('legacy_v025_output_geometry_invalid')
            if record.get('encoded_sha256') is None:raise core.RepairError('legacy_sha256_required')
            add('encoded',rel,record.get('target_ckey'),record.get('target_decoded_bytes'),ek,record.get('encoded_bytes'),record['encoded_sha256'])
        else:
            ck=_key(record.get('target_ckey'));ds=_size(record.get('target_decoded_bytes'))
            alternatives=record.get('alternatives',[]);candidates=record.get('candidates',[])
            if (not isinstance(alternatives,list) or not isinstance(candidates,list) or
                    len(alternatives)>256 or len(candidates)>MAX_CLAIMS):
                raise core.RepairError('legacy_supply_nested_limit')
            sizes={}
            for alt in alternatives:
                if not isinstance(alt,dict):raise core.RepairError('legacy_supply_alternative_invalid')
                ek=_key(alt.get('ekey'));es=alt.get('encoded_bytes')
                if es is None:continue
                es=_size(es)
                if ek in sizes and sizes[ek]!=es:raise core.RepairError('legacy_supply_size_conflict')
                sizes[ek]=es
            for candidate in candidates:
                if not isinstance(candidate,dict):raise core.RepairError('legacy_supply_candidate_invalid')
                kind=candidate.get('kind');rel=candidate.get('source_relative_path')
                if kind=='decoded':add(kind,rel,ck,ds)
                elif kind=='encoded':
                    ek=_key(candidate.get('ekey'))
                    if ek not in sizes:continue
                    add(kind,rel,ck,ds,ek,sizes[ek])
                else:raise core.RepairError('legacy_supply_candidate_kind_invalid')
    return claims,core.regular(item.manifest),fp
