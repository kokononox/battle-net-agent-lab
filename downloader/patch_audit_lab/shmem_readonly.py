"""Bounded observation of copied/explicit shmem bytes; never an activation writer.
Constructor geometry is pinned to Agent 9824 static evidence, not a general CASC
specification. A matching header does not prove a coherent or installable store.
"""
import argparse,json,re,struct
from pathlib import Path
import patch_audit as a
import source_binding as b

MAX_CONTROL=64*1024
PATTERN=re.compile('[0-9a-f]{10}\\.idx')

def inspect(raw,index_names=None):
    a.require(isinstance(raw,bytes) and 0x150<=len(raw)<=MAX_CONTROL,'shmem_observation_size')
    version,header=struct.unpack_from('<II',raw)
    a.require(version in (4,5),'unobserved_shmem_protocol')
    payload_size,offset=struct.unpack_from('<II',raw,0x108)
    a.require(payload_size==0x2ab8,'unobserved_shmem_payload_size')
    expected_headers=(0x150,) if version==4 else (0x154,0x258)
    a.require(header in expected_headers,'unobserved_shmem_header_size')
    a.require(offset==(0x150 if version==4 else 0x1000),'unobserved_shmem_payload_offset')
    a.require(header<=offset and offset+payload_size<=len(raw),'shmem_observation_truncated')
    name=raw[8:0x108]
    a.require(name[0]!=0 and b'\0' in name,'shmem_name_field_shape')
    inventory=None
    if index_names is not None:
        a.require(isinstance(index_names,list) and len(index_names)<=512 and all(isinstance(n,str) and PATTERN.fullmatch(n) and int(n[:2],16)<16 for n in index_names),'shmem_index_name_list')
        a.require(len(set(index_names))==len(index_names),'shmem_duplicate_index_name')
        inventory=set(index_names)
    rows=[]
    for bucket,seq in enumerate(struct.unpack_from('<16I',raw,0x110)):
        name=f'{bucket:02x}{seq:08x}.idx'
        versions=[] if inventory is None else sorted(int(n[2:10],16) for n in inventory if int(n[:2],16)==bucket)
        rows.append({'bucket':bucket,'sequence':seq,'sequence_filename':name,'sequence_file_present':None if inventory is None else name in inventory,'max_inventory_sequence':max(versions,default=None),'inventory_has_newer_sequence':None if inventory is None else any(v>seq for v in versions)})
    flags=struct.unpack_from('<I',raw,0x150)[0] if version==5 else None
    return {'format':'shmem-bounded-observation-1','status':'constructor_geometry_matches_static_evidence','protocol':version,'header_bytes':header,'observed_file_bytes':len(raw),'sha256':a.sha256(raw),'payload_offset':offset,'payload_size':payload_size,'opaque_extra_bytes':len(raw)-offset-payload_size,'name_field_exported':False,'name_field_nonempty_terminated':True,'protocol5_flags_uninterpreted':flags,'protocol5_low_flag_special_path':bool(flags&1) if flags is not None else None,'sequence_observations':rows,'index_inventory_supplied':inventory is not None,'index_file_payloads_read':0,'coherent_live_snapshot_proven':False,'sequence_is_active_for_game_proven':False,'installation_ready':False}

def observe_file(path,index_names=None):
    path=Path(path);a.require(path.name=='shmem','explicit_shmem_filename_required')
    watch=b.Watch();first=watch.read(path,MAX_CONTROL);second=watch.read(path,MAX_CONTROL)
    a.require(first==second,'shmem_changed_between_reads');result=inspect(first,index_names);watch.check()
    result.update(files_read=1,read_passes=2,network_requests=0,files_written=0,stable_two_reads=True)
    # mmap changes may not reliably update filesystem mtime; even two equal reads
    # do not establish an OS-wide snapshot or exclusion from a running Agent.
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--shmem',required=True,type=Path);p.add_argument('--index-name',action='append');args=p.parse_args()
    print(json.dumps(observe_file(args.shmem,args.index_name),indent=2))
if __name__=='__main__':main()
