"""Bounded, read-only PML v9 metadata reader. No payload/DNS/symbol resolution.
Format reference: procmon-parser 0.4.0 (MIT); independent implementation.
Unknown format or malformed input fails closed; never repairs original input.
"""
import collections, functools, ipaddress, ntpath, struct, time
from pathlib import Path
HEADER=0x3a8
EVENT=struct.Struct('<IIIHHIQQIHHII')
OPS={2:'Send',3:'Receive',4:'Accept',5:'Connect',6:'Disconnect',7:'Reconnect',8:'Retransmit',9:'TCPCopy'}
MAX_FILE=512*1024**2

def norm(s): return ntpath.normcase(ntpath.normpath(s))
def leaf(s): return ntpath.basename(s).replace('\x00','')[:160]
class PmlError(ValueError): pass

def analyze(path, selected, seconds=90):
    path=Path(path); before=path.stat()
    if before.st_size>MAX_FILE: raise PmlError('pml_over_512MiB_read_limit')
    if before.st_size<HEADER: raise PmlError('pml_too_short')
    deadline=time.monotonic()+seconds
    with path.open('rb') as f:
        size=before.st_size
        def read(pos,n):
            if n<0 or pos<0 or pos+n>size: raise PmlError('pml_out_of_bounds')
            f.seek(pos); b=f.read(n)
            if len(b)!=n: raise PmlError('pml_short_read')
            return b
        def u32(p):return struct.unpack('<I',read(p,4))[0]
        def u64(p):return struct.unpack('<Q',read(p,8))[0]
        def tick():
            if time.monotonic()>deadline:raise PmlError('pml_analysis_time_limit')
        h=read(0,HEADER)
        if h[:4]!=b'PML_':raise PmlError('not_pml')
        version=struct.unpack_from('<I',h,4)[0]
        if version!=9:raise PmlError('unsupported_pml_version_'+str(version))
        bits=struct.unpack_from('<I',h,8)[0]
        if bits not in (0,1):raise PmlError('pml_architecture_unknown')
        ptr=8 if bits else 4
        total=struct.unpack_from('<I',h,0x234)[0]
        if total>1500000:raise PmlError('pml_event_limit')
        ev,idx,pt,st,icons=struct.unpack_from('<QQQQQ',h,0x240)
        if any(x<HEADER or x>=size for x in (ev,idx,pt,st,icons,u64(0x3a0))):raise PmlError('pml_not_finalized_or_invalid')
        if u64(0x398)!=HEADER or ev>=idx or idx+total*5>size:raise PmlError('pml_header_invalid')
        sc=u32(st)
        if sc>1000000 or st+4+sc*4>size:raise PmlError('pml_string_table_limit')
        @functools.lru_cache(maxsize=4096)
        def string(i):
            if i>=sc:raise PmlError('pml_string_index_invalid')
            p=st+u32(st+4+i*4); n=u32(p)
            if n>65536 or n%2:raise PmlError('pml_string_size_invalid')
            return read(p+4,n).decode('utf-16le','strict').split('\0',1)[0]
        count=u32(pt)
        if count>4096 or pt+4+count*8>size:raise PmlError('pml_process_limit')
        procs={}; module_total=0
        for i in range(count):
            tick();p=pt+u32(pt+4+count*4+i*4);b=read(p,96)
            pi,pid,parent=struct.unpack_from('<III',b)
            if pi in procs:raise PmlError('pml_duplicate_process_index')
            start,end=struct.unpack_from('<QQ',b,32)
            image=string(struct.unpack_from('<I',b,68)[0])
            nm=u32(p+96+ptr)
            module_total+=nm
            if nm>4096 or module_total>200000:raise PmlError('pml_module_limit')
            procs[pi]={'pid':pid,'parent_pid':parent,'start':start,'end':end,'image':image,
                       'modules_pos':p+100+ptr,'module_count':nm}
        roots={i for i,p in procs.items() if norm(p['image'])==norm(selected)}
        if not roots:raise PmlError('selected_image_not_observed')
        chosen=set(roots); relationship={i:'selected_exact_image' for i in roots}
        # PID + creation/lifetime inference is explicitly a candidate, never proven ancestry.
        changed=True
        while changed:
            changed=False
            for i,p in procs.items():
                if i in chosen or not p['start']:continue
                candidates=[j for j,q in procs.items() if q['pid']==p['parent_pid'] and q['start'] and q['start']<=p['start'] and (not q['end'] or q['end']>=p['start'])]
                if len(candidates)==1 and candidates[0] in chosen:
                    chosen.add(i);relationship[i]='pid_lifetime_descendant_candidate';changed=True
        folder=ntpath.dirname(norm(selected))+'\\'
        for i,p in procs.items():
            if i not in chosen and norm(p['image']).startswith(folder):
                chosen.add(i);relationship[i]='game_folder_candidate_only'
        if len(chosen)>256:raise PmlError('selected_process_limit')
        modules={}
        for i in chosen:
            p=procs[i];items=[];ms=48+2*ptr
            for j in range(p['module_count']):
                b=read(p['modules_pos']+j*ms,ms)
                base=struct.unpack_from('<Q' if ptr==8 else '<I',b,ptr)[0]
                length,si=struct.unpack_from('<II',b,2*ptr)
                name=leaf(string(si))
                if length and name:items.append((base,base+length,name))
            modules[i]=items
        rows={}; net_count=0;selected_events=0;unknown_network=0;receive_events=0
        for e in range(total):
            if e%512==0:tick()
            off=struct.unpack('<I',read(idx+e*5,4))[0]
            if off<ev or off+EVENT.size>idx:raise PmlError('pml_event_offset_invalid')
            b=read(off,EVENT.size)
            pi,tid,cls,op,_,__,duration,date,result,depth,___,detail,extra=EVENT.unpack(b)
            if off+EVENT.size+depth*ptr+detail>idx:raise PmlError('pml_event_size_invalid')
            if pi not in chosen:continue
            selected_events+=1
            if cls!=5:continue
            net_count+=1
            if op not in OPS:unknown_network+=1;continue
            if op==3:receive_events+=1
            # Only send/connect/reconnect/retransmit endpoints are summarized as outgoing.
            if op not in (2,5,7,8):continue
            if depth>256 or detail<44 or detail>1024*1024:raise PmlError('pml_network_detail_invalid')
            d=read(off+EVENT.size+depth*ptr,44)
            flags=struct.unpack_from('<H',d)[0]
            if flags & ~7:raise PmlError('pml_network_flags_unknown')
            length=struct.unpack_from('<I',d,4)[0]
            dest=d[24:40];addr=str(ipaddress.ip_address(dest[:4] if flags&2 else dest))
            port=struct.unpack_from('<H',d,42)[0];proto='TCP' if flags&4 else 'UDP'
            key=(pi,addr,port,proto,OPS[op],result)
            if key not in rows:
                if len(rows)>=5000:raise PmlError('network_summary_limit')
                rows[key]={'process_index':pi,'remote_ip':addr,'remote_port':port,'protocol':proto,
                           'operation':OPS[op],'result_code':result,'event_count':0,
                           'successful_send_length_sum':0,'stack_module_hints':set(),'unmapped_stack_frames':0}
            r=rows[key];r['event_count']+=1
            if op==2 and result==0:r['successful_send_length_sum']+=length
            raw=read(off+EVENT.size,depth*ptr)
            for at in struct.unpack('<'+('Q' if ptr==8 else 'I')*depth,raw):
                matches={n for lo,hi,n in modules[pi] if lo<=at<hi}
                if len(matches)==1:r['stack_module_hints'].update(matches)
                else:r['unmapped_stack_frames']+=1
        out=[]
        for key in sorted(rows):
            r=rows[key];r['stack_module_hints']=sorted(r['stack_module_hints']);out.append(r)
        result={'status':'metadata_observed' if net_count else 'no_network_events_observed_in_this_window',
                'pml_version':version,'raw_file_bytes':size,'total_events_scanned':total,
                'selected_events':selected_events,'selected_network_events':net_count,
                'receive_event_count_without_endpoint_attribution':receive_events,'unknown_network_operations':unknown_network,
                'processes':[{'process_index':i,'pid':procs[i]['pid'],'image_name':leaf(procs[i]['image']),
                              'scope':relationship[i],'module_basenames':sorted({n for _,__,n in modules[i]})} for i in sorted(chosen)],
                'outgoing_observations':out,
                'limits':['No TLS plaintext or CPU/BIOS upload determination.',
                          'Module names/stack ranges are hints, not proof a DLL independently sent a request.',
                          'PID/lifetime and game-folder candidates are not proven child-process attribution.',
                          'No observations is not proof of no traffic; this is a short, system-wide metadata capture.',
                          'Send length sums are Procmon metadata, not unique uploaded payload or wire bytes.',
                          'IP addresses are not domain bindings; no online DNS or symbol lookup was performed.']}
    after=path.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise PmlError('pml_changed_during_read')
    return result
