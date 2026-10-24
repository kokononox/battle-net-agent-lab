"""Bounded PCAPNG -> private TCP byte runs. No addresses/bytes in shared reports.
Positive byte matches survive retransmissions; gaps, conflicts and unsupported
packet types are not treated as evidence of absence. Checksums not validated.
"""
import collections
import struct

MAX_FILE=128*1024*1024


def tcp_runs(raw):
    if len(raw)>MAX_FILE: raise ValueError('capture_size')
    rejected=[]; parsed=[]; conflicted=[]
    off=0; endian='<'; interfaces=[]; flows=collections.defaultdict(list)
    issues=collections.Counter(); packets=0; total=0
    while off<len(raw):
        if off+12>len(raw): raise ValueError('block_truncated')
        if raw[off:off+4]==b'\x0a\x0d\x0d\x0a':
            magic=raw[off+8:off+12]
            if magic not in (b'\x4d\x3c\x2b\x1a',b'\x1a\x2b\x3c\x4d'): raise ValueError('byte_order')
            endian='<' if magic==b'\x4d\x3c\x2b\x1a' else '>'; interfaces=[]
        kind,n=struct.unpack_from(endian+'II',raw,off)
        if n<12 or n%4 or off+n>len(raw) or struct.unpack_from(endian+'I',raw,off+n-4)[0]!=n: raise ValueError('block_bounds')
        body=raw[off+8:off+n-4];off+=n
        if kind==1:
            if len(body)<8: raise ValueError('interface')
            interfaces.append(struct.unpack_from(endian+'H',body)[0]);continue
        if kind!=6: continue
        if len(body)<20: raise ValueError('packet_header')
        idx,_,_,cap,orig=struct.unpack_from(endian+'5I',body)
        if idx>=len(interfaces) or cap>len(body)-20: raise ValueError('packet_bounds')
        frame=body[20:20+cap];packets+=1
        if packets>500000: raise ValueError('packet_limit')
        if cap<orig: issues['snapshot_truncated']+=1;continue
        link=interfaces[idx]
        if link==1:
            if len(frame)<14: issues['short_ethernet']+=1;continue
            et=struct.unpack_from('!H',frame,12)[0];p=14
            while et in (0x8100,0x88a8) and p+4<=len(frame): et=struct.unpack_from('!H',frame,p+2)[0];p+=4
            ip=frame[p:]
        elif link in (101,228,229):
            ip=frame;et=0x800 if ip and ip[0]>>4==4 else 0x86dd
        else: issues['unsupported_link']+=1;continue
        if et==0x800:
            if len(ip)<20: issues['short_ip']+=1;continue
            if ip[0]>>4!=4:issues['ip_bounds']+=1;rejected.append(frame);continue
            ihl=(ip[0]&15)*4;length=struct.unpack_from('!H',ip,2)[0]
            if ihl<20 or length<ihl or len(ip)<length: issues['ip_bounds']+=1;rejected.append(frame);continue
            if struct.unpack_from('!H',ip,6)[0]&0x3fff: issues['ip_fragments_unsupported']+=1;continue
            proto=ip[9];src=ip[12:16];dst=ip[16:20];seg=ip[ihl:length]
        elif et==0x86dd:
            if len(ip)<40: issues['short_ip6']+=1;continue
            if ip[0]>>4!=6:issues['ip6_bounds']+=1;continue
            length=40+struct.unpack_from('!H',ip,4)[0]
            if len(ip)<length: issues['ip6_bounds']+=1;continue
            proto=ip[6];src=ip[8:24];dst=ip[24:40];seg=ip[40:length]
            if proto in (0,43,44,60,51): issues['ipv6_extension_unsupported']+=1;continue
        else:continue
        if proto!=6:continue
        if len(seg)<20: issues['short_tcp']+=1;continue
        sp,dp,seq=struct.unpack_from('!HHI',seg);hl=(seg[12]>>4)*4
        if hl<20 or hl>len(seg): issues['tcp_bounds']+=1;continue
        data=seg[hl:]
        if not data:continue
        key=(src,sp,dst,dp)
        if key not in flows and len(flows)>=1024: raise ValueError('flow_limit')
        total+=len(data)
        if total>96*1024*1024:raise ValueError('payload_limit')
        flows[key].append(((seq+bool(seg[13]&2))&0xffffffff,data));parsed.append(data)
    runs=[]
    for key,segments in flows.items():
        anchor=segments[0][0]
        relative=sorted(((((seq-anchor+2**31)%2**32)-2**31,data) for seq,data in segments),key=lambda x:x[0])
        chunks=[];start=None;buf=bytearray();conflict=False
        for seq,data in relative:
            if start is None:start=seq;buf.extend(data);continue
            end=start+len(buf)
            if seq>end:chunks.append(bytes(buf));start=seq;buf=bytearray(data);continue
            overlap=min(end-seq,len(data))
            if overlap and bytes(buf[seq-start:seq-start+overlap])!=data[:overlap]:conflict=True;break
            buf.extend(data[overlap:])
        if conflict:issues['tcp_overlap_conflict']+=1;conflicted.extend(data for _,data in segments);continue
        if buf:chunks.append(bytes(buf))
        runs.append({'key':key,'chunks':chunks})
    return {'packets':packets,'issues':dict(issues),'runs':runs,'_private_rejected_ip_frames':rejected,'_private_valid_segments':parsed,'_private_conflicted_segments':conflicted}
