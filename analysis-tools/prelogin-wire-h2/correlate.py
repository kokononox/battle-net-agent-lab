"""Evidence ladder. Runtime bytes stay private; exports only allowlisted summaries.
A synchronous accepted socket write != network observation != HTTP acceptance.
"""
import collections
import re

KNOWN={'telemetry-in.battle.net','ingest.gdp.blizzard.com','example.com'}
LIMIT=1024*1024


def socket_streams(events,kind):
    groups=collections.defaultdict(list)
    for e in events:
        if e['kind']==kind: groups[(e['pid'],e['socket'])].append(e)
    out={}
    for key,rows in groups.items():
        if any(e.get('ambiguous') for e in rows):continue
        chunks=[];buf=bytearray()
        for e in sorted(rows,key=lambda e:e['order']):
            n=e.get('accepted_bytes')
            if type(e.get('return_code')) is not int or e['return_code']<0 or e.get('asynchronous') or n is None or not e.get('complete') or type(n) is not int or not 0<=n<=len(e['raw']):
                if buf:chunks.append(bytes(buf));buf.clear()
                continue
            buf.extend(e['raw'][:n])
            if len(buf)>LIMIT:break
        else:
            if buf:chunks.append(bytes(buf))
            out[key]=chunks
    return out


def locations(needle,runs):
    if len(needle)<16:return []
    result=[]
    for key,chunks in runs.items():
        for chunk in chunks:
            pos=chunk.find(needle)
            while pos!=-1:
                result.append(key)
                if len(result)>1:return result
                pos=chunk.find(needle,pos+1)
    return result


def chain(record,sends,packets):
    if record.get('return_code')!=0 or not record.get('complete'):return None
    needle=record.get('after',b'')
    match=locations(needle,sends)
    if len(match)!=1 or match[0][0]!=record['pid']:return None
    packet=locations(needle,{r['key']:r['chunks'] for r in packets.get('runs',[])})
    return {'socket':match[0],'wire':packet[0] if len(packet)==1 else None}


def requests(data):
    """Strict Content-Length HTTP/1 request framing; no resync into body strings."""
    pos=0;result=[]
    while pos<len(data) and len(result)<64:
        end=data.find(b'\r\n\r\n',pos)
        if end<0 or end-pos>16384:return result,'incomplete_headers'
        lines=data[pos:end].split(b'\r\n')
        match=re.fullmatch(rb'(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS) ([^\x00-\x20\x7f]{1,4096}) HTTP/1\.[01]',lines[0])
        if not match:return result,'unsupported_request_boundary'
        headers=collections.defaultdict(list)
        for line in lines[1:]:
            k,sep,v=line.partition(b':')
            if not sep or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+",k) or any(x<32 and x!=9 for x in v):return result,'invalid_headers'
            headers[k.lower()].append(v.strip())
        if len(headers[b'host'])!=1:return result,'invalid_host'
        if headers[b'transfer-encoding']:return result,'transfer_encoding_unsupported'
        lens=headers[b'content-length']
        if len(lens)>1 or (lens and not re.fullmatch(rb'[0-9]{1,7}',lens[0])):return result,'invalid_length'
        size=int(lens[0]) if lens else 0
        if size>LIMIT:return result,'body_limit'
        stop=end+4+size
        if stop>len(data):return result,'incomplete_body'
        result.append({'start':pos,'stop':stop,'host':headers[b'host'][0].decode('ascii',errors='replace').lower().removesuffix(':443'),
                       'body':data[end+4:stop],'content_type':headers[b'content-type'][0].decode('ascii',errors='replace') if len(headers[b'content-type'])==1 else '',
                       'method':match[1].decode(),'target':match[2]})
        pos=stop
    return result,'complete' if pos==len(data) else 'request_limit'


def analyze(events,packets,classify=None):
    sends=socket_streams(events,'send');recvs=socket_streams(events,'recv')
    groups=collections.defaultdict(list)
    for e in events:
        if e['kind']=='encrypt':groups[(e['pid'],e['context'])].append(e)
    output=[];parsing=collections.Counter()
    for (pid,ctx),rows in groups.items():
        rows=sorted(rows,key=lambda e:e['order'])
        if any(e.get('return_code')!=0 or not e.get('complete') for e in rows):parsing['context_has_failed_or_incomplete_encryption']+=1;continue
        if any(a['sequence']>b['order'] for a,b in zip(rows,rows[1:])):parsing['concurrent_context']+=1;continue
        plain=b''.join(e['before'] for e in rows)
        if len(plain)>LIMIT:parsing['context_limit']+=1;continue
        reqs,status=requests(plain);parsing[status]+=1
        offsets=[];pos=0
        for e in rows: offsets.append((pos,pos+len(e['before']),e));pos+=len(e['before'])
        for r in reqs:
            relevant=[e for a,b,e in offsets if a<r['stop'] and b>r['start']]
            links=[chain(e,sends,packets) for e in relevant]
            socket_ok=bool(links) and all(links) and len({x['socket'] for x in links if x})==1
            packet_ok=socket_ok and all(x['wire'] is not None for x in links) and len({x['wire'] for x in links})==1
            name=r['host'] if r['host'] in KNOWN else 'other'
            item={'destination':name,'method':r['method'],'tls_record_count':len(relevant),
                  'hardware_payload_verified':False,'hardware_field_count':0,
                  'cpu_reference_match':False,'socket_send_linked':bool(socket_ok),
                  'packet_bytes_linked':bool(packet_ok),'http_response_status':None,
                  'server_storage_proven':False}
            if classify:
                item.update(classify(r,rows[0]['process_sha256']))
            # Only a sole fully framed request on this context has unambiguous
            # request/response pairing here. Do not guess pipelining/H2 semantics.
            if packet_ok and len(reqs)==1 and status=='complete':
                incoming=[e for e in events if e['kind']=='decrypt' and e['pid']==pid and e['context']==ctx and e.get('return_code')==0 and e.get('complete')]
                incoming=sorted(incoming,key=lambda e:e['order'])
                response=b''.join(e['after'] for e in incoming)
                m=re.match(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?: |\r\n)',response)
                ordered=all(a['sequence']<=b['order'] for a,b in zip(incoming,incoming[1:]))
                after_request=all(e['order']>max(x['sequence'] for x in relevant) for e in incoming)
                if m and incoming and ordered and after_request:
                    same_socket=links[0]['socket'];wire=links[0]['wire'];reverse=(wire[2],wire[3],wire[0],wire[1])
                    checks=[]
                    for e in incoming:
                        raw=e['before'];rx=locations(raw,recvs);pk=locations(raw,{x['key']:x['chunks'] for x in packets['runs']})
                        checks.append(len(rx)==1 and rx[0]==same_socket and len(pk)==1 and pk[0]==reverse)
                    if all(checks):item['http_response_status']=int(m[1])
            output.append(item)
    return {'requests':output,'parse_states':dict(parsing),
            'network_linked_hardware_requests':sum(x['hardware_payload_verified'] and x['packet_bytes_linked'] for x in output),
            'request_count':len(output)}
