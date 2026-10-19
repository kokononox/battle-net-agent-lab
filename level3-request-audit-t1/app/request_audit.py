"""Bounded outgoing HTTP/1 reconstruction in RAM. Never export raw requests."""
import base64
from collections import Counter,defaultdict
import ipaddress
import json
import re
import socket
import urllib.parse
from core import Collector,decoded_cpu_match
from body_meta import FIELD_ALIASES,analyze_body
from http_input import parse_requests,MAX_STREAM

TARGET='level3.blizzard.com'
BLOCKED=tuple('''telemetry-in.battle.net breaking-news.support.blizzard.com rum.battle.net www.google-analytics.com analytics.google.com www.googletagmanager.com cm.g.doubleclick.net inn-pa.googleapis.com fcmatch.google.com eu.shop.battle.net bnetstorefront.akamaized.net catalog.blzstatic.com blz-contentstack-images.akamaized.net navbar.blizzard.com content-ui.battle.net images.blz-contentstack.com www.youtube.com www.youtube-nocookie.com fcmatch.youtube.com i.ytimg.com oauth.battle.net distribution.version.battle.net us.version.battle.net level3.ssl.blizzard.com'''.split())
KNOWN_HEADERS=set('host accept connection range user-agent content-length content-type content-encoding transfer-encoding authorization proxy-authorization cookie referer origin accept-encoding accept-language cache-control if-modified-since if-none-match'.split())
CAP_EVENTS=32768;CAP_BYTES=32*1024**2;CAP_CHANNELS=4096;CAP_REQUESTS=2048
REQUEST_KEYS=set('process_index channel layer host method path_class query_present query_pairs query_field_hints header_names unknown_header_count header_field_hints credential_header_present body_declared_bytes body_observed_bytes body_complete body_sample_truncated body_format body_field_hints cpu_literal_match user_agent_present local_api_only'.split())

def alias(k):return FIELD_ALIASES.get(re.sub('[^a-z0-9]','',k.lower()))
def classify_addresses(addresses):
    try:ips={ipaddress.ip_address(a) for a in addresses}
    except ValueError:return 'invalid_address'
    if not ips:return 'no_addresses'
    if all(a.is_loopback or a.is_unspecified for a in ips):return 'sink_only'
    if all(a.is_global for a in ips):return 'public_only'
    return 'mixed_or_nonpublic'

def probe():
    result={}
    for h in (*BLOCKED,TARGET):
        try:result[h]=classify_addresses(x[4][0] for x in socket.getaddrinfo(h,None,0,socket.SOCK_STREAM))
        except OSError:result[h]='resolution_failed'
    return result

def profile_ok(r):return set(r)==set((*BLOCKED,TARGET)) and all(r[h]=='sink_only' for h in BLOCKED) and r[TARGET]=='public_only'

def summarize_request(r,process,channel,needle):
    # Raw headers/target/body exist only inside this function and caller RAM.
    target=r['target'];headers=r['headers'];body=base64.b64decode(r['body_sample_base64'])
    query=target.partition('?')[2]
    try:pairs=urllib.parse.parse_qsl(query,keep_blank_values=True,max_num_fields=256)
    except ValueError:pairs=[]
    hints=sorted({a for k,v in pairs if (a:=alias(k))})
    names=[k for k,v in headers]
    # Recreate only for bounded local CPU matching including compressed bodies.
    raw=(r['method']+' '+target+' HTTP/1.1\r\n'+'\r\n'.join(k+': '+v for k,v in headers)+'\r\n\r\n').encode('latin1')+body
    meta=analyze_body(raw,len(raw));cpu=decoded_cpu_match(raw,needle)
    if needle and not cpu:
        cpu=needle in urllib.parse.unquote_to_bytes(raw.replace(b'+',b' '))
    return {'process_index':process,'channel':channel,'layer':'pre_tls_sspi_input' if channel.startswith('ctx') else 'plaintext_winsock_input',
        'host':r['host'],'method':r['method'],'path_class':'tpr' if target.split('?',1)[0].startswith('/tpr/') else 'other',
        'query_present':'?' in target,'query_pairs':min(257,query.count('&')+1) if query else 0,'query_field_hints':hints,
        'header_names':sorted(set(names)&KNOWN_HEADERS),'unknown_header_count':sum(n not in KNOWN_HEADERS for n in names),
        'header_field_hints':sorted({a for n in names if (a:=alias(n))}),
        'credential_header_present':bool(set(names)&{'cookie','authorization','proxy-authorization'}),
        'body_declared_bytes':r['body_declared_bytes'],'body_observed_bytes':r['body_observed_bytes'],
        'body_complete':r['body_complete'],'body_sample_truncated':r['body_sample_truncated'],
        'body_format':meta['format'],'body_field_hints':meta['field_name_hints'],'cpu_literal_match':cpu,
        'user_agent_present':'user-agent' in names,'local_api_only':True}

class AuditBuffer:
    def __init__(self,needle):
        self.needle=needle;self.channels=defaultdict(list);self.bytes=0;self.count=0;self.limited=False;self.frozen=None
    def add(self,key,e,raw):
        channel=(key,e['socket']);seq=e.get('sequence')
        if self.frozen is not None:return
        if type(seq) is not int or not 1<=seq<=1000000:self.limited=True;return
        if self.count>=CAP_EVENTS or self.bytes+len(raw)>CAP_BYTES or channel not in self.channels and len(self.channels)>=CAP_CHANNELS:
            self.limited=True;return
        self.channels[channel].append((seq,bytes(raw),e['accepted_bytes'],e['declared_bytes'],e.get('truncated') is True))
        self.count+=1;self.bytes+=len(raw)
    def finish(self):
        if self.frozen is not None:return self.frozen
        requests=[];streams=[];parsed=0
        for (key,tag),events in sorted(self.channels.items()):
            data=bytearray();gap=False;seen=set()
            for seq,raw,accepted,declared,truncated in sorted(events,key=lambda e:e[0]):
                if seq in seen or truncated or accepted is None or accepted>len(raw) or accepted==0 and declared>0 or len(data)+accepted>MAX_STREAM:
                    gap=True;break
                seen.add(seq);data.extend(raw[:accepted])
            rows,status=parse_requests(bytes(data),redact_secrets=False)
            parsed+=len(rows)
            if status=='request_limit':self.limited=True
            streams.append({'process_index':key,'channel':tag,'parse_status':status,'api_input_gap':gap,'prefix_bytes':len(data)})
            for r in rows:
                if len(requests)<CAP_REQUESTS:requests.append(summarize_request(r,key,tag,self.needle))
                else:self.limited=True
        target=[r for r in requests if r['host']==TARGET]
        summary={'exported_requests':len(requests),'parsed_requests_before_export_cap':parsed,
            'target_requests':len(target),'target_complete_requests':sum(r['body_complete'] for r in target),
            'target_nonzero_body_requests':sum(r['body_observed_bytes']>0 for r in target),
            'target_cpu_literal_matches':sum(r['cpu_literal_match'] is True for r in target),
            'target_credential_header_requests':sum(r['credential_header_present'] for r in target),
            'target_query_requests':sum(r['query_present'] for r in target),'method_counts':dict(Counter(r['method'] for r in target))}
        self.frozen={'summary':summary,'requests':requests,'streams':streams,'buffer_limit_hit':self.limited,
            'cpu_reference_available':bool(self.needle),'outgoing_only':True,'raw_exported':False,
            'zero_personal_data_proven':False,'received_bytes_measured':False}
        self.channels.clear();self.needle=None
        return self.frozen

class AuditCollector(Collector):
    def __init__(self,frida,needle,fixture_pid=None):
        super().__init__(frida,needle,fixture_pid);self.audit=AuditBuffer(needle)
    def message(self,key,msg,data):
        with self.lock:
            old=self.rows[key]['input_events'];super().message(key,msg,data)
            if self.rows[key]['input_events']!=old:self.audit.add(key,msg['payload'],bytes(data or b''))
    def close(self):
        super().close()
        with self.lock:self.audit.finish();self.needle=None
    def audit_report(self):
        with self.lock:return self.audit.finish()

def validate_audit(a):
    if set(a)!=set('summary requests streams buffer_limit_hit cpu_reference_available outgoing_only raw_exported zero_personal_data_proven received_bytes_measured'.split()):raise ValueError('audit_schema')
    if a['raw_exported'] is not False or a['zero_personal_data_proven'] is not False or a['received_bytes_measured'] is not False:raise ValueError('audit_scope')
    if len(a['requests'])>CAP_REQUESTS or len(a['streams'])>CAP_CHANNELS:raise ValueError('audit_bounds')
    for r in a['requests']:
        if set(r)!=REQUEST_KEYS:raise ValueError('request_schema')
        if not re.fullmatch(r'(?:s|ctx)\d{1,6}',r['channel']) or r['method'] not in {'GET','POST','HEAD','PUT','PATCH','DELETE','OPTIONS','CONNECT'}:raise ValueError('request_value')
        if r['path_class'] not in {'tpr','other'} or not set(r['header_names'])<=KNOWN_HEADERS:raise ValueError('request_values')
        if any(not set(r[k])<=set(FIELD_ALIASES.values()) for k in ('query_field_hints','header_field_hints','body_field_hints')):raise ValueError('field_hints')
    return a
