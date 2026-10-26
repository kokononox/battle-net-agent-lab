"""Research prototype: complete-request admission, NOT a transparent network filter.

No socket, TLS interception, process hook or installer launch is implemented here.
The caller must supply one complete bounded plaintext HTTP/1 request. Unknown
input is denied. Only reconstructed, independently public request bytes emerge.
"""
from dataclasses import dataclass
from pathlib import Path
import copy,re,json
from download_path_audit import Reference,load_reference,range_semantics
from schema_attribution import load_extra_refs,public_config_paths,table

VERSION_HOST='us.version.battle.net'
CDN_HOST='level3.blizzard.com'
MAX_REQUEST=16384
MAX_HEADERS=32
FIXED_UA='phoenix-agent/1.0'  # G67 independently pinned bootstrap literal only.

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    host: str = ''
    wire: bytes = b''  # Internal only: never serialize into evidence/logs.
    def audit(self):
        return {'allowed':self.allowed,'reason':self.reason,
                'destination_class':('version_host' if self.host==VERSION_HOST else
                                     'CDN_host' if self.host==CDN_HOST else 'none'),
                'raw_values_exported':False,'fingerprinting_absence_proven':False}

def deny(reason):return Decision(False,reason)

class Policy:
    def __init__(self,public_paths,metadata_routes):
        # Defensive copy: caller-owned dictionaries cannot later alter a decision.
        self._paths=Reference(copy.deepcopy(dict(public_paths)))
        self._paths.ranges=copy.deepcopy(getattr(public_paths,'ranges',{}))
        self._routes=frozenset(metadata_routes)

    def evaluate(self,request):
        if type(request) is not bytes:return deny('input_type')
        if not request or len(request)>MAX_REQUEST:return deny('request_size')
        cut=request.find(b'\r\n\r\n')
        if cut<0:return deny('incomplete_request')
        if cut+4!=len(request):return deny('body_or_trailing_bytes')
        head=request[:cut]
        # No bare newlines, tabs, obs-fold, NUL or non-ASCII ambiguity.
        if any(c<32 or c>126 for c in head.replace(b'\r\n',b'')):
            return deny('noncanonical_octet')
        lines=head.decode('ascii').split('\r\n')
        first=lines[0].split(' ')
        if len(first)!=3 or first[0]!='GET' or first[2]!='HTTP/1.1':
            return deny('method_or_request_line')
        target=first[1]
        if not target.startswith('/') or target.startswith('//') or '?' in target or '#' in target:
            return deny('request_target')
        if not 1<=len(lines)-1<=MAX_HEADERS:return deny('header_count')
        headers={}
        permitted={'host','accept','connection','user-agent','range','content-length'}
        for line in lines[1:]:
            if ':' not in line:return deny('header_syntax')
            name,value=line.split(':',1)
            if not re.fullmatch(r'[A-Za-z][A-Za-z-]*',name):return deny('header_syntax')
            name=name.lower();value=value.strip(' ')
            if name in headers:return deny('duplicate_header')
            if name not in permitted:return deny('unapproved_header')
            headers[name]=value
        host=headers.get('host')
        if host not in (VERSION_HOST,CDN_HOST):return deny('unapproved_host')
        if 'content-length' in headers and headers['content-length']!='0':return deny('body_framing')
        if 'accept' in headers and headers['accept']!='*/*':return deny('unapproved_accept')
        if 'connection' in headers and headers['connection'] not in ('close','keep-alive'):
            return deny('unapproved_connection')
        if 'user-agent' in headers and headers['user-agent']!=FIXED_UA:
            return deny('unapproved_user_agent')
        canonical_range=None
        if host==VERSION_HOST:
            if target not in self._routes:return deny('metadata_route_not_pinned')
            if 'range' in headers:return deny('metadata_range_not_supported')
        else:
            if target not in self._paths:return deny('CDN_path_not_pinned')
            if 'range' in headers:
                r=range_semantics(target,[headers['range']],self._paths)
                if not r['exact_public_boundary_match']:return deny('range_not_exact_public_boundary')
                match=re.fullmatch(r'bytes=([0-9]{1,20})-([0-9]{1,20})',headers['range'])
                if not match:return deny('range_syntax')
                canonical_range='bytes='+str(int(match[1]))+'-'+str(int(match[2]))
        # Do NOT forward raw input headers, UA, whitespace, casing or framing.
        # Only exact public target and validated canonical range may vary.
        wire=('GET '+target+' HTTP/1.1\r\nHost: '+host+
              '\r\nAccept: */*\r\nConnection: close\r\n'+
              ('Range: '+canonical_range+'\r\n' if canonical_range else '')+'\r\n').encode('ascii')
        return Decision(True,'canonical_public_request',host,wire)

class CompleteRequestGate:
    """No output from feed(). finish() admits exactly one complete message once.

    Fragment acquisition/completion is a trusted-adapter responsibility; EOF in
    the synthetic harness is NOT a usable transparent HTTP client protocol.
    """
    def __init__(self,policy):self._policy=policy;self._buffer=bytearray();self._failure=None;self._finished=False
    def feed(self,chunk):
        if self._finished:return False
        if self._failure:return False
        if type(chunk) is not bytes:self._failure='input_type';self._buffer.clear();return False
        if len(self._buffer)+len(chunk)>MAX_REQUEST:
            self._failure='request_size';self._buffer.clear();return False
        self._buffer.extend(chunk);return True
    def finish(self):
        if self._finished:return deny('gate_already_finished')
        self._finished=True
        try:
            if self._failure:return deny(self._failure)
            return self._policy.evaluate(bytes(self._buffer))
        except Exception:
            # Never stringify attacker input or exception messages to evidence.
            return deny('validation_failure')
        finally:self._buffer.clear()

def load_policy(base):
    base=Path(base)
    paths,_=load_reference(base)  # exact G69 Git-blob SHA256 and scope check
    extra=load_extra_refs(base)  # exact G72 SHA256, receipts and bts path checks
    configs=public_config_paths(extra)
    for path,rows in configs.items():
        # Add only paths derived by the existing reviewed public-reference rule.
        if path not in paths:paths[path]=[{'kind':'independent_public_configuration_path',
                                          'product':r['product']} for r in rows]
    routes=set()
    cat=json.loads((base/'public-download-reference.json').read_text())
    for r in cat['receipts']:
        url=r.get('url','');prefix='https://'+VERSION_HOST
        if url.startswith(prefix+'/v2/products/'):
            route=url[len(prefix):]
            if re.fullmatch(r'/v2/products/(agent|bna)/(versions|cdns)',route):routes.add(route)
    for r in extra:
        route=r.get('route','')
        if r.get('status')==200 and table(r.get('text','')) is not None and (
                route=='/v2/summary' or re.fullmatch(r'/v2/products/(agent_beta|agent_redist|bts)/(versions|cdns)',route)):
            routes.add(route)
    if len(routes)!=11:raise ValueError('metadata_route_reference_set')
    return Policy(paths,routes)
