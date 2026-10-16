"""Read-only finite log/UI signals from fresh-runner bootstrap; never raw text.
Log mentions and UI markers are signals, NOT proof of an operation or its cause.
"""
import collections
import os
from pathlib import Path
import re
import stat
import time

MAX_FILES=24
MAX_FILE_BYTES=2*1024**2
MAX_TOTAL_BYTES=16*1024**2
MAX_EVENTS=96
MAX_LINE=2048
KINDS={
    'lifecycle':r'\b(?:agentmain|agentasserver|agent starting|starting agent|agent started|agent shutting down|agent shutdown)\b',
    'agent_update':r'\b(?:agentupdate|agent update|update agent|self[-_ ]update|agentupdater)\b',
    'configuration':r'\b(?:configuration|config|manifest|buildconfig|cdnconfig|versions)\b',
    'content_storage':r'\b(?:casc|blte|encoding|ngdp|bpsv)\b',
    'download':r'\b(?:download|downloading|downloaded|downloader)\b',
    'patch':r'\b(?:patch|patching|patched|patcher)\b',
    'ipc':r'\b(?:ipc|rpc|named pipe|listen|listening)\b',
    'network':r'\b(?:http|https|connection|connect|connected|connecting|resolve|resolver|dns)\b',
    'timeout':r'\b(?:timeout|timed out)\b',
    'failure':r'\b(?:error|failed|failure|fatal)\b',
    'completion':r'\b(?:success|successful|succeeded|completed|finished)\b',
    'product':r'\b(?:product|products|wow|wow_beta|wowt)\b'
}
PATTERNS={k:re.compile(v,re.I) for k,v in KINDS.items()}
UI_KEYS=('language','legal','account','installation_options','progress','error')
ROOTS={'agent','app','local_app','temporary_install'}

def blank():
    return dict(status='not_collected',files_read=0,files_skipped=0,bytes_read=0,lines_scanned=0,
                oversized_lines_skipped=0,partial_lines_skipped=0,truncated=False,
                event_counts=dict.fromkeys(KINDS,0),events=[],gui_signals=dict.fromkeys(UI_KEYS,False),
                log_mentions_are_not_operation_proof=True,gui_markers_are_not_page_proof=True,
                raw_text_exported=False)

def ui_signals(gui):
    found=set();labels=set()
    a=gui.get('accessibility',{})
    for e in a.get('elements',[]):
        if e.get('offscreen') or e.get('password'):continue
        found.update(e.get('markers',[]));labels.add(e.get('label'))
    for w in gui.get('windows',[]):
        for e in [w,*w.get('controls',[])]:
            if e.get('visible'):
                found.update(e.get('markers',[]));labels.add(e.get('label'))
    return dict(language='select_language' in labels,
                legal=bool(found&{'license','agreement','terms','privacy'}),
                account=bool(found&{'login','sign_in'}),
                installation_options=bool(found&{'install','installation'}) and bool(found&{'location','folder','shortcut'}),
                progress=bool(found&{'installing','updating','initializing','connecting','download'}),
                error=bool(found&{'error','failed'}))

def parse_lines(text,file_index,category,start_line=1,deadline=None):
    """No caller-provided string is copied into returned records."""
    if type(file_index) is not int or not 0<=file_index<MAX_FILES or category not in ROOTS:raise ValueError('log_scope')
    counts=dict.fromkeys(KINDS,0);events=collections.deque(maxlen=MAX_EVENTS);lines=over=hits=0
    cut=False;deadline=time.monotonic()+2 if deadline is None else deadline
    for number,line in enumerate(text.splitlines(),start_line):
        if lines>=10000 or (lines%256==0 and time.monotonic()>deadline):cut=True;break
        lines+=1
        if len(line)>MAX_LINE:over+=1;continue
        matched=[k for k,p in PATTERNS.items() if p.search(line)]
        http=re.search(r'\bHTTP/[12](?:\.[01])?\s+([1-5][0-9]{2})\b',line,re.I)
        status=int(http.group(1)) if http else None
        severity='error' if re.search(r'\b(?:error|fatal|failed|failure)\b',line,re.I) else 'warning' if re.search(r'\b(?:warn|warning)\b',line,re.I) else 'unspecified'
        for kind in matched:
            counts[kind]+=1;hits+=1
            events.append(dict(file_index=file_index,category=category,line_number=number,kind=kind,severity=severity,http_status=status))
    return counts,list(events),lines,over,cut or hits>MAX_EVENTS

def safe_category(path,roots):
    # Only paths discovered under known bootstrap roots. Every ancestor must be ordinary.
    from observe_agent import is_reparse
    path=Path(path).absolute()
    for category,root in roots.items():
        if category not in ROOTS:continue
        root=Path(root).absolute()
        try:path.relative_to(root)
        except ValueError:continue
        parent=path
        while True:
            if is_reparse(parent):return None
            if parent==root:break
            parent=parent.parent
        if path.suffix.lower() not in {'.log','.txt'}:return None
        try:
            if not stat.S_ISREG(path.lstat().st_mode):return None
        except OSError:return None
        return category
    return None

def collect(paths,roots,final_gui):
    result=blank();result['status']='collected';result['gui_signals']=ui_signals(final_gui)
    events=collections.deque(maxlen=MAX_EVENTS);deadline=time.monotonic()+6
    unique=list(dict.fromkeys(Path(p).absolute() for p in paths))
    if len(unique)>MAX_FILES:result['truncated']=True
    for index,path in enumerate(unique[:MAX_FILES]):
        if time.monotonic()>deadline or result['bytes_read']>=MAX_TOTAL_BYTES:result['truncated']=True;break
        category=safe_category(path,roots)
        if category is None:result['files_skipped']+=1;continue
        fd=None
        try:
            fd=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):result['files_skipped']+=1;continue
            cap=min(MAX_FILE_BYTES,MAX_TOTAL_BYTES-result['bytes_read'])
            with os.fdopen(fd,'rb') as source:
                fd=None;raw=source.read(cap)
            result['files_read']+=1;result['bytes_read']+=len(raw)
            clipped=info.st_size>len(raw);result['truncated']|=clipped
            if raw.startswith((b'\xff\xfe',b'\xfe\xff')):text=raw.decode('utf-16',errors='replace')
            else:text=raw.decode('utf-8-sig',errors='replace')
            if text and not text.endswith(('\n','\r')):
                # Concurrent writers may leave partial lines; do not interpret them.
                result['partial_lines_skipped']+=1;text=text.rsplit('\n',1)[0] if '\n' in text else ''
            counts,found,lines,oversized,truncated=parse_lines(text,index,category,deadline=deadline)
            result['lines_scanned']+=lines;result['oversized_lines_skipped']+=oversized
            result['truncated']|=truncated or len(events)+len(found)>MAX_EVENTS
            for k,n in counts.items():result['event_counts'][k]+=n
            events.extend(found)
        except OSError:result['files_skipped']+=1
        finally:
            if fd is not None:os.close(fd)
    result['events']=list(events)
    return validate(result)

def validate(r):
    if type(r) is not dict or set(r)!=set(blank()):raise ValueError('agent_state_schema')
    if r['status'] not in {'not_collected','collected'}:raise ValueError('agent_state_status')
    caps={'files_read':MAX_FILES,'files_skipped':MAX_FILES,'bytes_read':MAX_TOTAL_BYTES,'lines_scanned':MAX_TOTAL_BYTES,
          'oversized_lines_skipped':MAX_TOTAL_BYTES,'partial_lines_skipped':MAX_FILES}
    for k,cap in caps.items():
        if type(r[k]) is not int or not 0<=r[k]<=cap:raise ValueError('agent_state_count')
    if type(r['truncated']) is not bool:raise ValueError('agent_state_flag')
    for k,expected in [('log_mentions_are_not_operation_proof',True),('gui_markers_are_not_page_proof',True),('raw_text_exported',False)]:
        if r[k] is not expected:raise ValueError('agent_state_interpretation')
    if type(r['event_counts']) is not dict or set(r['event_counts'])!=set(KINDS):raise ValueError('agent_state_counts')
    if any(type(n) is not int or not 0<=n<=MAX_TOTAL_BYTES for n in r['event_counts'].values()):raise ValueError('agent_state_counts')
    if type(r['gui_signals']) is not dict or set(r['gui_signals'])!=set(UI_KEYS) or any(type(n) is not bool for n in r['gui_signals'].values()):raise ValueError('agent_state_gui')
    if type(r['events']) is not list or len(r['events'])>MAX_EVENTS:raise ValueError('agent_state_events')
    retained=dict.fromkeys(KINDS,0)
    for e in r['events']:
        if type(e) is not dict or set(e)!={'file_index','category','line_number','kind','severity','http_status'}:raise ValueError('agent_state_event')
        if type(e['file_index']) is not int or not 0<=e['file_index']<MAX_FILES or e['category'] not in ROOTS:raise ValueError('agent_state_file')
        if type(e['line_number']) is not int or not 1<=e['line_number']<=MAX_TOTAL_BYTES:raise ValueError('agent_state_line')
        if e['kind'] not in KINDS or e['severity'] not in {'error','warning','unspecified'}:raise ValueError('agent_state_kind')
        if e['http_status'] is not None and (type(e['http_status']) is not int or not 100<=e['http_status']<=599):raise ValueError('agent_state_http')
        retained[e['kind']]+=1
    if any(retained[k]>r['event_counts'][k] for k in KINDS):raise ValueError('agent_state_counts')
    if r['files_read']==0 and (r['bytes_read'] or r['events'] or r['lines_scanned'] or any(r['event_counts'].values())):raise ValueError('agent_state_empty')
    if r['status']=='not_collected' and r!=blank():raise ValueError('agent_state_not_collected')
    return r
