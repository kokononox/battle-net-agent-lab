"""Local Procmon XML metadata analysis; never exports raw details, paths or stack addresses."""
import collections, ipaddress, ntpath, re
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_XML=768*1024*1024
MAX_EVENTS=750000
MAX_PROCESSES=20000
MAX_GROUPS=1500

def name(path):
    s=ntpath.basename(str(path or '').strip())
    return s if re.fullmatch(r'[A-Za-z0-9_. -]{1,100}',s) else 'other_module'

def norm(path):return ntpath.normcase(ntpath.normpath(str(path or '')))
def under(path,folder):
    try:return ntpath.commonpath([norm(path),norm(folder)])==norm(folder)
    except ValueError:return False

def integer(text,default=None):
    try:return int(text)
    except (TypeError,ValueError):return default

def text(el,key):return (el.findtext(key) or '').strip()

def elements(path,tag):
    # Only completed process/event records are retained; clear the parent list too.
    stack=[]
    for kind,el in ET.iterparse(path,events=('start','end')):
        if kind=='start':stack.append(el);continue
        if el.tag==tag:
            yield el
            if len(stack)>1:stack[-2].remove(el)
            el.clear()
        elif el.tag in ('process','event'):
            if len(stack)>1:stack[-2].remove(el)
            el.clear()
        stack.pop()

def endpoint(raw):
    raw=raw.strip(); host=None;port=None
    if raw.startswith('['):
        m=re.fullmatch(r'\[([^\]]+)\]:(\d+|[A-Za-z][A-Za-z0-9_-]{0,20})',raw)
        if m:host,port=m.groups()
    else:
        host,sep,port=raw.rpartition(':')
        if not sep:return None
    try:ip=ipaddress.ip_address(host)
    except ValueError:return None
    services={'http':80,'https':443,'domain':53}
    p=integer(port,services.get(str(port).lower()))
    if p is None or not 0<=p<=65535:return None
    return {'ip':str(ip),'port':p,'ip_is_global':ip.is_global}

def destination(path):
    parts=path.split(' -> ')
    return endpoint(parts[1]) if len(parts)==2 else None

def analyze(path,selected_exe):
    if Path(path).stat().st_size>MAX_XML:raise ValueError('xml_size_limit')
    with open(path,'rb') as f:
        prefix=f.read(65536)
    decoded=prefix.decode('utf-16' if prefix[:2] in (b'\xff\xfe',b'\xfe\xff') else 'utf-8-sig',errors='replace')
    if '<!DOCTYPE' in decoded or '<!ENTITY' in decoded:raise ValueError('xml_entities_not_allowed')
    processes={};capped=False
    for el in elements(path,'process'):
        if len(processes)>=MAX_PROCESSES:capped=True;break
        idx=integer(text(el,'ProcessIndex'));pid=integer(text(el,'ProcessId'))
        if idx is None or pid is None:continue
        processes[idx]={'index':idx,'pid':pid,'parent_index':integer(text(el,'ParentProcessIndex')),
                        'name':name(text(el,'ProcessName') or text(el,'ImagePath')),
                        'root_path_match':norm(text(el,'ImagePath'))==norm(selected_exe),
                        'game_folder':under(text(el,'ImagePath'),ntpath.dirname(selected_exe))}
    roots={i for i,p in processes.items() if p['root_path_match']}
    targets=set(roots)
    same_folder={i for i,p in processes.items() if p['game_folder'] and p['name'].lower().endswith('.exe')}
    while True:
        added={i for i,p in processes.items() if p['parent_index'] in targets}-targets
        if not added:break
        targets.update(added)
    proven_targets=set(targets)
    targets.update(same_folder)
    # Same-folder candidates are separately labelled, not declared game descendants.
    # No PID/name guessing: events must reference a process-table index.
    stats={i:collections.Counter() for i in targets}; modules={i:{} for i in targets}
    groups={};unknown_endpoints=collections.Counter();seen_ops=collections.Counter();events=0;network_events=0
    for el in elements(path,'event'):
        events+=1
        if events>MAX_EVENTS:capped=True;break
        op=text(el,'Operation');seen_ops[op]+=1
        i=integer(text(el,'ProcessIndex'))
        if i not in targets:continue
        # Refuse contradictory process metadata instead of conflating reused PIDs.
        if integer(text(el,'PID'))!=processes[i]['pid']:
            stats[i]['pid_mismatch_events']+=1;continue
        if op=='Load Image':
            p=text(el,'Path');m=name(p)
            if len(modules[i])<2048:modules[i][m]={'name':m,'in_game_folder':under(p,ntpath.dirname(selected_exe))}
            else:capped=True
            stats[i]['load_image_events']+=1
        if op not in ('TCP Connect','TCP Send','UDP Send','TCP Receive','UDP Receive'):continue
        stats[i][op]+=1;network_events+=1
        if op in ('TCP Receive','UDP Receive'):continue
        # For Send/Connect only, right endpoint is the destination. Receive paths are not reused.
        ep=destination(text(el,'Path'))
        if ep is None:unknown_endpoints[i]+=1;continue
        key=(i,op,ep['ip'],ep['port'])
        if key not in groups:
            if len(groups)>=MAX_GROUPS:capped=True;continue
            groups[key]={'process_index':i,'operation':op,'destination':ep,'events':0,'success_events':0,
                         'reported_successful_send_length_sum':0,'events_with_stack_modules':0,'events_with_stack_frames':0,'frames_without_module_path':0,
                         'stack_modules':set(),'game_folder_modules_in_stack':set()}
        g=groups[key];g['events']+=1;success=text(el,'Result')=='SUCCESS';g['success_events']+=int(success)
        if success and op in ('TCP Send','UDP Send'):
            m=re.search(r'(?:^|,\s*)Length:\s*([\d,]+)(?:\s|,|$)',text(el,'Detail'))
            if m:
                n=integer(m.group(1).replace(',',''),0)
                if 0<=n<=2**32:g['reported_successful_send_length_sum']+=n
        frames=el.findall('./stack/frame');observed=False
        g['events_with_stack_frames']+=int(bool(frames))
        for frame in frames[:64]:
            p=text(frame,'path')
            if not p:g['frames_without_module_path']+=1;continue
            observed=True;module=name(p)
            if len(g['stack_modules'])<64:g['stack_modules'].add(module)
            elif module not in g['stack_modules']:capped=True
            if under(p,ntpath.dirname(selected_exe)) and len(g['game_folder_modules_in_stack'])<64:g['game_folder_modules_in_stack'].add(module)
        if len(frames)>64:capped=True
        g['events_with_stack_modules']+=int(observed)
    out=[]
    for key in sorted(groups):
        g=groups[key];g['stack_modules']=sorted(g['stack_modules']);g['game_folder_modules_in_stack']=sorted(g['game_folder_modules_in_stack']);out.append(g)
    relevant=[]
    for i in sorted(targets):
        p=processes[i].copy();p['relation']='selected_executable' if i in roots else 'descendant_by_process_index' if i in proven_targets else 'same_game_folder_candidate_not_proven_related'
        p['observed_events']=dict(stats[i]);p['unparsed_send_or_connect_destinations']=unknown_endpoints[i]
        p['loaded_images_observed']=sorted(modules[i].values(),key=lambda m:m['name']);relevant.append(p)
    schema_ok=bool(processes)
    return {'xml_process_table_recognized':schema_ok,'selected_process_found':bool(roots),
            'status':'metadata_observed' if roots and network_events else 'selected_process_without_observed_network' if roots else 'selected_process_not_found',
            'processes':relevant,'send_and_connect_groups':out,'analysis_limit_hit':capped,
            'all_system_events_inspected':min(events,MAX_EVENTS),
            'capture_contains_network_events':any(k.startswith(('TCP ','UDP ')) for k in seen_ops),
            'capture_contains_load_image_events':seen_ops['Load Image']>0,
            'capture_contains_process_events':any(k in seen_ops for k in ('Process Create','Process Start','Process Exit')),
            'module_causality_proven':False,'tls_or_upload_contents_decoded':False,
            'notes':['Connections are attributed using Procmon process-table indexes, not PID alone.',
                     'Stack membership is an observed execution-path clue, not proof a DLL authored the request or its content.',
                     'Only literal IP + numeric/known-service-port endpoints are exported; unresolved names are counted, never guessed.',
                     'Send lengths are sums of reported successful operation lengths, not unique wire bytes or decoded payload.',
                     'Missing descendants, events, frames or modules do not prove absence; system export/capture settings may limit coverage.',
                     'Requests delegated by IPC to an already-running service outside this process tree/game folder may be missed.',
                     'No DLL is classified as telemetry solely because it is loaded. No zero-result proves no collection or queued upload.']}
