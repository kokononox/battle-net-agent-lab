"""Bounded nonthrowing Agent-9824 sequence-control model and fragment comparison.
Pure memory + mocked helper return values; NOT Windows storage or activation.
"""
import json,struct,subprocess
from pathlib import Path
import patch_audit as a
import source_binding as b
FIELDS=('operation','mode','bucket','header','cached','next_sequence','temp_error','serialize_error','flush_error','bind_error','open_error','count')
DEFAULTS=dict(zip(FIELDS,(1,0,2,2,1,2,0,0,0,0,0,0)))
EVENTS={1:'temp_name_mock',2:'serialize_mock',3:'flush_rename_mock',4:'move_context_mock',5:'bind_mock',6:'destroy_context_mock',7:'filename_mock',8:'join_path_mock',9:'open_mock',10:'convert_open_error_mock',11:'logger_mock',12:'open_error_path_mock',13:'error_string_mock'}
U32=0xffffffff

def config(**kwargs):
    a.require(set(kwargs)<=set(FIELDS),'visibility_unknown_field');got={**DEFAULTS,**kwargs}
    a.require(all(type(v) is int and 0<=v<=U32 for v in got.values()),'visibility_u32_fields')
    a.require(got['operation'] in (0,1,2) and got['mode'] in range(6) and got['bucket'] in range(16) and got['count'] in (0,1),'visibility_bounded_inputs')
    return got

def predict(**kwargs):
    c=config(**kwargs);h=c['header'];cached=c['cached'];events=[]
    out={'return_code':0,'header_after':h,'cache_after':cached,'bind_calls':0,'open_calls':0,'flush_calls':0,'filename_sequence':U32,'filename_bucket':U32,'flush_old_sequence':U32,'cache_seen_at_bind':U32,'header_seen_at_bind':U32,'bind_bucket':U32,'memory_canaries_intact':True,'first_reader_return':U32,'open_flags':0}
    def emit(*e):events.extend(e)
    def bind():
        out['bind_calls']+=1;out.update(cache_seen_at_bind=cached,header_seen_at_bind=h,bind_bucket=c['bucket']);emit(5)
    def reader():
        nonlocal cached
        if c['mode'] in (2,4,5) or cached==h:return 0
        if cached>h:emit(11);return 1  # unsigned comparison, no wrap inference
        emit(7,8,9);out.update(filename_sequence=h,filename_bucket=c['bucket'],open_flags=6);out['open_calls']+=1
        if c['open_error']:
            emit(12,10,6);return c['open_error']  # error-conversion helper is mocked too
        cached=h;emit(4);bind()
        if c['bind_error']:emit(13,11)
        emit(6);return 0  # original function returns EBX, not the bind's ESI
    if c['operation']==0:
        emit(1);err=c['temp_error']
        if not err:emit(2);err=c['serialize_error']
        if not err:
            emit(3);out['flush_calls']=1;out['flush_old_sequence']=cached;err=c['flush_error']
        if not err:
            cached=c['next_sequence'];emit(4);bind();err=c['bind_error']
            if err:emit(13,11)
        emit(6)
        if err:emit(13,11)
        else:h=c['next_sequence']
        out['return_code']=err
    else:
        out['first_reader_return']=reader();out['return_code']=out['first_reader_return']
        if c['operation']==2:out['return_code']=reader()
    out.update(header_after=h,cache_after=cached,events=events,event_names=[EVENTS[x] for x in events]);return out

def native(binary,**kwargs):
    c=config(**kwargs);binary=b.safe(binary,True)
    run=subprocess.run([str(binary)],input=struct.pack('<12I',*(c[k] for k in FIELDS)),capture_output=True,timeout=5)
    a.require(run.returncode==0 and len(run.stdout)==256 and not run.stderr,'visibility_native_protocol')
    v=struct.unpack('<64I',run.stdout);a.require(v[12]<=32 and v[13]==1 and all(x==0 for x in v[16+v[12]:]),'visibility_native_guard_and_padding')
    keys=('return_code','header_after','cache_after','bind_calls','open_calls','flush_calls','filename_sequence','filename_bucket','flush_old_sequence','cache_seen_at_bind','header_seen_at_bind','bind_bucket')
    got=dict(zip(keys,v[:12]));got.update(memory_canaries_intact=True,first_reader_return=v[14],open_flags=v[15],events=list(v[16:16+v[12]]))
    a.require(all(x in EVENTS for x in got['events']),'visibility_native_event');got['event_names']=[EVENTS[x] for x in got['events']];return got

def compare(binary,**kwargs):
    c=config(**kwargs);model=predict(**c);observed=native(binary,**c);a.require(model==observed,'visibility_fragment_model_mismatch')
    return {'inputs':c,'matched':True,'observed':observed,'original_agent_function_fragments_executed':True,'external_helpers_mocked':True,'windows_agent_process_executed':False,'windows_apis_executed':False,'installation_ready':False}
