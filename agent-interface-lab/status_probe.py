"""Two exact local GETs on a fresh VM: /agent then /game. No product mutations."""
import http.client
import json
import os
from pathlib import Path
import re
import sys
import probe

APPROVAL='lab: approved logged-out Agent status probe 2026-10-18 274ba6c1'
SCHEMA='logged-out-agent-status-1'
STATUSES={'not_started','handshake_not_ready','token_not_header_safe','identity_changed',
 'game_http_rejected','game_response_rejected','game_schema_unrecognized',
 'agent_error_reported','game_summary_observed','stopped_safely'}

def blank():
    return dict(schema=SCHEMA,source_commit=os.environ.get('GITHUB_SHA',''),
      run_id=os.environ.get('GITHUB_RUN_ID',''),run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT',''),
      status='not_started',handshake=probe.blank(),total_http_requests_attempted=0,
      game_http_requests_attempted=0,game_http_status=None,game_response_bytes=0,
      game_response_schema=None,product_entry_count=None,
      game_before_owner_verified=False,game_after_owner_verified=False,
      local_authorization_sent=False,agent_error_reported=False,
      account_login_attempted=False,game_download_requested=False,
      game_update_requested=False,repair_requested=False,product_initialized=False,
      game_files_opened=0,raw_response_exported=False,token_exported=False,
      product_names_or_links_exported=False,game_update_without_login_proven=False,
      retail_policy_proven=False,classic_download_authorized=False,
      child_network_hard_byte_cap=False)

OBSERVED={'game_before_owner_verified','game_after_owner_verified','local_authorization_sent','agent_error_reported'}

def fresh_environment(env,platform):
    return probe.fresh_environment(env,platform) and env.get('AGENT_STATUS_ONCE')==APPROVAL

def validate(r):
    template=blank()
    if type(r) is not dict or set(r)!=set(template):raise ValueError('status_schema')
    for k,v in template.items():
        if type(v) is bool:
            if type(r[k]) is not bool or (k not in OBSERVED and r[k] is not v):raise ValueError('status_safety_flag')
    if r['schema']!=SCHEMA or r['status'] not in STATUSES:raise ValueError('status_enum')
    probe.validate(r['handshake'])
    for k in ('source_commit','run_id','run_attempt'):
        if type(r[k]) is not str or r[k]!=r['handshake'][k]:raise ValueError('status_identity')
    for k,cap in (('total_http_requests_attempted',2),('game_http_requests_attempted',1),('game_response_bytes',probe.MAX_BODY),('game_files_opened',0)):
        if type(r[k]) is not int or not 0<=r[k]<=cap:raise ValueError('status_count')
    if r['total_http_requests_attempted'] != r['handshake']['http_requests_attempted']+r['game_http_requests_attempted']:raise ValueError('status_request_sum')
    if r['game_http_status'] is not None and (type(r['game_http_status']) is not int or not 100<=r['game_http_status']<=599):raise ValueError('status_http')
    if r['game_response_schema'] not in (None,'empty_object','error_zero_empty','product_link_mapping'):raise ValueError('status_response_schema')
    if r['product_entry_count'] is not None and (type(r['product_entry_count']) is not int or not 0<=r['product_entry_count']<=256):raise ValueError('status_product_count')
    if r['game_http_requests_attempted']:
        if not (r['handshake']['authorization_token_present'] and r['game_before_owner_verified'] and r['local_authorization_sent']):raise ValueError('status_request_without_token_identity')
    elif any((r['game_http_status'] is not None,r['game_response_bytes']!=0,r['local_authorization_sent'],r['game_after_owner_verified'],r['game_response_schema'] is not None,r['product_entry_count'] is not None,r['agent_error_reported'])):raise ValueError('status_response_without_request')
    if r['game_response_schema'] is not None:
        if r['game_http_status']!=200 or r['product_entry_count'] is None:raise ValueError('status_shape_evidence')
        if (r['game_response_schema']=='product_link_mapping') != (r['product_entry_count']>0):raise ValueError('status_shape_count')
    if r['status']=='game_summary_observed':
        if not (r['handshake']['status']=='handshake_token_observed' and r['handshake']['cleanup_attempted'] and r['game_response_schema'] is not None and r['game_after_owner_verified'] and r['total_http_requests_attempted']==2 and not r['agent_error_reported']):raise ValueError('status_success_evidence')
    return r

def summarize(raw):
    try:data=probe.unique_json(raw)
    except (ValueError,UnicodeError,RecursionError):raise probe.Stop('game_response_rejected') from None
    if 'error' in data:
        code=data.pop('error')
        if type(code) not in (int,float) or code<0:raise probe.Stop('game_schema_unrecognized')
        if code>0:raise probe.Stop('agent_error_reported')
        if not data:return 'error_zero_empty',0
    if not data:return 'empty_object',0
    if len(data)>256:raise probe.Stop('game_schema_unrecognized')
    for key,value in data.items():
        if type(key) is not str or not 1<=len(key)<=128 or type(value) is not dict:raise probe.Stop('game_schema_unrecognized')
        if type(value.get('link')) is not str or not 1<=len(value['link'])<=2048:raise probe.Stop('game_schema_unrecognized')
    return 'product_link_mapping',len(data)

def request_game(port,token,r,verify_live,connection_factory=http.client.HTTPConnection):
    if r['game_http_requests_attempted']!=0:raise probe.Stop('game_http_rejected')
    if type(port) is not int or not 1<=port<=65535:raise probe.Stop('identity_changed')
    if not r['handshake']['authorization_token_present']:raise probe.Stop('handshake_not_ready')
    if type(token) is not str or re.fullmatch(r'[!-~]{1,8192}',token) is None:raise probe.Stop('token_not_header_safe')
    if verify_live() is not True:raise probe.Stop('identity_changed')
    r['game_before_owner_verified']=True
    r['game_http_requests_attempted']=1;r['local_authorization_sent']=True
    # 'sent' means an attempt with the header; not proof of server authentication.
    conn=connection_factory('127.0.0.1',port,timeout=3)
    try:
        conn.request('GET','/game',headers={'Authorization':token,'User-Agent':'phoenix-agent/1.0',
          'Accept':'application/json','Accept-Encoding':'identity','Connection':'close'})
        response=conn.getresponse();r['game_http_status']=response.status
        if response.status!=200:raise probe.Stop('game_http_rejected')
        if response.getheader('Content-Encoding','identity').lower() not in ('','identity'):raise probe.Stop('game_response_rejected')
        length=response.getheader('Content-Length')
        if length is not None and (not re.fullmatch('[0-9]{1,10}',length) or int(length)>probe.MAX_BODY):raise probe.Stop('game_response_rejected')
        raw=response.read(probe.MAX_BODY+1)
        if len(raw)>probe.MAX_BODY:raise probe.Stop('game_response_rejected')
        r['game_response_bytes']=len(raw)
        if length is not None and len(raw)!=int(length):raise probe.Stop('game_response_rejected')
        schema,count=summarize(raw)
        if verify_live() is not True:raise probe.Stop('identity_changed')
        r['game_after_owner_verified']=True;r['game_response_schema']=schema;r['product_entry_count']=count
        r['status']='game_summary_observed'
    finally:conn.close()

def run(out):
    r=blank()
    try:
        if not fresh_environment(os.environ,sys.platform):raise probe.Stop('stopped_safely')
        def observer(token,port,verify_live):
            # probe.run keeps this exact handshake dict live until its cleanup/final validation.
            try:request_game(port,token,r,verify_live)
            except probe.Stop as exc:
                r['status']=str(exc) if str(exc) in STATUSES else 'identity_changed'
                if r['status']=='agent_error_reported':r['agent_error_reported']=True
            except Exception:r['status']='stopped_safely'
        # Observe handshake state during the callback without publishing token-bearing data.
        # The additional sink is an in-memory dict, not a disk/protocol plugin.
        handshake_sink=r['handshake']
        r['handshake']=probe.run(out,after_handshake=observer,report_sink=handshake_sink)
        if r['status']=='not_started':r['status']='handshake_not_ready'
        if r['handshake']['status']!='handshake_token_observed' and r['status']=='game_summary_observed':r['status']='identity_changed'
    except probe.Stop as exc:r['status']=str(exc) if str(exc) in STATUSES else 'stopped_safely'
    except Exception:r['status']='stopped_safely'
    finally:
        r['total_http_requests_attempted']=r['handshake']['http_requests_attempted']+r['game_http_requests_attempted']
        validate(r)
        out.mkdir(parents=True,exist_ok=True)
        payload=json.dumps(r,indent=2)
        if len(payload.encode())>16384:raise ValueError('status_report_size')
        (out/'agent-status-to-share.json').write_text(payload,encoding='utf-8')
        print(json.dumps({'status':r['status'],'total_http_requests_attempted':r['total_http_requests_attempted'],'report_written':True}))
    return r

if __name__=='__main__':
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
    run(Path('output'))
