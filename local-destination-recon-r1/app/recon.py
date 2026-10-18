"""Windows TCP/process-only recon. No injection, decryption or process control."""
import argparse
import ctypes
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
from core import NAMES,WOW,signature,versions
from hosts_guard import HostsGuard,safe_path
from native_identity import identity
from native_tcp import snapshot,tcp_connections
from monitor import integrity,single_instance
from recon_profiles import PROFILES,ALL_TARGETS,domains_for,ProfileGuard

BASE=Path(__file__).resolve().parents[1]
LIMITS={
    'injection_used':False,'tls_decryption_used':False,'packet_payload_captured':False,
    'automatic_report_upload':False,'game_files_changed_by_tool':False,
    'update_or_process_control_used':False,'denylist_not_allowlist':True,
    'hosts_is_system_wide':True,'short_lived_tcp_can_be_missed':True,
    'udp_quic_doh_and_direct_ip_not_blocked_by_hosts_guaranteed':True,
    'tcp_samples_not_bytes_or_request_counts':True,
    'ip_not_proof_of_hostname_or_payload':True,
    'progress_response_is_user_report':True,'zero_telemetry_proven':False,
    'whole_update_completion_proven':False,
}

def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()

class Scanner:
    def __init__(self):
        self.private={};self.processes=[];self.flows={};self.errors=0
        self.process_limit=False;self.flow_limit=False
    def poll(self,phase):
        try:snap=snapshot(NAMES)
        except Exception:self.errors+=1;return
        for p in snap['processes']:
            try:
                info=identity(p['ProcessId']);key=(p['ProcessId'],info['creation'])
                if key in self.private:continue
                if len(self.processes)>=64:self.process_limit=True;continue
                path=safe_path(info['path']);name=p['Name'].lower()
                if path.name.lower()!=name:raise ValueError('image_basename_mismatch')
                trust=signature(path)
                # Keep paths/modules/raw exception strings private.
                row={'index':len(self.processes)+1,'pid':p['ProcessId'],
                     'process_name':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                     'signature_valid':trust['valid'],'blizzard_publisher':trust['blizzard']}
                self.private[key]=row['index'];self.processes.append(row)
            except Exception:self.errors+=1
        for c in snap['connections']:
            try:
                pid=c['OwningProcess'];key=(pid,identity(pid)['creation'])
                index=self.private.get(key)
                if not index:continue
                row=self.processes[index-1]
                if not row['signature_valid'] or not row['blizzard_publisher']:continue
                addr=ipaddress.ip_address(c['RemoteAddress'])
                if not addr.is_global:continue
                token=(index,str(addr),c['RemotePort'],phase)
                if token not in self.flows:
                    if len(self.flows)>=1024:self.flow_limit=True;continue
                    self.flows[token]={'process_index':index,'remote_address':str(addr),
                        'remote_port':c['RemotePort'],'phase':phase,'sample_observations':0}
                self.flows[token]['sample_observations']+=1
            except Exception:self.errors+=1
    def agent_seen(self):
        return any(p['process_name']=='agent.exe' and p['signature_valid'] and p['blizzard_publisher']
                   for p in self.processes)
    def live_agent_seen(self):
        for (pid,creation),index in self.private.items():
            row=self.processes[index-1]
            if row['process_name']!='agent.exe' or not row['signature_valid'] or not row['blizzard_publisher']:continue
            try:
                if identity(pid)['creation']==creation:return True
            except Exception:continue
        return False
    def report(self):
        return {'processes':self.processes,'public_tcp_samples':list(self.flows.values()),
                'sampler_errors':self.errors,'process_limit_hit':self.process_limit,
                'flow_limit_hit':self.flow_limit}

def validate_report(r):
    if set(r)!=set('schema profile_id profile_label blocked_domains started_utc ready_utc observation_ended_utc ended_utc window_seconds end_reason ready user_preconditions_confirmed status error_code initial_versions final_versions hosts user_final_state user_download_behavior observation limits'.split()):raise ValueError('recon_schema')
    if r['schema']!='retail-destination-recon-1' or r['profile_id'] not in PROFILES:raise ValueError('recon_identity')
    if r['profile_label']!=PROFILES[r['profile_id']]['label'] or r['blocked_domains']!=list(domains_for(r['profile_id'])):raise ValueError('recon_profile')
    if r['limits']!=LIMITS or type(r['ready']) is not bool or r['window_seconds']!=120 or r['user_preconditions_confirmed'] is not True:raise ValueError('recon_limits')
    for k in ('started_utc','ready_utc','observation_ended_utc','ended_utc'):
        if r[k] is not None and not re.fullmatch(r'\d{4}-\d{2}-\d{2}T[0-9:.]+\+00:00',r[k]):raise ValueError('recon_time')
    if r['end_reason'] not in ('not_started','time_limit','user_q','stopped'):raise ValueError('recon_end_reason')
    if r['status'] not in ('started','observation_ended','stopped'):raise ValueError('recon_status')
    if r['error_code'] is not None and not re.fullmatch('[a-z0-9_]{1,100}',r['error_code']):raise ValueError('recon_error')
    from validate import version
    version(r['initial_versions'])
    if r['final_versions'] is not None:version(r['final_versions'])
    h=r['hosts']
    if set(h)!=set('changed restored restore_status resolution_after_apply resolution_before_restore'.split()):raise ValueError('recon_hosts')
    if type(h['changed']) is not bool or type(h['restored']) is not bool:raise ValueError('recon_hosts_bool')
    if h['restore_status'] not in ('not_needed','already_original','restored_exactly','needs_manual_attention_journal_kept'):raise ValueError('recon_restore')
    for key in ('resolution_after_apply','resolution_before_restore'):
        states=h[key]
        if type(states) is not dict or (states and set(states)!=set(r['blocked_domains'])):raise ValueError('recon_resolution')
        if any(s not in ('loopback_only','public_only','other_or_failed','timeout') for s in states.values()):raise ValueError('recon_resolution_value')
    if r['ready'] and (not h['changed'] or set(h['resolution_after_apply'])!=set(r['blocked_domains']) or any(s!='loopback_only' for s in h['resolution_after_apply'].values())):raise ValueError('recon_unblocked_ready')
    if r['user_final_state'] not in ('not_recorded','reported_finished','reported_paused','reported_error','unknown'):raise ValueError('recon_state')
    if r['user_download_behavior'] not in ('not_recorded','reported_progress','reported_stall','reported_error','unknown'):raise ValueError('recon_behavior')
    o=r['observation']
    if set(o)!=set('processes public_tcp_samples sampler_errors process_limit_hit flow_limit_hit'.split()):raise ValueError('recon_observation')
    if type(o['sampler_errors']) is not int or o['sampler_errors']<0:raise ValueError('recon_errors')
    for k in ('process_limit_hit','flow_limit_hit'):
        if type(o[k]) is not bool:raise ValueError('recon_cap')
    if type(o['processes']) is not list or len(o['processes'])>64 or type(o['public_tcp_samples']) is not list or len(o['public_tcp_samples'])>1024:raise ValueError('recon_caps')
    indices=set()
    for p in o['processes']:
        if set(p)!=set('index pid process_name sha256 signature_valid blizzard_publisher'.split()):raise ValueError('recon_process')
        if type(p['index']) is not int or p['index']<1 or p['index'] in indices or type(p['pid']) is not int or not 0<p['pid']<2**32:raise ValueError('recon_pid')
        if p['process_name'] not in NAMES or not re.fullmatch('[a-f0-9]{64}',p['sha256']):raise ValueError('recon_image')
        if type(p['signature_valid']) is not bool or type(p['blizzard_publisher']) is not bool or (p['blizzard_publisher'] and not p['signature_valid']):raise ValueError('recon_trust')
        indices.add(p['index'])
    for f in o['public_tcp_samples']:
        if set(f)!=set('process_index remote_address remote_port phase sample_observations'.split()):raise ValueError('recon_flow')
        if f['process_index'] not in indices or not ipaddress.ip_address(f['remote_address']).is_global:raise ValueError('recon_flow_source')
        if type(f['remote_port']) is not int or not 0<f['remote_port']<65536 or f['phase'] not in ('before_ready','observation_window'):raise ValueError('recon_flow_value')
        if type(f['sample_observations']) is not int or f['sample_observations']<1:raise ValueError('recon_samples')
    return r

def write_report(path,r):
    data=(json.dumps(validate_report(r),indent=2)+'\n').encode()
    if len(data)>2*1024**2:raise ValueError('recon_report_size')
    safe_path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(data)

def network_selftest():
    result={'schema':'r1-network-selftest-1','passed':False,'owned_loopback_only':True,
            'pid_identity_matches':False,'owned_tcp_connection_seen':False,
            'no_injection':True,'no_hosts_changed':True}
    with socket.socket() as server:
        server.bind(('127.0.0.1',0));server.listen(1)
        with socket.socket() as client:
            client.connect(server.getsockname())
            peer,_=server.accept()
            with peer:
                me=identity(os.getpid())
                result['pid_identity_matches']=Path(me['path']).resolve()==Path(sys.executable).resolve()
                rows=tcp_connections({os.getpid()})
                result['owned_tcp_connection_seen']=any(
                    row['OwningProcess']==os.getpid() and row['RemoteAddress']=='127.0.0.1'
                    and row['RemotePort']==server.getsockname()[1] for row in rows)
    result['passed']=result['pid_identity_matches'] and result['owned_tcp_connection_seen']
    target=BASE/'network-selftest-to-share.json'
    with target.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2)
    print(json.dumps(result))
    if not result['passed']:raise ValueError('network_selftest_failed')

def main(args):
    if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:raise ValueError('windows_x64_required')
    integrity()
    if args.selftest_network:network_selftest();return
    if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_as_administrator')
    state=safe_path(BASE/'PRIVATE-RECOVERY');state.mkdir(exist_ok=True)
    hostpath=Path(os.environ['SystemRoot'])/'System32'/'drivers'/'etc'/'hosts'
    journal=state/'hosts-recovery.json'
    recovery=HostsGuard(hostpath,journal)
    if journal.exists():
        print('Previous recovery pending. No trial starts. Result:',recovery.restore());return
    if snapshot(NAMES|WOW)['processes']:raise ValueError('close_battlenet_agent_and_wow_first')
    print('Destination Recon R1: NO injection or TLS decryption. NOT a privacy firewall.')
    print('Fixed profile:',args.profile,PROFILES[args.profile]['label'])
    print('Temporary SYSTEM-WIDE hosts block:',', '.join(domains_for(args.profile)))
    print('Unknown other destinations remain allowed. DNS checks/certificate services can use network.')
    print('WoW CLOSED; auto game updates OFF; signed out; backup exists; Update PAUSED.')
    root=Path(input('WoW folder [G:\\World of Warcraft]: ').strip().strip('\"') or r'G:\World of Warcraft')
    before=versions(root)
    if not before['retail_versions']:raise ValueError('retail_build_info_not_confirmed')
    if input('Type CONFIRM only if all conditions above are true: ').strip()!='CONFIRM':return
    if input('Type BLOCK to allow exactly this profile, anything else exits: ').strip()!='BLOCK':return
    guard=ProfileGuard(hostpath,journal,args.profile);scanner=Scanner()
    r={'schema':'retail-destination-recon-1','profile_id':args.profile,'profile_label':PROFILES[args.profile]['label'],
       'blocked_domains':list(domains_for(args.profile)),'started_utc':utc(),'ready_utc':None,
       'observation_ended_utc':None,'ended_utc':None,'window_seconds':120,'end_reason':'not_started',
       'ready':False,'user_preconditions_confirmed':True,'status':'started','error_code':None,
       'initial_versions':before,'final_versions':None,
       'hosts':{'changed':False,'restored':False,'restore_status':'not_needed','resolution_after_apply':{},'resolution_before_restore':{}},
       'user_final_state':'not_recorded','user_download_behavior':'not_recorded','observation':scanner.report(),'limits':LIMITS}
    try:
        if snapshot(NAMES|WOW)['processes']:raise ValueError('process_started_before_block')
        guard.apply();r['hosts']['resolution_after_apply']=dict(guard.resolutions)
        print('Now open Battle.net manually; stay signed out and KEEP Update PAUSED.')
        print('Waiting up to 180 seconds for a currently live verified Blizzard Agent. No hook will be attached.')
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            scanner.poll('before_ready')
            if scanner.live_agent_seen():break
            time.sleep(.5)
        if not scanner.live_agent_seen():raise ValueError('no_live_verified_agent_do_not_resume')
        if snapshot(WOW)['processes']:raise ValueError('wow_running_do_not_resume')
        if guard.check_resolution()!='loopback_only':raise ValueError('profile_no_longer_loopback_do_not_resume')
        r['ready']=True;r['ready_utc']=utc()
        print('READY FOR NETWORK OBSERVATION ONLY - not proof of zero telemetry or updater readiness.')
        print('You may manually Resume if desired. 120 seconds FROM NOW, not from the Resume click.')
        print('Timer/Q only ends observation; it NEVER pauses or cancels Update. Keep WoW closed.')
        import msvcrt
        start=time.monotonic();r['end_reason']='time_limit'
        while time.monotonic()-start<120:
            scanner.poll('observation_window')
            if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':r['end_reason']='user_q';break
            time.sleep(.5)
        r['status']='observation_ended'
    except KeyboardInterrupt:r['status']='stopped';r['end_reason']='stopped';r['error_code']='user_interrupted'
    except Exception as e:
        r['status']='stopped';r['end_reason']='stopped'
        r['error_code']=str(e) if isinstance(e,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(e)) else 'local_recon_failed'
        print('STOP:',r['error_code'],'Do not Resume for this trial.')
    finally:
        r['observation_ended_utc']=utc()
        try:
            print('Observation ended. Manually PAUSE/finish Update, then EXIT Battle.net from tray.')
            print('1 Finished / 2 Paused / 3 Error / 4 Unknown')
            r['user_final_state']={'1':'reported_finished','2':'reported_paused','3':'reported_error'}.get(input('Final state: ').strip(),'unknown')
            print('1 Download progressed / 2 Stalled / 3 Error / 4 Unknown or not resumed')
            r['user_download_behavior']={'1':'reported_progress','2':'reported_stall','3':'reported_error'}.get(input('Observed download behavior: ').strip(),'unknown')
            while snapshot(NAMES|WOW)['processes']:
                if input('Processes still open. Exit manually and Enter to recheck; STOP restores and ends: ').strip().upper()=='STOP':break
        finally:
            # Recovery executes even if prompts, snapshot or final version read fail.
            try:
                guard.check_resolution()
                r['hosts']['resolution_before_restore']=dict(guard.resolutions)
            except Exception:pass
            restore=guard.restore()
            r['hosts'].update(changed=guard.changed,restored=guard.restored,restore_status=restore)
            r['observation']=scanner.report()
            try:r['final_versions']=versions(root)
            except Exception:r['final_versions']={'status':'unreadable_or_unrecognized','retail_versions':[]}
            r['ended_utc']=utc()
            path=BASE/'output'/('recon-'+args.profile+'-'+str(time.time_ns())+'.json')
            write_report(path,r)
            print('Report:',str(Path('output')/path.name))
            print('Hosts restoration:',restore)
            print('No blocks remain after successful restore. Close Battle.net if not testing.')
            print('Send ONLY output/recon-*.json. NEVER share PRIVATE-RECOVERY.')
    return r

if __name__=='__main__':
    try:
        parser=argparse.ArgumentParser()
        parser.add_argument('--profile',choices=tuple(PROFILES),default='02')
        parser.add_argument('--selftest-network',action='store_true')
        args=parser.parse_args()
        mutex=single_instance() if sys.platform=='win32' else None
        main(args)
    except Exception as e:
        print('STOP:',str(e) if isinstance(e,ValueError) and re.fullmatch('[a-z0-9_]{1,100}',str(e)) else 'recon_preflight_failed')
        print('No permission to Resume Update has been given.');sys.exit(1)