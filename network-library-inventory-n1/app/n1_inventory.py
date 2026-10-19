"""N1 module/import inventory. No injection, memory-buffer capture or process control."""
import ctypes
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys
import time
from core import signature,WOW
from hosts_guard import safe_path
from native_identity import identity
from native_tcp import snapshot
from monitor import integrity,single_instance
from n1_pe import MODULES,inspect

BASE=Path(__file__).resolve().parents[1]
MANIFEST='49404242dfc41d4d0734d4d42a2e395ed749b747393d49884a7769b13b5cd5cc'
SOURCE='7eacb50b04ffe4676ff85a8c37df9f5e03d1a97e'
NAMES={'battle.net.exe','agent.exe'}
MAX_PROCESSES=48;MAX_MODULE_FILES=96;MAX_FILE=1024**3;MAX_HASHED_BYTES=2*1024**3


def hash_file(path):
    h=hashlib.sha256();total=0
    with path.open('rb') as f:
        while True:
            b=f.read(1024**2)
            if not b:break
            total+=len(b)
            if total>MAX_FILE:raise ValueError('file_size_changed_or_limit')
            h.update(b)
    return h.hexdigest()

def same_process(a,b):return a['creation']==b['creation'] and a['path'].lower()==b['path'].lower()

def path_category(path,image):
    try:
        p=str(path.resolve()).lower();image=str(image.resolve().parent).lower();win=str(Path(os.environ.get('SystemRoot',r'C:\Windows')).resolve()).lower()
        if p.startswith(win+os.sep):return 'windows'
        if p.startswith(image+os.sep):return 'image_directory'
    except OSError:pass
    return 'other_path_omitted'

class Inventory:
    def __init__(self):
        self.rows={};self.private={};self.files={};self.file_rows=[];self.connections={}
        self.hashed_bytes=0;self.errors=0;self.limits=False;self.samples=0
    def image(self,p):
        pid=p['ProcessId'];name=p['Name'].lower();first=identity(pid);token=(pid,first['creation'])
        if token in self.private:return self.private[token],first
        if len(self.rows)>=MAX_PROCESSES:self.limits=True;raise ValueError('process_limit')
        key=len(self.rows)+1
        row={'index':key,'pid':pid,'parent_pid':p['ParentProcessId'],'process_name':name,'sha256':None,
            'authenticode_valid':False,'blizzard_publisher':False,'status':'checking','error_code':None,
            'module_statuses':[],'module_samples':0,'largest_module_count':0,'other_module_names_omitted':0,
            'module_file_indices':[]}
        self.rows[key]=row;self.private[token]=key
        try:
            path=safe_path(first['path'])
            if name not in NAMES or path.name.lower()!=name or not 0<path.stat().st_size<=128*1024**2:raise ValueError('image_refused')
            sig=signature(path);row['authenticode_valid']=sig['valid'];row['blizzard_publisher']=sig['blizzard']
            if not sig['valid'] or not sig['blizzard']:raise ValueError('signature_refused')
            row['sha256']=hash_file(path)
            if not same_process(first,identity(pid)):raise ValueError('pid_identity_changed')
            row['status']='verified'
        except Exception as exc:
            row['status']='unconfirmed';row['error_code']=str(exc) if isinstance(exc,ValueError) and str(exc) in {'image_refused','signature_refused','pid_identity_changed'} else 'identity_or_signature_failed'
        return key,first
    def module(self,path,image,is_image=False):
        path=safe_path(path);name=path.name.lower()
        if not is_image and name not in MODULES:return None
        stat=path.stat();token=(str(path).lower(),stat.st_size,stat.st_mtime_ns)
        if token in self.files:return self.files[token]
        if len(self.file_rows)>=MAX_MODULE_FILES or not 0<stat.st_size<=MAX_FILE or self.hashed_bytes+stat.st_size>MAX_HASHED_BYTES:
            self.limits=True;return None
        digest=hash_file(path);self.hashed_bytes+=stat.st_size
        info=inspect(path)
        again=path.stat()
        if (again.st_size,again.st_mtime_ns)!=(stat.st_size,stat.st_mtime_ns):raise ValueError('module_file_changed')
        index=len(self.file_rows)+1
        self.file_rows.append({'index':index,'category':name if name in MODULES or is_image else 'omitted',
            'is_process_image':is_image,'location_category':path_category(path,image),
            'sha256':digest,'file_bytes':stat.st_size,'pe':info})
        self.files[token]=index;return index
    def sample(self):
        snap=snapshot(NAMES|WOW);self.samples+=1
        if any(p['Name'].lower() in WOW for p in snap['processes']):raise ValueError('wow_running_stop_inventory')
        verified={}
        for p in snap['processes']:
            if p['Name'].lower() not in NAMES:continue
            try:
                key,first=self.image(p);row=self.rows[key]
                if row['status']!='verified':continue
                # Re-enumerate: module availability and PID identity can change.
                live=identity(p['ProcessId'])
                if not same_process(first,live):raise ValueError('pid_identity_changed')
                if live['module_status'] not in row['module_statuses']:row['module_statuses'].append(live['module_status'])
                row['module_samples']+=1;row['largest_module_count']=max(row['largest_module_count'],len(live['modules']))
                paths=[live['path']]+[s for s in live['modules'] if Path(s).name.lower() in MODULES and s.lower()!=live['path'].lower()]
                row['other_module_names_omitted']=max(row['other_module_names_omitted'],sum(Path(s).name.lower() not in MODULES and s.lower()!=live['path'].lower() for s in live['modules']))
                for path in paths:
                    try:
                        i=self.module(Path(path),Path(live['path']),str(path).lower()==live['path'].lower())
                        if i and i not in row['module_file_indices']:row['module_file_indices'].append(i)
                    except Exception:self.errors+=1
                if not same_process(live,identity(p['ProcessId'])):raise ValueError('pid_identity_changed')
                verified[p['ProcessId']]=(key,live)
            except Exception:self.errors+=1
        # Verified identities are established BEFORE this fresh TCP snapshot,
        # and rechecked afterwards; do not associate earlier PID-only rows.
        network=snapshot(NAMES|WOW)
        if any(p['Name'].lower() in WOW for p in network['processes']):raise ValueError('wow_running_stop_inventory')
        for c in network['connections']:
            pid=c['OwningProcess']
            if pid not in verified:continue
            key,prior=verified[pid]
            try:
                if not same_process(prior,identity(pid)):raise ValueError('pid_identity_changed')
                addr=ipaddress.ip_address(c['RemoteAddress'])
                if not addr.is_global:continue
                k=(key,str(addr),c['RemotePort'])
                if k not in self.connections:
                    if len(self.connections)>=256:self.limits=True;continue
                    self.connections[k]={'process_index':key,'remote_address':str(addr),'remote_port':c['RemotePort'],'sample_observations':0,'states':[]}
                row=self.connections[k];row['sample_observations']+=1
                if c['State'] not in row['states']:row['states'].append(c['State'])
            except Exception:self.errors+=1
    def report(self):
        return {'processes':list(self.rows.values()),'module_files':self.file_rows,'public_tcp_destinations':list(self.connections.values()),
            'sampling_errors':self.errors,'sample_count':self.samples,'limit_hit':self.limits,
            'limits':{'module_presence_proves_network_api_use':False,'export_or_import_presence_proves_api_called':False,
                'full_tls_library_identification_guaranteed':False,'statically_linked_or_dynamic_resolved_apis_excluded':False,
                'delay_imports_inspected':False,'udp_quic_connections_sampled':False,'full_module_paths_exported':False,'unknown_module_names_exported':False,
                'command_lines_memory_payloads_keys_or_account_values_read':False,'raw_requests_or_tls_keys_saved':False,
                'hooks_attached':False,'hosts_firewall_or_game_files_modified':False,'process_lifecycle_control':False,
                'automatic_report_upload':False,'certificate_validation_may_contact_network':True,
                'module_file_on_disk_proves_exact_loaded_memory_contents':False,'download_resume_requested':False}}

def main():
    if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:raise ValueError('windows_x64_required')
    if hashlib.sha256((BASE/'MANIFEST-SHA256.json').read_bytes()).hexdigest()!=MANIFEST:raise ValueError('requires_original_T11_package_manifest')
    integrity()
    if json.loads((BASE/'BUILD-INFO.json').read_text())['source_commit']!=SOURCE:raise ValueError('requires_T11_source_build')
    if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_inventory_as_administrator')
    mutex=single_instance()
    print('N1 Network Library Inventory - READ ONLY. No hooks, decryption or privacy verdict.')
    print('Keep WoW CLOSED, update PAUSED, automatic game updates OFF; remain signed out.')
    print('Close previous observer windows. This tool never changes hosts/firewall/game files or starts/stops Blizzard processes.')
    print('Battle.net may remain open PAUSED. If closed, open it YOURSELF only with auto-updates OFF; DO NOT Resume.')
    print('Image signature checks can contact certificate services. No payloads/keys/command lines are read.')
    if snapshot(WOW)['processes']:raise ValueError('close_wow_first')
    if input('Confirm these conditions and Battle.net open. Type PAUSED: ').strip()!='PAUSED':return
    start=datetime.datetime.now(datetime.timezone.utc);inventory=Inventory();status='collecting';error=None
    try:
        import msvcrt
        print('Collecting read-only process/module/TCP snapshots. Do NOT Resume. Press Q to end early.')
        began=time.monotonic();next_sample=0
        while time.monotonic()-began<60:
            if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':status='user_ended';break
            if time.monotonic()>=next_sample:
                inventory.sample();next_sample=time.monotonic()+5
            time.sleep(.2)
        else:status='window_ended'
    except KeyboardInterrupt:status='user_interrupted'
    except Exception as exc:
        status='stopped';error=str(exc) if isinstance(exc,ValueError) and str(exc)=='wow_running_stop_inventory' else 'inventory_failed'
    report={'schema':'n1-network-library-inventory-1','started_utc':start.isoformat(),'ended_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'status':status,'error_code':error,'preconditions_user_confirmed':True,'required_base_source':SOURCE,
        'base_manifest_sha256':MANIFEST,'inventory':inventory.report()}
    out=safe_path(BASE/'output');out.mkdir(exist_ok=True)
    target=safe_path(out/('n1-network-inventory-'+str(time.time_ns())+'.json'))
    raw=(json.dumps(report,indent=2)+'\n').encode()
    if len(raw)>2*1024**2:raise ValueError('report_size_limit')
    with target.open('xb') as f:f.write(raw)
    print('Saved output/'+target.name)
    print('Send that JSON only. Keep update PAUSED; no Resume permission is given by this tool.')

if __name__=='__main__':
    try:main()
    except Exception as exc:
        allowed={'windows_x64_required','requires_original_T11_package_manifest','requires_T11_source_build','run_inventory_as_administrator','close_wow_first','monitor_already_running_do_not_restore_hosts','single_instance_guard_failed','report_size_limit'}
        print('STOP:',str(exc) if isinstance(exc,ValueError) and str(exc) in allowed else 'inventory_initialization_failed');sys.exit(1)
