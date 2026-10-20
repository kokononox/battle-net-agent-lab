"""Finite, passive network capture. Never attaches/injects into the selected application."""
import ctypes,datetime,json,os,subprocess,sys,threading,time
from pathlib import Path
from collections import defaultdict
from launcher_destinations import choose_exe,file_hash,Tracker,process_rows,process_identity
from native_tcp import tcp_connections
from safepaths import safe_path
from capture_platform import Capture
BASE=Path(__file__).resolve().parents[1]

class OwnershipSampler:
 def __init__(self,path,sha):
  self.tracker=Tracker(path,sha);self.ownership={};self.stop=threading.Event();self.thread=None
  self.errors=0;self.limited=False;self.failure=None
 def run(self):
  while not self.stop.is_set():
   try:
    processes=process_rows();live=self.tracker.discover(processes)
    connections=tcp_connections({p['pid'] for p in processes});now=time.time();verified={}
    for pid,(token,d) in live.items():
     try:
      i=process_identity(pid)
      if (pid,i['creation'])==token:verified[pid]=d
     except OSError:self.errors+=1
    for c in connections:
     key=(c['LocalAddress'],c['LocalPort'],c['RemoteAddress'],c['RemotePort'])
     if not c['RemotePort']:continue
     d=verified.get(c['OwningProcess'])
     if d is None:
      if key in self.ownership and not any(o['process_index'] is None for o in self.ownership[key]):
       self.ownership[key].append({'process_index':None,'first_seen_epoch':now,'last_seen_epoch':now})
      continue
     if key not in self.ownership:
      if len(self.ownership)>=8192:self.limited=True;continue
      self.ownership[key]=[]
     existing=next((o for o in self.ownership[key] if o['process_index']==d['index']),None)
     if existing:existing['last_seen_epoch']=now
     else:self.ownership[key].append({'process_index':d['index'],'first_seen_epoch':now,'last_seen_epoch':now})
   except ValueError as e:self.failure=str(e);self.stop.set()
   except Exception:self.errors+=1
   self.stop.wait(.2)
 def start(self):self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
 def close(self):
  self.stop.set()
  if self.thread:self.thread.join(10)
 def report(self):
  r=self.tracker.report()
  return {'processes':r['processes'],'sampler_errors':self.errors,'identity_read_errors':r['identity_read_errors'],
   'limits_hit':self.limited or r['limits_hit'],'sampled_tcp_tuple_count':len(self.ownership),
   'sampling_thread_stopped':not self.thread or not self.thread.is_alive(),'failure':self.failure,
   'udp_process_attribution_available':False}


def save(report):
 out=safe_path(BASE/'output');out.mkdir(exist_ok=True)
 raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode()
 if len(raw)>8*1024**2:raise ValueError('metadata_report_size_limit')
 p=safe_path(out/('passive-network-'+str(time.time_ns())+'.json'))
 with p.open('xb') as f:f.write(raw)
 print('\nSEND ONLY THIS JSON:',str(p))
 print('DO NOT upload ETL/PCAPNG files. They may contain other apps and sensitive traffic.')


def main():
 report={'schema':'passive-game-network-1','version':'0.2.1','status':'preflight','error_code':None,
 'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'selected_exe_name':None,'selected_exe_sha256':None,
 'capture':None,'process_sampling':None,'analysis':None,
 'limits':{'no_process_attach_or_injection':True,'no_game_memory_reading':True,
 'no_firewall_vpn_dns_tls_or_capture_filter_changes':True,'pktmon_capture_session_started_and_stopped':True,
 'raw_recording_machine_wide_on_nics_and_stays_local':True,'packet_prefix_snaplen':4096,
 'maximum_intended_capture_seconds':60,'independent_owned_capture_watchdog_seconds':90,
 'disk_budget_soft_limit_bytes':96*1024**2,'raw_file_budget_may_overshoot_between_polls':True,
 'tcp_process_attribution_sampled_not_continuous':True,'udp_not_process_attributed':True,
 'dns_process_attribution_not_proven':True,'dns_cache_not_flushed':True,'cross_file_tls_streams_not_reassembled':True,'doh_dot_ech_quic_or_vpn_can_hide_domains':True,
 'payload_tls_game_protocol_decrypted':False,'hardware_marker_checks_only_for_reconstructed_plaintext_http':True,'pcapng_enhanced_packet_blocks_only':True,'captured_bytes_not_unique_application_bytes':True,
 'zero_hardware_upload_or_only_download_proven':False,'native_windows_qualification_completed_by_builder':False}}
 cap=None;sampler=None;folder=None;lock=None;watchdog=None
 try:
  if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:raise ValueError('windows_x64_required')
  if not ctypes.windll.shell32.IsUserAnAdmin():raise ValueError('run_as_administrator')
  from passive_boot import integrity,mutex
  integrity();lock=mutex()
  print('Passive Game Network 0.2.1 - NO INJECTION. Raw capture is local and machine-wide.')
  print('Close unrelated apps; do NOT enter passwords or log in during this diagnostic.')
  print('Prefer the selected game CLOSED so its first connections can be observed.')
  path=choose_exe()
  if path is None:report['status']='cancelled';return
  sha=file_hash(path);report['selected_exe_name']=path.name;report['selected_exe_sha256']=sha
  check=Tracker(path,sha);report['selected_already_running_before_capture']=bool(check.discover(process_rows()))
  parent=safe_path(BASE/'private-captures');parent.mkdir(exist_ok=True)
  folder=safe_path(parent/('run-'+str(time.time_ns())));folder.mkdir(exist_ok=False)
  cap=Capture(folder);cap.start()
  # Independent finite worker only; it stops only the still-verified owned session if this window closes.
  watchdog=subprocess.Popen([sys.executable,'-I',str(Path(__file__).with_name('passive_watchdog.py')),
   str(folder),cap.owner['name'],str(cap.owner['handle'])],stdin=subprocess.DEVNULL,
   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000)
  sampler=OwnershipSampler(path,sha);sampler.start();report['status']='capturing'
  print('\nCAPTURE READY. Open the selected game yourself NOW and reach the login screen.')
  print('Do not enter account credentials. Q ends early. Capture ends after 60 seconds.')
  print('Do not close this window with X. An independent 90-second safety stop is armed.')
  import msvcrt
  started=time.monotonic();reason='time_limit'
  while time.monotonic()-started<60:
   if msvcrt.kbhit() and msvcrt.getwch().lower()=='q':reason='user_q';break
   if sampler.failure:reason='sampler_failure';break
   if (folder/'watchdog-stopped.flag').exists():reason='watchdog_stop';cap.started=False;cap.stop_verified=True;break
   if sum(p.stat().st_size for p in folder.glob('pktmon-owned*.etl'))>=96*1024**2:reason='soft_disk_budget';break
   time.sleep(.2)
  sampler.close();cap.stop()
  if sampler.thread and sampler.thread.is_alive():raise ValueError('sampling_thread_did_not_stop_no_analysis')
  (folder/'stop.flag').write_text('normal_stop\n')
  report['capture']={'end_reason':reason,'duration_seconds':round(time.monotonic()-started,2),
   'owned_capture_stop_verified':cap.stop_verified,'raw_file_count':len(list(folder.glob('pktmon-owned*.etl'))),
   'packet_logging_loss_counters':cap.diagnostics,'existing_filters_not_modified_or_certified':True,
   'nic_capture_vpn_inner_visibility_not_certified':True,'raw_files_kept_local':True}
  print('Capture stopped. Converting owned trace locally; do not close the window yet...')
  paths=cap.convert()
  from passive_packets import Analyzer,packets
  from hardware import references
  refs=references()
  a=Analyzer(sampler.ownership,refs);refs.clear();parse_files=[]
  for path in paths:
   try:
    for packet in packets(path):
     packet['interface']=(len(parse_files),*packet['interface'])
     a.add(packet)
    parse_files.append({'file_index':len(parse_files)+1,'status':'parsed'})
   except (ValueError,OSError) as e:
    parse_files.append({'file_index':len(parse_files)+1,'status':'partial','error_code':str(e) if isinstance(e,ValueError) else 'file_read_failed'})
  report['analysis']=a.finish();report['capture']['parse_files']=parse_files
  report['status']='observation_ended' if all(r['status']=='parsed' for r in parse_files) else 'partial_parse'
  print('Sample-attributed game TCP flows:',len(report['analysis']['selected_process_tcp_flows']))
 except KeyboardInterrupt:report['status']='interrupted'
 except Exception as e:
  import re
  report['status']='stopped';report['error_code']=str(e) if isinstance(e,ValueError) and re.fullmatch('[a-z0-9_]{1,110}',str(e)) else 'local_capture_or_conversion_failed'
  report['exception_type']=type(e).__name__;print('STOP:',report['error_code'])
 finally:
  if sampler:
   sampler.close();report['process_sampling']=sampler.report()
  if cap and cap.started:
   try:cap.stop()
   except Exception:
    report['manual_pktmon_attention_required']=True
    print('ATTENTION: capture stop not verified. The safety worker may stop the owned trace within 90 seconds.')
    print('Run pktmon status locally to review. No unknown capture was stopped automatically.')
  if cap and cap.stop_verified and folder:(folder/'stop.flag').write_text('verified_stop\n')
  print('Game and downloads were NOT closed or paused. Raw captures stay in private-captures locally.')
  save(report)

if __name__=='__main__':main()
