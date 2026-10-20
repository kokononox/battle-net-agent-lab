"""Native read-only ETW session inventory plus owned Pktmon CLI lifecycle.
No injection, capture-filter mutation, DNS lookup, or firewall/TLS modification.
"""
import ctypes as c
from pathlib import Path
import os,subprocess
from launcher_destinations import path_key

class WNODE(c.Structure):
 _fields_=[('BufferSize',c.c_uint32),('ProviderId',c.c_uint32),('HistoricalContext',c.c_uint64),
 ('TimeStamp',c.c_int64),('Guid',c.c_ubyte*16),('ClientContext',c.c_uint32),('Flags',c.c_uint32)]
class PROPERTIES(c.Structure):
 _fields_=[('Wnode',WNODE)]+[(x,c.c_uint32) for x in ('BufferSize','MinimumBuffers','MaximumBuffers','MaximumFileSize','LogFileMode','FlushTimer','EnableFlags')]+[('AgeLimit',c.c_int32)]+[(x,c.c_uint32) for x in ('NumberOfBuffers','FreeBuffers','EventsLost','BuffersWritten','LogBuffersLost','RealTimeBuffersLost')]+[('LoggerThreadId',c.c_void_p),('LogFileNameOffset',c.c_uint32),('LoggerNameOffset',c.c_uint32)]

def sessions():
 if c.sizeof(PROPERTIES)!=120:raise ValueError('unexpected_etw_properties_layout')
 api=c.WinDLL('advapi32',use_last_error=True).QueryAllTracesW
 api.argtypes=[c.POINTER(c.POINTER(PROPERTIES)),c.c_uint32,c.POINTER(c.c_uint32)];api.restype=c.c_uint32
 count=32;size=120+8192
 for _ in range(4):
  buffers=[c.create_string_buffer(size) for _ in range(count)]
  pointers=(c.POINTER(PROPERTIES)*count)()
  for i,b in enumerate(buffers):
   p=c.cast(b,c.POINTER(PROPERTIES));p.contents.Wnode.BufferSize=size
   p.contents.LoggerNameOffset=120;p.contents.LogFileNameOffset=4216;pointers[i]=p
  n=c.c_uint32();code=api(pointers,count,c.byref(n))
  if code==234 and count<n.value<=1024:
   count=n.value;continue
  if code or n.value>count:raise ValueError('etw_session_inventory_unavailable')
  break
 else:raise ValueError('etw_session_inventory_kept_growing')
 result=[]
 for i in range(n.value):
  p=pointers[i].contents;raw=buffers[i].raw
  def text(offset):
   if not 120<=offset<size or offset%2:return ''
   b=raw[offset:];end=next((j for j in range(0,len(b)-1,2) if b[j:j+2]==b'\x00\x00'),len(b)//2*2)
   return b[:end].decode('utf-16-le',errors='replace')
  result.append({'name':text(p.LoggerNameOffset),'file':text(p.LogFileNameOffset),
   'handle':int(p.Wnode.HistoricalContext),'events_lost':int(p.EventsLost),'log_buffers_lost':int(p.LogBuffersLost)})
 return result


def pktmon_sessions(rows):
 return [r for r in rows if 'pktmon' in r['name'].lower() or 'pktmon' in Path(r['file']).name.lower()]


class Capture:
 def __init__(self,folder):
  self.folder=Path(folder);self.exe=Path(os.environ['SystemRoot'])/'System32/pktmon.exe'
  self.started=False;self.owner=None;self.stop_verified=False;self.diagnostics=[]
  self.prefix=self.folder/'pktmon-owned.etl'
 def command(self,args,timeout=30):
  r=subprocess.run([str(self.exe),*map(str,args)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
   stderr=subprocess.STDOUT,timeout=timeout,creationflags=0x08000000)
  text=r.stdout.decode('utf-8',errors='replace')
  # Local CLI output may contain paths; show locally, never serialize it into shared JSON.
  print(text[:4000])
  return r.returncode,text
 def start(self):
  if not self.exe.is_file():raise ValueError('pktmon_not_available')
  if pktmon_sessions(sessions()):raise ValueError('existing_pktmon_session_do_not_interrupt')
  self.command(['status'])
  self.command(['filter','list'])
  print('If another Pktmon capture is active, CANCEL. Existing filters are NOT changed.')
  print('Packet recording is machine-wide on NICs. Raw files may include other apps and stay LOCAL.')
  print('Close unrelated apps; do not enter passwords. Do not run other Pktmon tools during this test.')
  if input('Confirm no existing Pktmon capture and consent to local recording: type CAPTURE: ').strip()!='CAPTURE':
   raise ValueError('capture_not_confirmed')
  # Recheck immediately after consent, before starting any trace.
  if pktmon_sessions(sessions()):raise ValueError('pktmon_started_elsewhere_do_not_interrupt')
  self.started=True
  code,_=self.command(['start','--capture','--comp','nics','--pkt-size','4096',
   '--file-name',self.prefix,'--file-size','16','--log-mode','multi-file'])
  if code:raise ValueError('pktmon_start_failed_verify_owned_cleanup')
  self.started=True
  rows=pktmon_sessions(sessions())
  owned=[r for r in rows if self.owned_path(r['file'])]
  if len(rows)!=1 or len(owned)!=1:
   raise ValueError('pktmon_ownership_not_confirmed_manual_status_required')
  self.owner=owned[0]
 def owned_path(self,path):
  # Pktmon may number the first file immediately in multi-file mode.
  import ntpath,re
  return path_key(ntpath.dirname(path))==path_key(self.folder) and bool(re.fullmatch(r'pktmon-owned\d*\.etl',ntpath.basename(path),re.I))
 def stop(self):
  if not self.started:return
  current=pktmon_sessions(sessions())
  if not self.owner:
   recovered=[r for r in current if self.owned_path(r['file'])]
   if len(current)==1 and len(recovered)==1:self.owner=recovered[0]
   else:raise ValueError('capture_stop_not_owned_check_pktmon_status_manually')
  match=[r for r in current if r['name']==self.owner['name'] and r['handle']==self.owner['handle'] and self.owned_path(r['file'])]
  if len(current)!=1 or len(match)!=1:raise ValueError('capture_ownership_changed_no_global_stop')
  code,_=self.command(['stop'])
  if code:raise ValueError('pktmon_stop_failed_check_status_manually')
  self.started=False;self.stop_verified=True
  self.diagnostics.append({'events_lost_before_stop':match[0]['events_lost'],'log_buffers_lost_before_stop':match[0]['log_buffers_lost']})
 def convert(self):
  if not self.stop_verified:raise ValueError('capture_stop_required_before_conversion')
  import re
  paths=sorted(self.folder.glob('pktmon-owned*.etl'),key=lambda p:int(re.search(r'(\d*)\.etl$',p.name).group(1) or 0))
  if not paths:raise ValueError('no_owned_etl_files_found')
  if len(paths)>32 or sum(p.stat().st_size for p in paths)>256*1024**2:raise ValueError('raw_capture_processing_size_limit')
  out=[]
  for path in paths:
   dest=path.with_suffix('.pcapng')
   code,_=self.command(['etl2pcap',path,'--out',dest],timeout=60)
   if code or not dest.exists():raise ValueError('pktmon_conversion_failed_raw_files_kept_local')
   out.append(dest)
  return out
