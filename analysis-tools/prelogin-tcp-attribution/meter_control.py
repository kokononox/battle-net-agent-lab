"""Launch only the precompiled meter as a child of the existing native Job."""
import os,subprocess,time
from pathlib import Path
import meter_receipt

def start(pid,port):
 if os.environ.get('RETAIL_SUPERVISED')!='job-c10'or os.environ.get('RETAIL_TCP_METER')!='owned-baseline-t2':raise ValueError('meter_scope')
 if type(pid)is not int or not 0<pid<2**32 or type(port)is not int or not 0<port<65536:raise ValueError('meter_owner')
 out=Path('output').resolve();exe=out/'tcp_meter.exe'
 if not exe.is_file()or any((out/n).exists()for n in ('tcp-meter-ready.signal','tcp-meter-stop.signal','tcp-meter.json')):raise ValueError('meter_fresh')
 env=dict(os.environ,TCP_METER_PID=str(pid),TCP_METER_PORT=str(port))
 p=subprocess.Popen([str(exe),env['GITHUB_SHA'],env['GITHUB_RUN_ID']],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  deadline=time.monotonic()+3
  while time.monotonic()<deadline:
   if p.poll()is not None:raise ValueError('meter_exited')
   ready=out/'tcp-meter-ready.signal'
   if ready.exists():
    if ready.is_symlink()or ready.read_bytes()!=b'ready\n':raise ValueError('meter_ready')
    r=meter_receipt.read(out/'tcp-meter.json')
    if r['source_commit']!=env['GITHUB_SHA']or r['run_id']!=env['GITHUB_RUN_ID']or not r['baseline_ready']or r['status']!='observing':raise ValueError('meter_receipt')
    return p
   time.sleep(.025)
  raise ValueError('meter_timeout')
 except BaseException:
  if p.poll()is None:p.terminate();p.wait(timeout=2)
  raise

def stop(p):
 if p is None:return
 Path('output/tcp-meter-stop.signal').write_bytes(b'stop\n')
 try:p.wait(timeout=2)
 except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=2)
