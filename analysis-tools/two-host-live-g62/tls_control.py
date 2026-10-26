"""Real TLS1.2 loopback control; fixture trust removed before any installer launch."""
import os,json,subprocess,threading
from pathlib import Path
from collections import Counter
import frida
from Job import Job
BASE=Path(__file__).resolve().parent
REQUEST=b'G62-REQUEST-PLAINTEXT';RESPONSE=b'G62-RESPONSE-PLAINTEXT'
def cert(action):
 r=subprocess.run(['powershell.exe','-NoProfile','-File',str(BASE/'TlsCert.ps1'),'-Action',action],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=90)
 if r.returncode:raise RuntimeError('tls_fixture_certificate_'+action.lower()+'_failed')
 return r.stdout.decode('utf-8-sig').strip()
def run_tls(arch,thumb):
 exe=Path(os.environ['RUNNER_TEMP'])/('g62-tls-'+arch+'.exe');marker=Path(os.environ['RUNNER_TEMP'])/('g62-tls-'+arch+'.exact')
 if exe.exists() or marker.exists():raise RuntimeError('fixture_path_exists')
 csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 built=subprocess.run([str(csc),'/nologo','/platform:'+arch,'/out:'+str(exe),str(BASE/'TlsFixture.cs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if built.returncode:raise RuntimeError('tls_fixture_compile_failed')
 job=Job();device=frida.get_local_device();session=None;ready=threading.Event();done=threading.Event();parts=[];statuses=[];counts=Counter();errors=0
 try:
  pid=device.spawn([str(exe),thumb,str(marker)]);job.assign(pid);session=device.attach(pid);session.on('detached',lambda *a:done.set())
  script=session.create_script('globalThis.SSPI_FIXTURE=true;\n'+(BASE/'hook.js').read_text())
  def message(m,data):
   nonlocal errors
   if m.get('type')!='send':errors+=1;return
   p=m['payload'];counts[p.get('kind')]+=1
   if p.get('kind')=='ready':ready.set()
   if p.get('kind')=='sspi_plaintext':parts.append((p,bytes(data or b'')))
   if p.get('kind')=='sspi_handshake_status':statuses.append(p)
  script.on('message',message);script.load()
  if not ready.wait(5):raise RuntimeError('tls_observer_not_ready')
  device.resume(pid)
  if not done.wait(40):raise RuntimeError('tls_fixture_timeout')
  native_exact=marker.is_file() and marker.read_text()=='G62_TLS_BOTH_ENDPOINTS_EXACT'
  outgoing=any(p['server']=='localhost' and p['direction']=='outgoing_pre_encrypt' and p['status']=='0x00000000' and b==REQUEST for p,b in parts)
  incoming=any(p['server']=='localhost' and p['direction']=='incoming_post_decrypt' and p['status']=='0x00000000' and b==RESPONSE for p,b in parts)
  handshake=any(p['server']=='localhost' and p['succeeded'] for p in statuses)
  passed=native_exact and outgoing and incoming and handshake and errors==0 and counts['sspi_observation_error']==0
  return {'architecture':arch,'control':'Schannel_TLS12_loopback','passed':bool(passed),'native_both_endpoints_exact':native_exact,'pre_encrypt_plaintext_exact':outgoing,'post_decrypt_plaintext_exact':incoming,'scoped_handshake_success_observed':handshake,'script_errors':errors,'observation_errors':counts['sspi_observation_error'],'plaintext_API_events':len(parts),'handshake_status_codes':sorted(set(p['status_hex'] for p in statuses)),'TLS_fixture_executed':True,'certificate_validation_callback_used':False,'certificate_error_bypass_used':False,'synthetic_only':True,'included_in_real_report':False}
 finally:
  job.close()
  if session:
   try:session.detach()
   except Exception:pass
  for p in (exe,marker):
   try:p.unlink()
   except OSError:pass
