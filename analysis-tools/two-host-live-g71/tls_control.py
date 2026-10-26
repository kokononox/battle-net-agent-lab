"""Real TLS1.2 loopback control; fixture trust removed before any installer launch."""
import os,json,subprocess,threading
from pathlib import Path
from collections import Counter
import frida
from Job import Job
from response_origin import ResponseOrigin
BASE=Path(__file__).resolve().parent
REQUEST=b'GET /v2/products/agent/versions HTTP/1.1\r\nHost: us.version.battle.net\r\n\r\n';RESPONSE=b'HTTP/1.1 200 OK\r\nContent-Length: 71\r\nETag: "0123456789abcdef0123456789abcdef"\r\n\r\nRegion!STRING:0|BuildConfig!HEX:16\nus|0123456789abcdef0123456789abcdef\n'
SYNTHETIC_BODY='Region!STRING:0|BuildConfig!HEX:16\nus|0123456789abcdef0123456789abcdef\n'
def cert(action):
 output=Path(os.environ['RUNNER_TEMP'])/('g71-cert-'+action+'.PRIVATE.txt')
 with output.open('wb') as stream:
  r=subprocess.run(['powershell.exe','-NoProfile','-File',str(BASE/'TlsCert.ps1'),'-Action',action],stdout=stream,stderr=subprocess.DEVNULL,timeout=40)
 if r.returncode:raise RuntimeError('tls_fixture_certificate_'+action.lower()+'_failed')
 return output.read_text(encoding='utf-8-sig').strip()

def run_tls(arch,thumb):
 exe=Path(os.environ['RUNNER_TEMP'])/('g71-tls-'+arch+'.exe');marker=Path(os.environ['RUNNER_TEMP'])/('g71-tls-'+arch+'.exact')
 if exe.exists() or marker.exists():raise RuntimeError('fixture_path_exists')
 csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 built=subprocess.run([str(csc),'/nologo','/platform:'+arch,'/out:'+str(exe),str(BASE/'TlsFixture.cs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if built.returncode:raise RuntimeError('tls_fixture_compile_failed')
 job=Job();device=frida.get_local_device();session=None;ready=threading.Event();done=threading.Event();parts=[];statuses=[];counts=Counter();errors=0;pairer=ResponseOrigin([{'route':'/v2/products/agent/versions','status':200,'text':SYNTHETIC_BODY,'headers':{'etag':['"0123456789abcdef0123456789abcdef"']}}])
 try:
  pid=device.spawn([str(exe),thumb,str(marker)]);job.assign(pid);session=device.attach(pid);session.on('detached',lambda *a:done.set())
  script=session.create_script('globalThis.SSPI_FIXTURE=true;\n'+(BASE/'hook.js').read_text())
  def message(m,data):
   nonlocal errors
   if m.get('type')!='send':errors+=1;return
   p=m['payload'];counts[p.get('kind')]+=1
   if p.get('kind')=='ready':ready.set()
   if p.get('kind')=='sspi_plaintext':
    parts.append((p,bytes(data or b'')))
    if p.get('status')=='0x00000000':pairer.feed(p['context_index'],'out' if p['direction']=='outgoing_pre_encrypt' else 'in',bytes(data or b''))
   if p.get('kind')=='sspi_handshake_status':statuses.append(p)
  script.on('message',message);script.load()
  if not ready.wait(5):raise RuntimeError('tls_observer_not_ready')
  device.resume(pid)
  if not done.wait(40):raise RuntimeError('tls_fixture_timeout')
  native_exact=marker.is_file() and marker.read_text()=='G71_TLS_BOTH_ENDPOINTS_EXACT'
  outgoing=any(p['server']=='localhost' and p['direction']=='outgoing_pre_encrypt' and p['status']=='0x00000000' and b==REQUEST for p,b in parts)
  incoming=any(p['server']=='localhost' and p['direction']=='incoming_post_decrypt' and p['status']=='0x00000000' and b==RESPONSE for p,b in parts)
  handshake=any(p['server']=='localhost' and p['succeeded'] for p in statuses)
  pairer.target('0123456789abcdef0123456789abcdef','/tpr/fixture/config/01/23/0123456789abcdef0123456789abcdef')
  attr=pairer.report();ar=attr['targets'][0];occ=ar['paired_response_occurrences'];public=ar['independent_reference_occurrences']
  attribution=bool(occ and occ[0]['route']=='/v2/products/agent/versions' and occ[0]['preceded_target_observation'] and any(v['area']=='typed_table_cell' and v['field']=='BuildConfig' and v['match']=='exact_value' for v in occ[0]['locations']) and any(v['area']=='HTTP_header' and v['field']=='etag' for v in occ[0]['locations']) and public and not attr['blocked_contexts'])
  passed=attribution and native_exact and outgoing and incoming and handshake and errors==0 and counts['sspi_observation_error']==0
  return {'architecture':arch,'control':'Schannel_TLS12_loopback','passed':bool(passed),'response_field_attribution_passed':attribution,'synthetic_response_attribution':attr,'native_both_endpoints_exact':native_exact,'pre_encrypt_plaintext_exact':outgoing,'post_decrypt_plaintext_exact':incoming,'scoped_handshake_success_observed':handshake,'script_errors':errors,'observation_errors':counts['sspi_observation_error'],'plaintext_API_events':len(parts),'handshake_status_codes':sorted(set(p['status_hex'] for p in statuses)),'TLS_fixture_executed':True,'fixture_exact_certificate_pin_required':True,'fixture_standard_chain_trust_used':False,'fixture_root_trust_installed':False,'production_certificate_validation_changed':False,'synthetic_only':True,'included_in_real_report':False}
 finally:
  job.close()
  if session:
   try:session.detach()
   except Exception:pass
  for p in (exe,marker):
   try:p.unlink()
   except OSError:pass
