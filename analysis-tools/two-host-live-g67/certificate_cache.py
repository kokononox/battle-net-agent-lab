"""Bounded strict online warmup and blocked offline verification; no raw certificate output."""
import os,json,subprocess,ipaddress
from pathlib import Path
BASE=Path(__file__).resolve().parent

def run(root,mode):
 if os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('BNET_G67')!='approved-live-startup-two-hosts-g67':raise RuntimeError('fresh_hosted_required')
 if root.resolve()!=(Path(os.environ['RUNNER_TEMP'])/'g67-private').resolve():raise RuntimeError('root_rejected')
 exe=Path(os.environ['RUNNER_TEMP'])/'g67-certificate-cache.exe'
 if mode=='Online':
  csc=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
  built=subprocess.run([str(csc),'/nologo','/out:'+str(exe),'/reference:'+str(csc.parent/'System.Web.Extensions.dll'),str(BASE/'CertificateCache.cs')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  if built.returncode:raise RuntimeError('certificate_cache_helper_compile_failed')
 c=json.loads((root/'config.json').read_text(encoding='utf-8-sig'));addresses=c['hostmap']['us.version.battle.net'];ip=next((x for x in addresses if ipaddress.ip_address(x).version==4),addresses[0])
 output=root/('certificate-cache-'+mode+'.json')
 try:
  with output.open('wb') as stream:r=subprocess.run([str(exe),mode,str(root),ip],stdout=stream,stderr=subprocess.DEVNULL,timeout=50)
  if output.stat().st_size>16384:raise RuntimeError('certificate_cache_output_limit')
  report=json.loads(output.read_text(encoding='utf-8-sig'))
  if report.get('mode')!=mode or report.get('host')!='us.version.battle.net':raise RuntimeError('certificate_cache_report_invalid')
  if r.returncode or report.get('successful') is not True:raise RuntimeError('certificate_cache_'+mode.lower()+'_failed')
  return report
 except subprocess.TimeoutExpired:
  output.write_text(json.dumps({'mode':mode,'host':'us.version.battle.net','successful':False,'error_type':'TimeoutExpired','raw_values_exported':False}));raise RuntimeError('certificate_cache_'+mode.lower()+'_timeout')
