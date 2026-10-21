import json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import observer
PS=os.environ.get('WOW_QA_PWSH')
class MonitorPathTests(unittest.TestCase):
 def test_explicit_path_parts_not_null_extension(self):
  s=(Path(observer.__file__).parent/'monitor.ps1').read_text();self.assertNotIn('ChangeExtension($jpath,$null)',s);self.assertIn('GetFileNameWithoutExtension($jpath)',s)
 @unittest.skipUnless(PS,'Set WOW_QA_PWSH to an official PowerShell runtime for real parser/handshake QA')
 def test_real_powershell_start_and_stop_handshake(self):
  with tempfile.TemporaryDirectory(prefix='wow.monitor.') as t:
   root=Path(t);i='b'*32;j=root/('session-'+i+'.json')
   j.write_text(json.dumps({'id':i,'name':'WoWEndpointSteps-'+i,'group':'WoWEndpointStepsOwner-'+i,'program':str(root/'Wow.exe'),'parent_pid':os.getpid(),'protocol':'TCP','ip':'3.124.215.108','port':443}))
   script=Path(observer.__file__).parent/'monitor.ps1'
   # Windows-only data sources mocked; actual PowerShell parser, file paths,
   # loop readiness, stop marker, and JSON serialization execute for real.
   code="function Get-NetTCPConnection { @() }; function Get-WinEvent { @() }; & ([scriptblock]::Create([IO.File]::ReadAllText('"+str(script).replace("'","''")+"')))"
   env=os.environ.copy();env.update(WOW_STEPS_MONITOR_JOURNAL=str(j),DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='1')
   p=subprocess.Popen([PS,'-NoLogo','-NoProfile','-NonInteractive','-Command',code],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   try:
    end=time.monotonic()+15
    while time.monotonic()<end and not j.with_suffix('.monitor-ready').exists():
     if p.poll() is not None:break
     time.sleep(.05)
    self.assertTrue(j.with_suffix('.monitor-ready').exists(),'expected single-dot readiness file missing')
    self.assertFalse((root/('session-'+i+'..monitor-ready')).exists())
    out=observer.stop(j);self.assertEqual(out['status'],'sample_finished');self.assertEqual(out['wfp_query_status'],'queried')
    stdout,stderr=p.communicate(timeout=10);self.assertEqual(p.returncode,0,stderr.decode(errors='replace'))
    self.assertTrue(j.with_suffix('.monitor-result').exists());self.assertFalse((root/('session-'+i+'..monitor-result')).exists())
   finally:
    if p.poll() is None:p.kill();p.communicate()
 @unittest.skipUnless(PS,'Official PowerShell runtime required')
 def test_original_null_extension_expression_reproduces_extra_dot(self):
  env=os.environ.copy();env['DOTNET_SYSTEM_GLOBALIZATION_INVARIANT']='1'
  code="[IO.Path]::ChangeExtension('/tmp/session-example.json',$null)+'.monitor-ready'"
  p=subprocess.run([PS,'-NoLogo','-NoProfile','-Command',code],env=env,capture_output=True,timeout=20)
  self.assertEqual(p.returncode,0);self.assertTrue(p.stdout.decode().strip().endswith('session-example..monitor-ready'))
 @unittest.skipUnless(PS,'Official PowerShell runtime required')
 def test_real_parser_no_syntax_errors(self):
  r=Path(observer.__file__).parent
  for script in (r/'monitor.ps1',r/'firewall.ps1'):
   code="$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('"+str(script).replace("'","''")+"',[ref]$t,[ref]$e); if($e.Count -gt 0){exit 2}else{exit 0}"
   env=os.environ.copy();env['DOTNET_SYSTEM_GLOBALIZATION_INVARIANT']='1'
   p=subprocess.run([PS,'-NoLogo','-NoProfile','-Command',code],env=env,capture_output=True,timeout=20)
   self.assertEqual(p.returncode,0,script.name+' parser errors')
if __name__=='__main__':unittest.main()
