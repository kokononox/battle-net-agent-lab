import json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import BASE,spec,digest
PS=os.environ.get('WOW_QA_PWSH')
def quoted(p):return str(p).replace("'","''")
MOCKS=r'''
$global:store=@{};$global:adds=0;$global:removes=0
function Get-NetFirewallRule { [CmdletBinding()]param($PolicyStore); @($global:store.Values) }
function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore); @([pscustomobject]@{Enabled='True'},[pscustomobject]@{Enabled='True'},[pscustomobject]@{Enabled='True'}) }
function Get-Service { [CmdletBinding()]param($Name); [pscustomobject]@{Status='Running'} }
function New-NetFirewallRule { [CmdletBinding()]param($PolicyStore,$Name,$DisplayName,$Group,$Direction,$Action,$Enabled,$Profile,$Program,$Protocol,$RemoteAddress,$RemotePort)
 $global:adds++;$r=[pscustomobject]@{Name=$Name;Group=$Group;Direction=$Direction;Action=$Action;Enabled=$Enabled;Profile=$Profile;Program=$Program;IP=$RemoteAddress;Port=$RemotePort;Protocol=$Protocol};$global:store[$Name]=$r;$r
}
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{Program=$InputObject.Program}} }
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{RemoteAddress=$InputObject.IP}} }
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{RemotePort=$InputObject.Port;Protocol=$InputObject.Protocol}} }
function Remove-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{if($InputObject.Group -eq 'Unrelated'){throw 'foreign_rule_removal_attempt'};$global:removes++;$global:store.Remove($InputObject.Name)} }
'''
@unittest.skipUnless(PS,'Official QA PowerShell runtime required')
class RealPowerShell(unittest.TestCase):
 def env(self,**kwargs):return {**os.environ,'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT':'1',**kwargs}
 def runps(self,code,env=None):return subprocess.run([PS,'-NoLogo','-NoProfile','-NonInteractive','-Command',code],env=env or self.env(),capture_output=True,timeout=40)
 def test_all_scripts_parse(self):
  for script in (BASE/'app').glob('*.ps1'):
   code="$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile('"+quoted(script)+"',[ref]$t,[ref]$e);if($e.Count){$e|ForEach-Object {$_.Message};exit 2}"
   r=self.runps(code);self.assertEqual(r.returncode,0,r.stdout.decode(errors='replace')+r.stderr.decode(errors='replace'))
 def test_real_reconcile_ten_update_restore_preserves_foreign(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');owner='a'*32;entries=json.loads((BASE/'app/defaults.json').read_text());plans=[]
   for action,items in [('apply',entries),('apply',entries[:-1]),('restore',[]),('status',[])]:
    plan=dict(owner=owner,program=str(exe),action=action,entries=[spec(owner,str(exe),e) for e in items]);p=root/('plan-'+str(len(plans))+'.json');p.write_text(json.dumps(plan));plans.append(p)
   code=MOCKS+"\n$global:store['Unrelated']=[pscustomobject]@{Name='Unrelated';Group='Unrelated'}\n"
   for p in plans:code+="$env:WOW_BL_REQUEST='"+quoted(p)+"';& ([scriptblock]::Create([IO.File]::ReadAllText('"+quoted(BASE/'app/firewall.ps1')+"')))\n"
   code+="if($global:store.Count -ne 1 -or !$global:store.ContainsKey('Unrelated') -or $global:adds -ne 10 -or $global:removes -ne 10){throw 'reconcile_invariant_failed'}"
   r=self.runps(code);self.assertEqual(r.returncode,0,r.stdout.decode(errors='replace')+r.stderr.decode(errors='replace'))
   results=[json.loads(s) for s in r.stdout.decode('utf-8-sig').splitlines() if s.startswith('{')];self.assertEqual(len(results),4);self.assertEqual(results[0]['persistent_count'],10);self.assertEqual(results[1]['active_count'],9);self.assertTrue(results[2]['absence_verified'])
 def test_foreign_name_collision_is_not_removed_or_overwritten(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');owner='b'*32;e=spec(owner,str(exe),dict(ip='1.1.1.1',port=443,protocol='TCP'));p=root/'plan.json';p.write_text(json.dumps(dict(owner=owner,program=str(exe),action='apply',entries=[e])))
   code=MOCKS+"\n$global:store['"+e['name']+"']=[pscustomobject]@{Name='"+e['name']+"';Group='Unrelated'}\n$env:WOW_BL_REQUEST='"+quoted(p)+"';& ([scriptblock]::Create([IO.File]::ReadAllText('"+quoted(BASE/'app/firewall.ps1')+"')))"
   r=self.runps(code);self.assertEqual(r.returncode,3);result=json.loads(r.stdout.decode('utf-8-sig'));self.assertEqual(result['stage'],'check_name_collisions');self.assertFalse(result['ok'])
 def test_real_observer_ready_stop_and_destination_output(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');p=root/'plan.json';ready=root/'job.ready';stop=root/'job.stop'
   p.write_text(json.dumps(dict(program=str(exe),program_sha256=digest(exe),seconds=60,parent_pid=os.getpid(),ready_path=str(ready),stop_path=str(stop))))
   code="$global:born=[DateTime]::Now.AddSeconds(1);function Get-Process {param($Id,$Name,$ErrorAction);[pscustomobject]@{Id=123;Path='"+quoted(exe)+"';StartTime=$global:born}};function Get-NetTCPConnection {[pscustomobject]@{OwningProcess=123;RemoteAddress='3.125.189.135';RemotePort=443}};& ([scriptblock]::Create([IO.File]::ReadAllText('"+quoted(BASE/'app/observe.ps1')+"')))"
   proc=subprocess.Popen([PS,'-NoLogo','-NoProfile','-NonInteractive','-Command',code],env=self.env(WOW_BL_REQUEST=str(p)),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   try:
    end=time.monotonic()+15
    while time.monotonic()<end and not ready.exists():
     if proc.poll() is not None:break
     time.sleep(.05)
    self.assertTrue(ready.exists());time.sleep(1.2);stop.write_text('stop');out,err=proc.communicate(timeout=10);self.assertEqual(proc.returncode,0,err.decode(errors='replace'));result=json.loads(out.decode('utf-8-sig'));self.assertTrue(result['ok']);self.assertEqual(result['endpoints'][0]['ip'],'3.125.189.135');self.assertGreater(result['endpoints'][0]['samples'],0)
   finally:
    if proc.poll() is None:proc.kill();proc.communicate()
if __name__=='__main__':unittest.main()
