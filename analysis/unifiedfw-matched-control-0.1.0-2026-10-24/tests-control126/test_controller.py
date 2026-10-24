"""Controller fixture: actual PowerShell parser/control flow; mocked network and clock only."""
from pathlib import Path
import hashlib,json,shutil,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1];PS='/data/devtools/pwsh/pwsh'
class ControllerTests(unittest.TestCase):
 def execute(self,failure=False,invalid=False):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);d=root/'control126';shutil.copytree(ROOT/'control126',d,ignore=shutil.ignore_patterns('__pycache__'))
   job=root/'private-state/control126-jobs/fixture';job.mkdir(parents=True);(root/'runtime').mkdir()
   programs=[]
   for role,name in [('A','python.exe'),('B','pythonw.exe')]:
    p=root/'runtime'/name;p.write_bytes(b'fixture');programs.append(dict(role=role,path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
   q=dict(schema='unifiedfw-control126-request-1',https_url='https://example.com/probe.php',address='8.8.8.8',programs=programs)
   if invalid:q['programs'][0]['sha256']='0'*64
   req=job/'request.json';out=job/'result.json';req.write_text(json.dumps(q))
   code=(d/'controller.ps1').read_text('utf-8-sig');needle=". (Join-Path $PSScriptRoot 'https-tools.ps1')"
   mock='''
$script:Tick=0.0
function TMonotonicMilliseconds(){return $script:Tick}
function TDelayMilliseconds([int]$Milliseconds){$script:Tick+=$Milliseconds}
function MakeRow($C){$script:Tick+=100;return [pscustomobject]@{probe_valid=$true;request_id=$C.request_id;role=$C.role;connected=$true;tls_verified=$true;handshake_ok=$true;http_status=200;stage='complete';error=$null}}
function HReference($URL,$Address,$C){$r=MakeRow $C;FAILURE;return $r}
function TRunProcess($Exe,$Script,$Request,$Output){$v=ConvertFrom-Json ([IO.File]::ReadAllText($Request));return (MakeRow $v.challenge)}
'''.replace('FAILURE',"if($script:THttpsSequence -eq 123){$r.connected=$false;$r.handshake_ok=$false;$r.stage='tcp_connect';$r.error='https_connect_timeout'}" if failure else '')
   (d/'fixture.ps1').write_text(code.replace(needle,needle+mock),encoding='utf-8-sig')
   cp=subprocess.run([PS,'-NoLogo','-NoProfile','-File',str(d/'fixture.ps1'),'-Request',str(req),'-Output',str(out)],capture_output=True,text=True,timeout=60)
   if invalid:
    self.assertNotEqual(cp.returncode,0);self.assertFalse(out.exists());return
   self.assertEqual(cp.returncode,0,cp.stderr);r=json.loads(out.read_text('utf-8-sig'));self.assertEqual(len(r['rows']),126);self.assertTrue(r['completed']);self.assertEqual([x['pacing_sequence'] for x in r['rows']],list(range(126)))
   self.assertTrue(all(x['gap_since_previous_probe_ms']>=4000 for x in r['rows'][1:]));self.assertEqual(len({x['controller_pid'] for x in r['rows']}),1)
   self.assertEqual(r['rows'][123]['role'],'REF');self.assertEqual(r['rows'][123]['phase'],'wl_denies_bl_A');self.assertEqual(r['rows'][123]['control_segment'],'after_restore_control')
   if failure:self.assertEqual(r['rows'][123]['error'],'https_connect_timeout');self.assertTrue(r['rows'][125]['handshake_ok'])
 def test_runtime_tamper_rejected_before_network(self):self.execute(invalid=True)
 def test_all_126(self):self.execute()
 def test_timeout_preserved_and_continued(self):self.execute(True)
 def test_parser(self):
  s="param($Dir)\n$errors=@();Get-ChildItem -LiteralPath $Dir -Filter *.ps1 | ForEach-Object {$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e);$errors+=@($e)};if($errors.Count){$errors|Out-String|Write-Error;exit 1}"
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'parse.ps1';p.write_text(s);cp=subprocess.run([PS,'-NoProfile','-File',str(p),str(ROOT/'control126')],capture_output=True,text=True);self.assertEqual(cp.returncode,0,cp.stderr)
if __name__=='__main__':unittest.main()
