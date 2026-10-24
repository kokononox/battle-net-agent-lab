from pathlib import Path
import hashlib,json,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'trace082'))
import run,common
class Admission(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.old=(run.ROOT,common.ROOT);run.ROOT=common.ROOT=self.root
  self.cfg=dict(url='https://example.com/probe.php',address='8.8.8.8',port=443);self.binding=dict(previous_report_sha256='f'*64)
  (self.root/'runtime').mkdir();programs=[]
  for role,n in [('A','python.exe'),('B','pythonw.exe')]:
   p=self.root/'runtime'/n;p.write_bytes(n.encode());programs.append(dict(role=role,path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
  schedule=[(p,s,i,role) for p in ('baseline','wl_allows','wl_denies','wl_allows_bl_A','wl_allows_bl_B','wl_allows_bl_both','wl_denies_bl_A') for s in ('during_control','after_restore_control') for i,roles in enumerate((('REF','A','B'),('B','A','REF'),('REF','A','B'))) for role in roles]
  self.report=dict(schema='unifiedfw-control126-result-1',completed=True,errors=[],controller_exit_code=0,classification=dict(outcome='all_126_attempts_succeeded'),firewall_mutation_attempted=False,vpn_or_route_changes_attempted=False,endpoint=self.cfg,programs=programs,controller_pid=99,same_path_binding=self.binding,rows=[dict(phase=p,control_segment=s,round=i,role=role,controller_pid=99,pacing_sequence=n,probe_valid=True,connected=True,tls_verified=True,handshake_ok=True,http_status=200,gap_since_previous_probe_ms=4000 if n else None) for n,(p,s,i,role) in enumerate(schedule)])
  self.job=self.root/'private-state/control126-jobs/abc';self.job.mkdir(parents=True);self.save()
 def save(self):(self.job/'result.json').write_text(json.dumps(self.report))
 def tearDown(self):run.ROOT,common.ROOT=self.old;self.t.cleanup()
 def reject(self):
  self.save()
  with self.assertRaises(ValueError):run.control_binding(self.cfg,self.binding)
 def test_success(self):self.assertTrue(run.control_binding(self.cfg,self.binding)['control126_pass_checked'])
 def test_old_control_binding(self):
  with self.assertRaises(ValueError):run.control_binding(self.cfg,dict(previous_report_sha256='a'*64))
 def test_bad_latest(self):self.report['completed']=False;self.reject()
 def test_wrong_endpoint(self):self.report['endpoint']=dict(self.cfg,address='1.1.1.1');self.reject()
 def test_runtime_tamper(self):
  (self.root/'runtime/python.exe').write_bytes(b'changed')
  with self.assertRaises(ValueError):run.control_binding(self.cfg,self.binding)
 def test_changed_path(self):self.report['programs'][0]['path']='C:\\other\\python.exe';self.reject()
 def test_short(self):self.report['rows'].pop();self.reject()
 def test_timeout(self):self.report['rows'][123]['handshake_ok']=False;self.reject()
 def test_gap(self):self.report['rows'][123]['gap_since_previous_probe_ms']=3999;self.reject()
 def test_order(self):self.report['rows'][123]['role']='A';self.reject()
 def test_pid(self):self.report['rows'][123]['controller_pid']=100;self.reject()
 def test_sequence(self):self.report['rows'][123]['pacing_sequence']=122;self.reject()
 def test_scope(self):self.report['firewall_mutation_attempted']=True;self.reject()
 def test_newer_bad_no_fallback(self):
  import os
  new=self.job.parent/'new';new.mkdir();p=new/'result.json';p.write_text(json.dumps(self.report|{'completed':False}));os.utime(p,(2000000000,2000000000))
  with self.assertRaises(ValueError):run.control_binding(self.cfg,self.binding)
 def test_symlink(self):
  (self.root/'link').symlink_to(self.root/'runtime',target_is_directory=True)
  with self.assertRaises(ValueError):common.safe(self.root/'link/python.exe')
class Preservation(unittest.TestCase):
 def test_original_tcp_and_process_functions(self):
  base=(Path('/data/unified-firewall-0.8.1/lab/traffic-tools.ps1')).read_text('utf-8-sig');new=(ROOT/'trace082/traffic-tools.ps1').read_text('utf-8-sig')
  for name,nextname in [('TRunProcess','TReference'),('TReference',None)]:
   first=base.index('function '+name);end=base.index('function '+nextname) if nextname else base.index('# Fixed HTTPS pacing')
   fragment=base[first:end];self.assertIn(fragment,new)
 def test_no_force_or_profile_changes(self):
  import re
  source='\n'.join(p.read_text('utf-8-sig') for p in (ROOT/'trace082').glob('*.ps1'))
  for pattern in (r'(?i)Set-NetFirewallProfile',r'(?i)Set-ExecutionPolicy',r'(?i)New-NetRoute',r'(?i)Remove-NetRoute',r'(?i)Set-VpnConnection',r'(?i)Invoke-Expression'):self.assertIsNone(re.search(pattern,source))

class OverlayIntegrity(unittest.TestCase):
 def test_exact_overlay_and_tamper(self):
  import shutil
  old=common.ROOT
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp)/'base';shutil.copytree('/data/unified-firewall-0.8.1',root,ignore=shutil.ignore_patterns('__pycache__','private-state'));shutil.copytree(ROOT,root,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','private-state'))
   common.ROOT=root
   try:
    common.verify();(root/'trace082/trace-tools.ps1').write_text('# tampered')
    with self.assertRaises(ValueError):common.verify()
   finally:common.ROOT=old
 def test_manifest_pinned(self):
  old=common.ROOT
  with tempfile.TemporaryDirectory() as temp:
   common.ROOT=Path(temp);(common.ROOT/'MANIFEST-SHA256.json').write_text('{}')
   try:
    with self.assertRaises(ValueError):common.verify()
   finally:common.ROOT=old

if __name__=='__main__':unittest.main()
