from pathlib import Path
import copy,hashlib,importlib.util,json,shutil,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'control126'))
import run,common
class Classification(unittest.TestCase):
 def good(self):
  return dict(completed=True,errors=[],controller_pid=123,rows=[dict(phase=p,control_segment=s,round=r,role=role,pacing_sequence=i,gap_since_previous_probe_ms=4000 if i else None,controller_pid=123,probe_valid=True,connected=True,tls_verified=True,handshake_ok=True,http_status=200) for i,(p,s,r,role) in enumerate(run.schedule())])
 def test_good(self):self.assertEqual(run.summarize(self.good())['outcome'],'all_126_attempts_succeeded')
 def test_schedule(self):
  s=run.schedule();self.assertEqual(len(s),126)
  for role in ('A','B','REF'):self.assertEqual(sum(x[3]==role for x in s),42)
  self.assertEqual(s[123],('wl_denies_bl_A','after_restore_control',2,'REF'))
 def bad(self,key,val):
  q=self.good();q['rows'][123][key]=val;self.assertNotEqual(run.summarize(q)['outcome'],'all_126_attempts_succeeded')
 def test_timeout(self):self.bad('connected',False)
 def test_bad_echo(self):self.bad('handshake_ok',False)
 def test_invalid_child(self):self.bad('probe_valid',False)
 def test_tls(self):self.bad('tls_verified',False)
 def test_http(self):self.bad('http_status',302)
 def test_gap(self):self.bad('gap_since_previous_probe_ms',3999.999)
 def test_gap_nan(self):self.bad('gap_since_previous_probe_ms',float('nan'))
 def test_gap_boolean(self):self.bad('gap_since_previous_probe_ms',True)
 def test_pid(self):self.bad('controller_pid',124)
 def test_sequence(self):self.bad('pacing_sequence',122)
 def test_role(self):self.bad('role','A')
 def test_order(self):
  q=self.good();q['rows'][0],q['rows'][1]=q['rows'][1],q['rows'][0];self.assertNotEqual(run.summarize(q)['outcome'],'all_126_attempts_succeeded')
 def test_incomplete(self):
  q=self.good();q['completed']=False;self.assertNotEqual(run.summarize(q)['outcome'],'all_126_attempts_succeeded')
 def test_error(self):
  q=self.good();q['errors']=['controller error'];self.assertNotEqual(run.summarize(q)['outcome'],'all_126_attempts_succeeded')
 def test_short(self):
  q=self.good();q['rows'].pop();self.assertNotEqual(run.summarize(q)['outcome'],'all_126_attempts_succeeded')
class Admission(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.old=common.ROOT;common.ROOT=self.root
  self.cfg=dict(url='https://example.com/probe.php',address='8.8.8.8',port=443)
  self.job=self.root/'private-state/coexistence-jobs/abc';self.job.mkdir(parents=True)
  (self.root/'runtime').mkdir();self.programs=[]
  for role,n in [('A','python.exe'),('B','pythonw.exe')]:
   p=self.root/'runtime'/n;p.write_bytes(n.encode());self.programs.append(dict(role=role,path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
  self.report=dict(schema='unifiedfw-coexistence-result-1',https_pacing={},restore_verified=True,phases=[dict(restored=True,baseline_strict_equal=True)],endpoint=dict(https_url=self.cfg['url'],address=self.cfg['address'],port=443))
  (self.job/'request.json').write_text(json.dumps(dict(programs=self.programs)));self.save()
 def save(self):(self.job/'result.json').write_text(json.dumps(self.report))
 def tearDown(self):common.ROOT=self.old;self.t.cleanup()
 def test_binding(self):self.assertTrue(common.previous_test(self.cfg)['previous_restoration_record_is_not_a_live_policy_check'])
 def test_unrestored(self):
  self.report['restore_verified']=False;self.save()
  with self.assertRaises(ValueError):common.previous_test(self.cfg)
 def test_strict(self):
  self.report['phases'][0]['baseline_strict_equal']=False;self.save()
  with self.assertRaises(ValueError):common.previous_test(self.cfg)
 def test_hash(self):
  (self.root/'runtime/python.exe').write_bytes(b'changed')
  with self.assertRaises(ValueError):common.previous_test(self.cfg)
 def test_other_endpoint(self):
  with self.assertRaises(ValueError):common.previous_test(self.cfg|{'address':'1.1.1.1'})
 def test_newer_bad(self):
  import os
  other=self.job.parent/'new';other.mkdir();p=other/'result.json';p.write_text(json.dumps(self.report|{'restore_verified':False}));os.utime(p,(2000000000,2000000000))
  with self.assertRaises(ValueError):common.previous_test(self.cfg)
 def test_symlink(self):
  (self.root/'link').symlink_to(self.root/'runtime',target_is_directory=True)
  with self.assertRaises(ValueError):common.safe(self.root/'link/python.exe')
 def test_request_outside(self):
  with self.assertRaises(ValueError):common.admit(self.job/'request.json',self.job/'outside.json')
 def test_verify_real_overlay(self):
  for p in Path('/data/unified-firewall-0.8.1').rglob('*'):
   if p.is_file() and '__pycache__' not in p.parts and 'private-state' not in p.parts:
    dest=self.root/p.relative_to('/data/unified-firewall-0.8.1');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
  for p in ROOT.rglob('*'):
   if p.is_file() and '__pycache__' not in p.parts:
    dest=self.root/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
  common.verify()
  (self.root/'control126/probe.py').write_text('# tampered')
  with self.assertRaises(ValueError):common.verify()
class SourceSafety(unittest.TestCase):
 def test_no_policy_mutators(self):
  import re
  text='\n'.join(p.read_text('utf-8-sig') for p in (ROOT/'control126').glob('*') if p.suffix in ('.py','.ps1'))
  for pattern in (r'(?i)New-NetFirewall',r'(?i)Set-NetFirewall',r'(?i)Remove-NetFirewall',r'(?i)netsh\s',r'(?i)rasdial\s',r'(?i)Set-ExecutionPolicy',r'(?i)ServerCertificateValidationCallback'):self.assertIsNone(re.search(pattern,text))
 def test_original_transport_identity(self):
  for n in ('https_common.py','https-tools.ps1','traffic_common.py'):self.assertEqual((ROOT/'control126'/n).read_bytes(),(Path('/data/unified-firewall-0.8.1/lab')/n).read_bytes())
if __name__=='__main__':unittest.main()
