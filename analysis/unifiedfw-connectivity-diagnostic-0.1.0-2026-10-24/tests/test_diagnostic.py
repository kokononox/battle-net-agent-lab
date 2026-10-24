from pathlib import Path
import contextlib,importlib.util,io,json,os,subprocess,sys,tempfile,types,unittest,zipfile
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'diag'))
import common,https_common as h
spec=importlib.util.spec_from_file_location('diagnostic',ROOT/'diag/run.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
URL='https://ufw-test.example/probe.php';IP='9.9.9.9'
def good(role):return dict(role=role,probe_valid=True,connected=True,tls_verified=True,http_status=200,handshake_ok=True,stage='complete',error=None,error_code=None)
class DiagnosticTests(unittest.TestCase):
 def test_order_balanced(self):
  self.assertEqual(len(d.orders()),6)
  for role in ('A','B','REF'):
   for position in range(3):self.assertEqual(sum(row[position]==role for row in d.orders()),2)
 def test_summary_requires_all18(self):
  rows=[dict(good(role),round=i) for i,roles in enumerate(d.orders()) for role in roles]
  self.assertEqual(d.summarize(rows,True)['outcome'],'all_18_attempts_succeeded')
  self.assertNotEqual(d.summarize(rows,False)['outcome'],'all_18_attempts_succeeded')
  self.assertNotEqual(d.summarize(rows[:-1],True)['outcome'],'all_18_attempts_succeeded')
 def test_duplicate_or_missing_round_never_passes(self):
  rows=[dict(good(role),round=i) for i,roles in enumerate(d.orders()) for role in roles];rows[0]['round']=1
  self.assertNotEqual(d.summarize(rows,True)['outcome'],'all_18_attempts_succeeded')
 def test_timeout_and_access_denied_never_count_as_success_or_block_acceptance(self):
  for code in (None,10013):
   rows=[dict(good(role),round=i) for i,roles in enumerate(d.orders()) for role in roles];rows[0].update(connected=False,handshake_ok=False,error='timeout_or_denied',error_code=code,stage='tcp_connect')
   self.assertNotEqual(d.summarize(rows,True)['outcome'],'all_18_attempts_succeeded')
 def test_invalid_probe_not_counted(self):
  rows=[dict(good(role),round=i) for i,roles in enumerate(d.orders()) for role in roles];rows[0]['probe_valid']=False
  self.assertNotEqual(d.summarize(rows,True)['outcome'],'all_18_attempts_succeeded')
 def test_distinct_executable_commands(self):
  with patch.object(d,'os',types.SimpleNamespace(environ={'SystemRoot':'C:/Windows'})):
   a=d.child('A',Path('r'),Path('o'));b=d.child('B',Path('r'),Path('o'));ref=d.child('REF',Path('r'),Path('o'))
  self.assertTrue(a[0].endswith('python.exe'));self.assertTrue(b[0].endswith('pythonw.exe'));self.assertTrue(ref[0].endswith('powershell.exe'));self.assertNotIn('Bypass',ref)
 def exercise(self,mode='good'):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'BUILD-INFO.json').write_text('{}');(root/'runtime').mkdir();(root/'runtime/python.exe').write_bytes(b'test-A');(root/'runtime/pythonw.exe').write_bytes(b'test-B');count=[];sleeps=[]
   def execute(args,**kwargs):
    request=Path(args[args.index('--request')+1] if '--request' in args else args[args.index('-Request')+1]);output=Path(args[args.index('--output')+1] if '--output' in args else args[args.index('-Output')+1]);q=json.loads(request.read_text());count.append(q['challenge']['role'])
    if mode=='interrupt' and len(count)==2:raise KeyboardInterrupt()
    if mode=='timeout' and len(count)==2:raise subprocess.TimeoutExpired(args,20)
    row=good(q['challenge']['role']);row['request_id']=q['challenge']['request_id']
    if mode=='identity' and len(count)==2:row['request_id']='wrong'
    output.write_text(json.dumps(row));return subprocess.CompletedProcess(args,0,b'',b'')
   inputs=iter([URL,IP,'ON','I CONTROL THIS TEST ENDPOINT'])
   fakeos=types.SimpleNamespace(name='nt',environ={'SystemRoot':'C:/Windows'},CREATE_NO_WINDOW=0)
   m=types.SimpleNamespace(LK_NBLCK=1,LK_UNLCK=0,locking=lambda *args:None)
   with patch.object(d,'ROOT',root),patch.object(d,'verify'),patch.object(d,'os',fakeos),patch.object(d,'verify_dns',side_effect=ValueError('DNS_mismatch') if mode=='dns' else None,return_value=[IP]),patch.dict(sys.modules,{'msvcrt':m}),patch('builtins.input',side_effect=lambda *args:next(inputs)),patch.object(d.subprocess,'run',side_effect=execute),patch.object(d.time,'sleep',side_effect=lambda x:sleeps.append(x)),contextlib.redirect_stdout(io.StringIO()):code=d.run()
   reports=list(root.glob('UnifiedFW-Connectivity-Results-*.zip'));self.assertEqual(len(reports),1)
   with zipfile.ZipFile(reports[0]) as z:
    self.assertEqual(set(z.namelist()),{'result.json','BUILD-INFO.json','report-sha256.json'});report=json.loads(z.read('result.json'))
   self.assertFalse(report['firewall_mutation_attempted']);self.assertFalse(report['protection_verified']);return code,report,count,sleeps
 def test_full_orchestrator_18_serial_no_retry_17_gaps(self):
  code,r,count,gaps=self.exercise();self.assertEqual(code,0);self.assertEqual(len(count),18);self.assertEqual(gaps,[4]*17);self.assertTrue(r['completed'])
 def test_child_timeout_retained_no_retry(self):
  code,r,count,gaps=self.exercise('timeout');self.assertEqual(code,1);self.assertEqual(len(count),18);self.assertFalse(r['rows'][1]['probe_valid']);self.assertEqual(r['rows'][1]['stage'],'child_execution')
 def test_child_identity_mismatch_invalid(self):
  code,r,*_=self.exercise('identity');self.assertEqual(code,1);self.assertFalse(r['rows'][1]['probe_valid'])
 def test_interrupt_keeps_partial_and_exports(self):
  code,r,count,_=self.exercise('interrupt');self.assertEqual(code,1);self.assertFalse(r['completed']);self.assertEqual(len(r['rows']),1)
 def test_dns_failure_zero_attempts(self):
  code,r,count,_=self.exercise('dns');self.assertEqual(code,1);self.assertEqual(count,[]);self.assertFalse(r['completed'])
 def test_request_admission_rejects_other_directory(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);req=root/'r.json';req.write_text('{}')
   with patch.object(common,'ROOT',root),self.assertRaisesRegex(ValueError,'scope'):common.admit(req,root/'o.json')
 def test_request_admission_validates_challenge(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);job=root/'private-state/jobs/abc';job.mkdir(parents=True);req=job/'r.json'
   q={'url':URL,'address':IP,'challenge':{'kind':'unifiedfw-traffic-1','nonce':'a'*64,'request_id':'b'*32,'role':'A'}};req.write_text(json.dumps(q))
   with patch.object(common,'ROOT',root):self.assertEqual(common.admit(req,job/'o.json')[0],q)
   q['challenge']['role']='OTHER';req.write_text(json.dumps(q))
   with patch.object(common,'ROOT',root),self.assertRaises(ValueError):common.admit(req,job/'o.json')
 def test_symlink_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   a=Path(tmp)/'a';a.symlink_to('/tmp',target_is_directory=True)
   with self.assertRaises(ValueError):common.safe(a/'file.json')
 def test_canonical_and_public_gate(self):
  for url in ('http://ufw-test.example/probe.php',URL+'?x=1',URL+'#x','https://ufw-test.example:443/probe.php'):
   with self.assertRaises(ValueError):h.https_endpoint(url,IP)
  for ip in ('127.0.0.1','10.0.0.1','203.0.113.1','::1'):
   with self.assertRaises(ValueError):h.https_endpoint(URL,ip)
 def test_no_policy_mutation_implementation_in_distribution(self):
  for p in (ROOT/'diag').iterdir():
   if p.suffix not in ('.py','.ps1'):continue
   s=p.read_text('utf-8-sig').lower()
   for forbidden in ('new-netfirewallrule','remove-netfirewallrule','set-netfirewall','new-netroute','set-netroute','rasdial','netsh ','session-core.ps1','native.ps1','-verb runas'):
    self.assertNotIn(forbidden,s,p.name)
if __name__=='__main__':unittest.main()
