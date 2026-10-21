import ipaddress,json,os,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from backend import Manager,BlacklistError,atomic,BASE,parse_list,parse_target,format_list
from range_builder import build_range
from dns_lookup import Resolver,clean_names,query_ptr
import test_manager as tm
import test_real_powershell as tp

def make(mode,value,last='',port=80,protocol='TCP'):
 return build_range(dict(mode=mode,value=value,last=last,port=port,protocol=protocol),parse_target,format_list)
class RangeBuilderTests(unittest.TestCase):
 def test_star_and_x_and_abbreviated_patterns(self):
  for value in ('2.*.*.*','2.x.x.x','2.X.X.X','2'):
   r=make('pattern',value);self.assertEqual(r['text'],'2.0.0.0/8:80 TCP');self.assertEqual(r['address_count'],'16777216');self.assertFalse(r['applied'])
  self.assertEqual(make('pattern','2.19')['text'],'2.19.0.0/16:80 TCP')
  self.assertEqual(make('pattern','2.19.198.*')['text'],'2.19.198.0/24:80 TCP')
 def test_pattern_single_host_and_port_protocol(self):
  r=make('pattern','2.19.198.11',port=443,protocol='UDP');self.assertEqual(r['text'],'2.19.198.11:443 UDP');self.assertEqual(r['address_count'],'1')
 def test_cidr_host_address_explicitly_previews_real_boundary(self):
  r=make('cidr','2.19.198.11/8');self.assertEqual(r['first_ip'],'2.0.0.0');self.assertEqual(r['last_ip'],'2.255.255.255');self.assertEqual(r['text'],'2.0.0.0/8:80 TCP')
 def test_between_has_exact_coverage_no_added_hosts(self):
  r=make('between','2.19.198.10','2.19.198.20');nets=[ipaddress.ip_network(e['ip']) for e in r['entries']]
  self.assertEqual(r['address_count'],'11');self.assertEqual(sum(n.num_addresses for n in nets),11);self.assertEqual(min(n.network_address for n in nets),ipaddress.ip_address('2.19.198.10'));self.assertEqual(max(n.broadcast_address for n in nets),ipaddress.ip_address('2.19.198.20'));self.assertEqual(parse_list(r['text']),r['entries'])
 def test_between_full_octet_reduces_to_one_cidr(self):
  r=make('between','2.0.0.0','2.255.255.255');self.assertEqual(r['rule_count'],1);self.assertEqual(r['entries'][0]['ip'],'2.0.0.0/8')
 def test_ipv6_cidr_and_between(self):
  r=make('cidr','2606:4700::/32');self.assertEqual(r['text'],'[2606:4700::/32]:80 TCP')
  r=make('between','2606:4700::1','2606:4700::a');self.assertEqual(r['address_count'],'10');self.assertEqual(parse_list(r['text']),r['entries'])
 def test_public_only_and_overlap_checked_across_entire_range(self):
  for mode,value,last in [('pattern','*.*.*.*',''),('pattern','10.*.*.*',''),('cidr','0.0.0.0/0',''),('between','9.255.255.255','11.0.0.0'),('between','192.0.0.1','192.1.1.1')]:
   with self.subTest(mode=mode,value=value),self.assertRaises(ValueError):make(mode,value,last)
 def test_invalid_inputs_rejected(self):
  cases=[('pattern','2.*.19.*',''),('pattern','2.256',''),('pattern','2..3',''),('pattern','02',''),('between','2.0.0.2','2.0.0.1'),('between','2.0.0.1','2606:4700::1'),('cidr','example.com','')]
  for mode,value,last in cases:
   with self.subTest(value=value),self.assertRaises(ValueError):make(mode,value,last)
  for port in (0,65536,'80',True):
   with self.assertRaises(ValueError):make('pattern','2',port=port)
 def test_random_exact_ipv4_interval_coverage(self):
  import random
  rng=random.Random(42)
  for _ in range(100):
   a=rng.randrange(0,65535);b=rng.randrange(a,65536);base=int(ipaddress.ip_address('2.19.0.0'))
   r=make('between',str(ipaddress.ip_address(base+a)),str(ipaddress.ip_address(base+b)))
   nets=[ipaddress.ip_network(e['ip']) for e in r['entries']];self.assertEqual(sum(n.num_addresses for n in nets),b-a+1)
   self.assertEqual(int(nets[0].network_address),base+a);self.assertEqual(int(nets[-1].broadcast_address),base+b)

class ResolverTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.now=100000.;self.calls=[]
  def query(ip):self.calls.append(ip);return dict(status='found',names=['Host.Example.COM.'])
  self.query=query;self.res=Resolver(self.root/'cache.json',BASE/'app',atomic,query=query,clock=lambda:self.now)
 def tearDown(self):self.tmp.cleanup()
 def test_clean_names_not_html_or_shell(self):
  self.assertEqual(clean_names(['Host.Example.com.','host.example.com','<script>x</script>','a;calc','bad\nname','x'*64+'.com']),['host.example.com'])
 def test_dedup_ip_across_ports(self):
  r=self.res.lookup(parse_list('2.19.198.11:80 TCP\n2.19.198.11:443 TCP'));self.assertEqual(self.calls,['2.19.198.11']);self.assertEqual(r['requested'],1);self.assertFalse(r['actual_domain_verified']);self.assertFalse(r['firewall_changed'])
 def test_cache_hit_restart_and_force_refresh(self):
  e=parse_list('2.19.198.11:80 TCP');self.res.lookup(e);r=self.res.lookup(e);self.assertEqual(len(self.calls),1);self.assertTrue(r['entries'][0]['cached'])
  other=Resolver(self.res.path,BASE/'app',atomic,query=self.query,clock=lambda:self.now);self.assertEqual(other.rows()[0]['names'],['host.example.com']);other.lookup(e);self.assertEqual(len(self.calls),1);other.lookup(e,force=True);self.assertEqual(len(self.calls),2)
 def test_positive_expiry(self):
  e=parse_list('2.19.198.11:80 TCP');self.res.lookup(e);self.now+=86401;self.assertTrue(self.res.rows()[0]['stale']);self.res.lookup(e);self.assertEqual(len(self.calls),2)
 def test_no_ptr_timeout_error_are_distinct_and_cached(self):
  for status,ttl in [('no_ptr',900),('timeout',60),('error',60)]:
   self.res.cache={};self.res.query=lambda ip:dict(status=status,names=[]);r=self.res.lookup(parse_list('2.19.198.11:80 TCP'))
   self.assertEqual(r['entries'][0]['status'],status);self.assertEqual(r['entries'][0]['expires_utc']-r['entries'][0]['checked_utc'],ttl)
 def test_bad_resolver_data_is_not_found(self):
  for raw in (None,[],{'status':'found','names':['<script>']},{'status':'made_up','names':[]}):
   self.res.cache={};self.res.query=lambda ip:raw;r=self.res.lookup(parse_list('2.19.198.11:80 TCP'));self.assertEqual(r['entries'][0]['status'],'error')
 def test_ranges_skipped_not_expanded_or_queried(self):
  r=self.res.lookup(parse_list('2.0.0.0/8:80 TCP'));self.assertEqual(self.calls,[]);self.assertEqual(r['skipped_ranges'],['2.0.0.0/8']);self.assertEqual(r['completed'],0)
 def test_stop_before_scheduling(self):
  r=self.res.lookup(parse_list('2.19.198.11:80 TCP'),stop=lambda:True);self.assertEqual(self.calls,[]);self.assertTrue(r['cancelled']);self.assertEqual(r['completed'],0)
 def test_stop_does_not_schedule_whole_batch(self):
  stopped=threading.Event();count=0;lock=threading.Lock()
  def query(ip):
   nonlocal count
   with lock:count+=1
   stopped.set();time.sleep(.01);return dict(status='no_ptr',names=[])
  self.res.query=query;entries=[dict(ip='2.0.0.'+str(i),port=80,protocol='TCP') for i in range(1,20)]
  r=self.res.lookup(entries,stop=stopped.is_set);self.assertTrue(r['cancelled']);self.assertLessEqual(count,4);self.assertLess(r['completed'],r['requested'])
 def test_concurrency_is_bounded(self):
  active=0;peak=0;lock=threading.Lock()
  def query(ip):
   nonlocal active,peak
   with lock:active+=1;peak=max(peak,active)
   time.sleep(.01)
   with lock:active-=1
   return dict(status='no_ptr',names=[])
  self.res.query=query;self.res.lookup([dict(ip='2.0.0.'+str(i),port=80,protocol='TCP') for i in range(1,20)]);self.assertLessEqual(peak,4)
 def test_corrupt_cache_ignored(self):
  self.res.path.write_text('not json');other=Resolver(self.res.path,BASE/'app',atomic,query=self.query,clock=lambda:self.now);self.assertEqual(other.rows(),[])
 def test_cache_name_is_sanitized_on_read(self):
  self.res.lookup(parse_list('2.19.198.11:80 TCP'));raw=json.loads(self.res.path.read_text());raw['entries']['2.19.198.11']['names']=['<script>'];atomic(self.res.path,raw)
  other=Resolver(self.res.path,BASE/'app',atomic,query=self.query,clock=lambda:self.now);self.assertEqual(other.rows(),[])
 def test_lookup_limit_is_enforced_before_queries(self):
  entries=[dict(ip='2.0.0.'+str(i),port=80,protocol='TCP') for i in range(1,102)]
  with self.assertRaises(ValueError):self.res.lookup(entries)
  self.assertEqual(self.calls,[])
 def test_readonly_child_timeout_is_bounded(self):
  import subprocess
  with patch('dns_lookup.subprocess.run',side_effect=subprocess.TimeoutExpired('fixture',6)) as run:
   self.assertEqual(query_ptr('2.19.198.11',BASE/'app')['status'],'timeout');self.assertEqual(run.call_args.kwargs['timeout'],6)
 def test_readonly_child_handles_result_and_failure(self):
  import subprocess
  with patch('dns_lookup.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'{"status":"no_ptr","names":[]}')):
   self.assertEqual(query_ptr('2.19.198.11',BASE/'app')['status'],'no_ptr')
  with patch('dns_lookup.subprocess.run',side_effect=OSError('fixture')):self.assertEqual(query_ptr('2.19.198.11',BASE/'app')['status'],'error')

class ManagerNameRangeTests(unittest.TestCase):
 setUp=tm.ManagerTests.setUp
 tearDown=tm.ManagerTests.tearDown
 def test_lookup_does_not_modify_draft_txt_settings_or_firewall(self):
  self.m.resolver.query=lambda ip:dict(status='found',names=['edge.example.com'])
  before=self.m.config_path.read_bytes();txt=self.m.text_path.read_bytes();self.calls.clear();r=self.m.run('lookup',dict(text='2.19.198.11:80 TCP'))
  self.assertEqual(self.calls,[]);self.assertEqual(self.m.config_path.read_bytes(),before);self.assertEqual(self.m.text_path.read_bytes(),txt);self.assertEqual(r['lookup']['entries'][0]['names'],['edge.example.com'])
 def test_load_reads_cache_without_network(self):
  self.m.resolver.query=lambda ip:dict(status='found',names=['edge.example.com']);self.m.run('lookup',dict(text='2.19.198.11:80 TCP'));self.m.resolver.query=lambda ip:(_ for _ in ()).throw(AssertionError('network'))
  r=self.m.run('load');self.assertTrue(r['lookup_cache']);self.assertEqual(self.actual,{})
 def test_invalid_lookup_targets_fail_before_network(self):
  self.m.resolver.query=lambda ip:(_ for _ in ()).throw(AssertionError('network'))
  with self.assertRaises(BlacklistError):self.m.run('lookup',dict(text='127.0.0.1:80 TCP'))
  self.assertEqual(self.calls,[])
 def test_range_preview_has_no_rule_or_list_side_effect(self):
  before=self.m.config_path.read_bytes();txt=self.m.text_path.read_bytes();r=self.m.run('preview_range',dict(mode='pattern',value='2.*.*.*',last='',port=80,protocol='TCP'))
  self.assertEqual(r['range_preview']['address_count'],'16777216');self.assertEqual(self.calls,[]);self.assertEqual(self.m.config_path.read_bytes(),before);self.assertEqual(self.m.text_path.read_bytes(),txt)
 def test_invalid_range_preview_has_friendly_code(self):
  with self.assertRaisesRegex(BlacklistError,'public_without_special'):self.m.run('preview_range',dict(mode='pattern',value='10',last='',port=80,protocol='TCP'))
 def test_preview_can_run_before_first_load_without_creating_owner(self):
  with tempfile.TemporaryDirectory() as t:
   m=Manager(t);m.run('preview_range',dict(mode='pattern',value='2',last='',port=80,protocol='TCP'));self.assertFalse((m.private/'owner-id.json').exists());self.assertFalse(m.text_path.exists())

class IsolatedCliTests(unittest.TestCase):
 def test_isolated_runtime_can_load_new_modules_and_preview(self):
  import shutil,subprocess
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);shutil.copytree(BASE/'app',root/'app',ignore=shutil.ignore_patterns('__pycache__'));private=root/'private-state';private.mkdir();job='e'*32;request=private/('job-'+job+'.request.json')
   atomic(request,dict(action='preview_range',payload=dict(mode='pattern',value='2.*.*.*',last='',port=80,protocol='TCP')))
   r=subprocess.run([sys.executable,'-I',str(root/'app/backend.py'),str(request)],capture_output=True,timeout=10)
   self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));result=json.loads((private/('job-'+job+'.result.json')).read_text());self.assertTrue(result['ok']);self.assertEqual(result['range_preview']['address_count'],'16777216')
 def test_isolated_lookup_skips_networks_without_dns_or_firewall(self):
  import shutil,subprocess
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);shutil.copytree(BASE/'app',root/'app',ignore=shutil.ignore_patterns('__pycache__'));private=root/'private-state';private.mkdir();job='f'*32;request=private/('job-'+job+'.request.json')
   atomic(private/'owner-id.json',dict(owner='a'*32));atomic(request,dict(action='lookup',payload=dict(text='2.0.0.0/8:80 TCP')))
   r=subprocess.run([sys.executable,'-I',str(root/'app/backend.py'),str(request)],capture_output=True,timeout=10)
   self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));result=json.loads((private/('job-'+job+'.result.json')).read_text());self.assertTrue(result['ok']);self.assertEqual(result['lookup']['skipped_ranges'],['2.0.0.0/8']);self.assertFalse((private/'blacklist.txt').exists())

@unittest.skipUnless(tp.PS,'PowerShell runtime required')
class PtrPowerShellTests(unittest.TestCase):
 env=tp.RealPowerShell.env
 runps=tp.RealPowerShell.runps
 def test_real_ptr_script_with_mocked_dns_results(self):
  code="function Resolve-DnsName {param($Name,$Type,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout,$ErrorAction);[pscustomobject]@{Type='PTR';NameHost='edge.example.com.'}};$env:WOW_PTR_IP='2.19.198.11';& ([scriptblock]::Create([IO.File]::ReadAllText('"+tp.quoted(BASE/'app/resolve.ps1')+"')))"
  r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));raw=json.loads(r.stdout.decode('utf-8-sig'));self.assertEqual(raw['status'],'found');self.assertEqual(raw['names'],['edge.example.com.'])
 def test_real_ptr_no_records_and_error_differ(self):
  for body,status in [("@()",'no_ptr'),("throw 'fixture DNS failure'",'error')]:
   code="function Resolve-DnsName {param($Name,$Type,[switch]$DnsOnly,[switch]$NoHostsFile,[switch]$QuickTimeout,$ErrorAction);"+body+"};$env:WOW_PTR_IP='2.19.198.11';& ([scriptblock]::Create([IO.File]::ReadAllText('"+tp.quoted(BASE/'app/resolve.ps1')+"')))"
   r=self.runps(code);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual(json.loads(r.stdout.decode('utf-8-sig'))['status'],status)

class PtrUiContractTests(unittest.TestCase):
 def test_lookup_preserves_editor_and_has_cancel_progress(self):
  s=(BASE/'app/ui.ps1').read_text();branch=s[s.index("if($j.Action -eq 'lookup'){"):s.index('if($r.lookup_cache)')]
  self.assertIn('ReadNames',branch);self.assertNotIn('ShowRows',branch);self.assertIn('progress.done',s);self.assertIn("@('observe','lookup')",s)
 def test_both_tables_have_name_and_status_columns(self):
  s=(BASE/'app/ui.ps1').read_text()
  for grid in ('$black','$found'):
   self.assertIn('Column '+grid+" 'hostname'",s);self.assertIn('Column '+grid+" 'ptrstate'",s)
 def test_range_add_requires_fresh_preview(self):
  s=(BASE/'app/ui-range.ps1').read_text();self.assertIn('$script:rw.preview=$null',s);self.assertIn('$script:rw.add.Enabled=$false',s);self.assertIn('Invalidate-RangePreview',s);self.assertIn("action='preview_range'",s);self.assertNotIn("action='apply'",s)
 def test_table_validates_before_clearing_old_rows(self):
  s=(BASE/'app/ui.ps1').read_text();part=s[s.index('function ShowRows'):s.index('function DetailText')]
  self.assertLess(part.index('$parsed=@(Ui-Parse'),part.index('$black.Rows.Clear()'))
 def test_resolver_has_no_firewall_or_web_actions(self):
  s=(BASE/'app/resolve.ps1').read_text()
  for forbidden in ('NetFirewall','Invoke-WebRequest','Invoke-RestMethod','Set-DnsClient','Clear-DnsClient'):self.assertNotIn(forbidden,s)
  self.assertIn('-DnsOnly -NoHostsFile -QuickTimeout',s)

if __name__=='__main__':unittest.main()
