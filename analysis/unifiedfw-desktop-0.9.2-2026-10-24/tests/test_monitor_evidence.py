import copy,datetime,json,pathlib,sys,types,unittest,tempfile,zipfile
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'app'),str(ROOT/'tests')]
import live_ops as lo,monitor_evidence as me,dns_lookup as dl
from test_restored import capture
from state import Store,atomic_json
from policy import PolicyError,program_id

def dns(c,**kw):
 p=c['programs'][0]
 e=dict(record_id='d'*32,program_id=p['id'],program_path=p['path'],pid=99,event_record_id=44,observed_utc='2026-10-24T12:00:00Z',kind='dns_query',domain='query.example',query_results='type: 5 alias.example;8.8.8.8;2606:4700:4700::1111;',dns_status='0',hosts_mapping='not_listed',hosts_addresses=[])
 e.update(kw);return e

def inventory(c,**kw):
 p=c['programs'][0];d=dict(schema='unified-monitor-inventory-1',available=True,complete=True,checked_utc='2026-10-24T12:00:00Z',rules=[dict(program_id=p['id'],program=p['path'],protocol='TCP',port=443,remote_addresses=['8.8.8.0/24'],name='fixture')],reason='fixture')
 d.update(kw);return d
class EvidenceTests(unittest.TestCase):
 def setUp(self):self.c=capture();self.p=self.c['programs'][0]
 def normalized(self,e):return me.normalize(dict(events=[e]),self.c['programs'])
 def test_dns_is_not_http_or_ptr(self):
  e=self.normalized(dns(self.c))['events'][0];self.assertEqual(e['source'],'Sysmon_22');self.assertFalse(e['HTTP_request_verified']);self.assertFalse(e['rule_owner_verified']);self.assertFalse(e['packet_drop_verified']);self.assertEqual(e['result_ips'],['8.8.8.8','2606:4700:4700::1111'])
 def test_dns_exact_path_not_same_basename(self):
  d=self.normalized(dns(self.c,program_path=r'C:\Other\Game.exe'));self.assertFalse(d['events']);self.assertTrue(d['truncated'])
 def test_dns_wrong_pid_or_id_rejected(self):
  for field,value in [('pid',True),('pid',0),('program_id','e'*24),('record_id','bad')]:
   with self.subTest(field=field):self.assertFalse(self.normalized(dns(self.c,**{field:value}))['events'])
 def test_dns_invalid_names(self):
  for value in ('https://a.example','a.example/path','a example','<script>', 'a'*254):
   with self.subTest(value=value):self.assertFalse(self.normalized(dns(self.c,domain=value))['events'])
 def test_dns_no_future_or_naive_timestamp(self):
  self.assertFalse(self.normalized(dns(self.c,observed_utc='2026-10-24T12:00:00'))['events'])
  self.assertFalse(self.normalized(dns(self.c,observed_utc='not time'))['events'])
 def test_dns_evidence_bounded(self):
  d=me.normalize(dict(events=[dns(self.c,record_id=f'{i:032x}') for i in range(1001)]),self.c['programs']);self.assertEqual(len(d['events']),1000);self.assertTrue(d['truncated'])
 def test_dns_duplicate_id_not_duplicate_request(self):
  d=me.normalize(dict(events=[dns(self.c),dns(self.c)]),self.c['programs']);self.assertEqual(len(d['events']),1);self.assertTrue(d['truncated'])
 def test_hosts_mapping_not_block_certification(self):
  e=self.normalized(dns(self.c,hosts_mapping='local_sink_mapping',hosts_addresses=['0.0.0.0','::']))['events'][0];self.assertFalse(e['hosts_block_verified']);self.assertEqual(e['hosts_addresses'],['0.0.0.0','::'])
 def test_unavailable_logs_never_empty_coverage_claim(self):
  e=me.normalize({},self.c['programs']);self.assertEqual(e['streams']['dns']['status'],'not_collected');self.assertFalse(e['streams']['dns']['coverage_verified'])
 def test_log_error_status_preserved(self):
  d=me.normalize(dict(streams=dict(dns=dict(status='read_failed'))),self.c['programs']);self.assertEqual(d['streams']['dns']['status'],'read_failed')
 def test_wfp_actual_event_not_owned_drop(self):
  e=dns(self.c,kind='wfp_connection_block',ip='8.8.8.8',port=443,protocol='TCP',direction='outbound',filter_id='122');out=self.normalized(e)['events'][0];self.assertTrue(out['connection_denial_event']);self.assertFalse(out['rule_owner_verified']);self.assertFalse(out['packet_drop_verified']);self.assertEqual(out['source'],'Security_5157')
 def test_wfp_inbound_or_invalid_protocol_rejected(self):
  for field,value in [('direction','inbound'),('protocol','ICMP'),('port',0),('ip','bad')]:
   e=dns(self.c,kind='wfp_connection_block',ip='8.8.8.8',port=443,protocol='TCP',direction='outbound');e[field]=value;self.assertFalse(self.normalized(e)['events'])
 def test_result_IP_parser_no_CNAME_guess(self):
  self.assertEqual(me.result_ips('type: 5 cdn.example;8.8.8.8;8.8.8.8;http://1.1.1.1'),['8.8.8.8'])
 def test_rule_correct_scope(self):
  snapshot=me.inventory(inventory(self.c),self.c['programs']);row=self.c['endpoints'][0];self.assertEqual(me.rule_state(row,snapshot),'verified_owned_block_snapshot')
  for field,value in [('remote_ip','1.1.1.1'),('remote_port',80),('protocol','UDP'),('program_id','1'*24)]:
   r=dict(row,**{field:value});self.assertEqual(me.rule_state(r,snapshot),'no_matching_owned_block_snapshot')
 def test_unknown_inventory_not_allowed(self):
  for inv in (None,{},dict(available=False,complete=False,checked_utc='2026-10-24T12:00:00Z')):
   normalized=me.inventory(inv,self.c['programs']);self.assertEqual(me.rule_state(self.c['endpoints'][0],normalized),'unknown')
 def test_partial_inventory_only_positive_match(self):
  inv=me.inventory(inventory(self.c,complete=False),self.c['programs']);row=self.c['endpoints'][0];self.assertEqual(me.rule_state(row,inv),'verified_owned_block_snapshot');self.assertEqual(me.rule_state(dict(row,remote_ip='1.1.1.1'),inv),'unknown')
 def test_invalid_inventory_path_disables_classification(self):
  inv=inventory(self.c);inv['rules'][0]['program']=r'C:\Other\Game.exe';out=me.inventory(inv,self.c['programs']);self.assertFalse(out['available'])
 def test_inventory_does_not_accept_bad_CIDR(self):
  inv=inventory(self.c);inv['rules'][0]['remote_addresses']=['8.8.8.1/24'];self.assertFalse(me.inventory(inv,self.c['programs'])['available'])
 def test_ipv6_rule_coverage(self):
  inv=inventory(self.c);inv['rules'][0]['remote_addresses']=['2606:4700::/32'];row=dict(self.c['endpoints'][0],remote_ip='2606:4700:4700::1111');self.assertEqual(me.rule_state(row,me.inventory(inv,self.c['programs'])),'verified_owned_block_snapshot')
 def test_dns_IP_link_same_process_path_and_before_last_sample(self):
  self.c['event_evidence']=dict(events=[dns(self.c)]);out=lo.validate(self.c);self.assertEqual(out['endpoints'][0]['dns_names'],['query.example']);self.assertEqual(out['endpoints'][0]['rule_state'],'unknown')
 def test_dns_IP_link_different_PID_not_correlated(self):
  self.c['event_evidence']=dict(events=[dns(self.c,pid=100)]);self.assertFalse(lo.validate(self.c)['endpoints'][0]['dns_names'])
 def test_dns_IP_link_future_query_not_correlated(self):
  self.c['event_evidence']=dict(events=[dns(self.c,observed_utc='2026-10-24T12:01:00Z')]);self.assertFalse(lo.validate(self.c)['endpoints'][0]['dns_names'])
 def test_dns_IP_link_before_process_birth_not_correlated(self):
  at=datetime.datetime(2026,10,24,12,1,tzinfo=datetime.timezone.utc);delta=at-datetime.datetime(1,1,1,tzinfo=datetime.timezone.utc);self.c['endpoints'][0]['process_start_ticks']=str((delta.days*86400+delta.seconds)*10000000);self.c['event_evidence']=dict(events=[dns(self.c)]);self.assertFalse(lo.validate(self.c)['endpoints'][0]['dns_names'])
 def test_forged_DNS_names_removed(self):
  self.c['endpoints'][0]['dns_names']=['made.up'];self.assertFalse(lo.validate(self.c)['endpoints'][0]['dns_names'])
 def test_old_archive_compatibility(self):
  out=lo.validate(self.c);self.assertFalse(out['event_evidence']['events']);self.assertFalse(out['block_inventory']['available']);self.assertEqual(out['endpoints'][0]['rule_state'],'unknown')
 def test_export_strips_new_event_and_rule_paths(self):
  with tempfile.TemporaryDirectory() as temp:
   store=Store(pathlib.Path(temp)/'private');job=pathlib.Path(temp)/'job';job.mkdir();self.c['event_evidence']=dict(events=[dns(self.c)]);self.c['block_inventory']=inventory(self.c);lo.Archive(store.root).save(self.c)
   r=lo.export_capture(store,dict(capture_id=self.c['capture_id']),job)
   with zipfile.ZipFile(r['export_file']) as z:
    raw=z.read('capture.json').decode();out=json.loads(raw);self.assertNotIn('program_path',out['event_evidence']['events'][0]);self.assertNotIn('program',out['block_inventory']['rules'][0]);self.assertNotIn('C:\\\\Apps',raw);self.assertIn('query.example',raw)
 def test_ptr_explicit_bounded_input(self):
  with tempfile.TemporaryDirectory() as temp:
   store=Store(pathlib.Path(temp)/'private');job=pathlib.Path(temp)/'job';job.mkdir()
   for q in ({},dict(ips=['a.example']),dict(ips=['8.8.8.8']*101),dict(ips=['8.8.8.8'],force='yes')):
    with self.subTest(q=q),patch.object(dl,'query_ptr') as fn,self.assertRaises(ValueError):lo.ptr_lookup(store,q,job)
    fn.assert_not_called()
 def test_ptr_lookup_cache_cancel_and_private_IP_skip(self):
  with tempfile.TemporaryDirectory() as temp:
   store=Store(pathlib.Path(temp)/'private');job=pathlib.Path(temp)/'job';job.mkdir()
   with patch.object(dl,'query_ptr',return_value=dict(status='found',names=['ptr.example'])) as fn:
    r=lo.ptr_lookup(store,dict(ips=['8.8.8.8','127.0.0.1','10.0.0.1']),job);self.assertEqual(fn.call_count,1);self.assertEqual(len(r['ptr']['skipped_non_public_ips']),2);self.assertFalse(r['actual_connection_hostname_verified'])
    r=lo.ptr_lookup(store,dict(ips=['8.8.8.8']),job);self.assertEqual(fn.call_count,1);self.assertTrue(r['ptr']['entries'][0]['cached'])
    r=lo.ptr_lookup(store,dict(ips=['8.8.8.8'],force=True),job);self.assertEqual(fn.call_count,2)
    (job/'stop.txt').write_text('stop');r=lo.ptr_lookup(store,dict(ips=['1.1.1.1']),job);self.assertTrue(r['ptr']['cancelled']);self.assertEqual(r['ptr']['completed'],0);self.assertEqual(fn.call_count,2)
 def test_ptr_nonpublic_only_no_query(self):
  with tempfile.TemporaryDirectory() as temp:
   store=Store(pathlib.Path(temp)/'private');job=pathlib.Path(temp)/'job';job.mkdir()
   with patch.object(dl,'query_ptr') as fn:r=lo.ptr_lookup(store,dict(ips=['127.0.0.1','224.0.0.1']),job)
   fn.assert_not_called();self.assertEqual(r['ptr']['completed'],0)
 def test_ui_has_two_sections_and_pulse_cell_not_whole_row_flash(self):
  s=(ROOT/'app/ui-evidence.ps1').read_text('utf-8-sig');self.assertIn("دامنه / رویدادهای DNS",s);self.assertIn('IP / نمونهٔ TCP',s);self.assertIn("Cells['pulse'].Style.BackColor",s);self.assertIn('State-Color',s);self.assertIn('rule_state',s);self.assertIn('Ptr-Text',s);self.assertIn('Update-Ptr',s)
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig');self.assertIn('Update-Ptr',s);self.assertNotIn('row.DefaultCellStyle.BackColor=[Drawing.Color]::Empty',s)
 def test_existing_logs_reader_does_not_enable_logging(self):
  text=(ROOT/'app/live-events.ps1').read_text('utf-8-sig')
  for bad in ('wevtutil','auditpol','Set-WinEvent','Sysmon.exe','New-Service'):self.assertNotIn(bad,text)
  for good in ('event_programs','candidate.path','candidate.device_path','ProviderName','NoMatchingEventsFound','coverage_verified=$false'):self.assertIn(good,text)
 def test_readonly_inventory_isolated_from_sampling(self):
  collector=(ROOT/'app/live.ps1').read_text('utf-8-sig');self.assertNotIn('Get-MonitorInventory',collector);self.assertNotIn('UReadNative',collector)
  reader=(ROOT/'app/inventory-read.ps1').read_text('utf-8-sig')
  for bad in ('NewUSession ','InvokeUSession ','RestoreUSession ','UCreateNative ','UEnableNative ','URemoveNative ','USave ','OpenOrCreate'):self.assertNotIn(bad,reader)
if __name__=='__main__':unittest.main()
