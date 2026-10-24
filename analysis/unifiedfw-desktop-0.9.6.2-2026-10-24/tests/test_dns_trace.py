import copy,pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'app'),str(ROOT/'tests')]
import monitor_evidence as me,live_ops as lo
from test_monitor_evidence import dns
from test_restored import capture
from policy import PolicyError
class DnsTraceTests(unittest.TestCase):
 def setUp(self):self.c=capture();self.e=dns(self.c,source='DNSClient_ETW',dns_event_id=3006,process_start_ticks=str(me.utc_ticks(me.instant('2026-10-24T11:59:59Z'))),dns_status='pending')
 def norm(self):return me.normalize(dict(events=[self.e]),self.c['programs'])
 def test_live_query_source_preserved(self):
  e=self.norm()['events'][0];self.assertEqual(e['source'],'DNSClient_ETW');self.assertEqual(e['dns_phase'],'query_called');self.assertEqual(e['attribution'],'live_exact_path_PID_and_process_birth_at_event');self.assertFalse(e['HTTP_request_verified'])
 def test_live_completion_source_and_results(self):
  self.e['dns_event_id']=3008;e=self.norm()['events'][0];self.assertEqual(e['dns_phase'],'query_completed');self.assertEqual(e['result_ips'][0],'8.8.8.8')
 def test_unknown_dns_source_rejected(self):
  self.e['source']='PTR';self.assertFalse(self.norm()['events'])
 def test_wrong_live_event_id_rejected(self):
  self.e['dns_event_id']=3010;self.assertFalse(self.norm()['events'])
 def test_live_process_birth_required(self):
  self.e.pop('process_start_ticks');self.assertFalse(self.norm()['events'])
 def test_live_process_birth_after_event_rejected(self):
  self.e['process_start_ticks']=str(me.utc_ticks(me.instant(self.e['observed_utc']))+10);self.assertFalse(self.norm()['events'])
 def test_live_process_birth_round_trip_exact(self):
  self.e['process_start_ticks']=str(me.utc_ticks(me.instant(self.e['observed_utc'])));self.assertEqual(self.norm()['events'][0]['process_start_ticks'],self.e['process_start_ticks'])
 def test_trace_status_and_error_exposed(self):
  d=me.normalize(dict(dns_trace=dict(status='start_failed',error_code='Administrator_required_for_DNS_ETW',selected_events=0)),self.c['programs']);self.assertEqual(d['dns_trace']['status'],'start_failed');self.assertIn('Administrator',d['dns_trace']['error_code']);self.assertFalse(d['dns_trace']['coverage_verified'])
 def test_trace_counters_validated(self):
  d=me.normalize(dict(dns_trace=dict(status='running_realtime_coverage_unverified',seen=-1,selected_events=True,queue_dropped=10,cleanup_required=True)),self.c['programs'])['dns_trace'];self.assertIsNone(d['seen']);self.assertIsNone(d['selected_events']);self.assertEqual(d['queue_dropped'],10);self.assertTrue(d['cleanup_required'])
 def test_no_trace_is_not_claimed_running(self):self.assertEqual(me.normalize({},self.c['programs'])['dns_trace']['status'],'not_requested')
 def test_legacy_sysmon_still_supported(self):
  self.e.pop('source');self.assertEqual(self.norm()['events'][0]['source'],'Sysmon_22')
 def test_live_cap_not_corrupted_by_source_label(self):
  d=me.normalize(dict(events=[dict(self.e,record_id=f'{i:032x}') for i in range(1001)]),self.c['programs']);self.assertEqual(len(d['events']),1000);self.assertTrue(d['truncated'])
 def test_cleanup_requires_consent(self):
  with self.assertRaisesRegex(PolicyError,'consent'):lo.dns_cleanup(None,{},None)
 def test_no_global_logging_or_dns_change_commands(self):
  s=(ROOT/'app/live-dns.ps1').read_text('utf-8-sig')+(ROOT/'app/dns-trace.cs').read_text()
  for bad in ('wevtutil','auditpol','ipconfig','FlushResolverCache','Set-DnsClient','Set-NetFirewall','UCreateNative'):self.assertNotIn(bad,s)
 def test_cleanup_is_name_guid_and_liveness_scoped(self):
  s=(ROOT/'app/dns-cleanup.ps1').read_text('utf-8-sig');self.assertIn('collector_birth_ticks',s);self.assertIn('active_or_unreadable_collector_skipped',s);self.assertIn('session_guid',s)
  s=(ROOT/'app/dns-trace.cs').read_text();self.assertIn('DNS_cleanup_GUID_mismatch',s);self.assertIn('^UnifiedFW-DNS-',s);self.assertNotIn('logman',s)
 def test_etw_stop_in_finally_before_capture_written(self):
  s=(ROOT/'app/live.ps1').read_text('utf-8-sig');self.assertIn('}finally{Stop-DnsTrace}',s);self.assertLess(s.index('}finally{Stop-DnsTrace}'),s.index("$final=Frame 'finished'"))
 def test_start_is_explicit_and_why_empty_is_visible(self):
  s=(ROOT/'app/ui.ps1').read_text('utf-8-sig');self.assertIn('dns_etw_consent=[bool]$dnsTrace.Checked',s);self.assertIn('DNS زنده:',s);self.assertIn('$d.error_code',s)
if __name__=='__main__':unittest.main()
