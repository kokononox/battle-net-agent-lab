import unittest,copy
import guard_report as g

def rec(mode='fixture_timeout'):
 fixture=mode!='observe'
 return dict(schema='bnet-retail-supervisor-1',source_commit='a'*40,run_id='1',mode=mode,status='worker_completed' if not fixture else {'fixture_timeout':'time_limit','fixture_network':'network_limit','fixture_disk':'disk_limit'}[mode],root_exit_code=0 if not fixture else 125,network_scope='synthetic_fixture'if fixture else 'hostwide_adapter_counters',job_kill_on_close_configured=True,child_assigned_before_resume=True,child_resumed=True,termination_requested=True,job_drained=True,metrics_available=True,hard_network_byte_cap=False,game_transfer_requested=False,max_active_processes=2,final_active_processes=0,win32_error=0,elapsed_ms=3500 if fixture else 150000,time_limit_ms=3000 if fixture else 240000,network_threshold_bytes=2 if mode=='fixture_network'else 1073741824,network_delta_bytes=3 if mode=='fixture_network'else 0,minimum_free_bytes=0 if mode=='fixture_disk'else 20000000000,disk_reserve_bytes=10737418240,poll_interval_ms=250)
class Receipts(unittest.TestCase):
 def test_modes(self):
  for mode in g.MODES:g.receipt(rec(mode))
 def test_three_fixture_stops(self):
  for mode in g.MODES-{'observe'}:self.assertTrue(g.fixture_passed(rec(mode)))
 def test_need_two_processes(self):
  r=rec();r['max_active_processes']=1;self.assertFalse(g.fixture_passed(r))
 def test_need_job_drain(self):
  r=rec();r['job_drained']=False;self.assertFalse(g.fixture_passed(r))
 def test_fixed_flags(self):
  for k in ('hard_network_byte_cap','game_transfer_requested'):
   r=rec();r[k]=True;self.assertRaises(ValueError,g.receipt,r)
 def test_resume_before_assignment_refused(self):
  r=rec();r['child_assigned_before_resume']=False;self.assertRaises(ValueError,g.receipt,r)
 def test_nonempty_job_refused(self):
  r=rec();r['final_active_processes']=1;self.assertRaises(ValueError,g.receipt,r)
 def test_no_unknown_fields(self):
  r=rec();r['private_pid']=123;self.assertRaises(ValueError,g.receipt,r)
 def test_no_boolean_bytes(self):
  r=rec();r['network_delta_bytes']=True;self.assertRaises(ValueError,g.receipt,r)
 def test_gate_blank(self):g.validate(g.blank('a'*40,'1'))
 def test_gate_complete(self):
  r=g.blank('a'*40,'1');r.update(status='completed',fixtures={m:rec(m)for m in g.MODES-{'observe'}},observation=rec('observe'));g.validate(r)
 def test_gate_before_fixtures_refused(self):
  r=g.blank('a'*40,'1');r['observation']=rec('observe');self.assertRaises(ValueError,g.validate,r)
 def test_source_bound(self):
  r=g.blank('a'*40,'1');r['fixtures']['fixture_timeout']=rec();r['fixtures']['fixture_timeout']['run_id']='2';self.assertRaises(ValueError,g.validate,r)
 def test_not_a_hard_byte_limit(self):
  r=rec('observe');self.assertFalse(r['hard_network_byte_cap']);self.assertEqual(r['network_scope'],'hostwide_adapter_counters')
if __name__=='__main__':unittest.main()
