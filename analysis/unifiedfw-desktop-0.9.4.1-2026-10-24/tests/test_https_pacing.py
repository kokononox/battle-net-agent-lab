from pathlib import Path
import copy,math,sys,unittest
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'lab'),str(ROOT/'app'),str(ROOT/'tests')]
from coexistence import classify_coexistence
from test_https import https_report

def report():
 r=https_report();r['https_pacing']={'minimum_gap_ms':4000,'automatic_retries':0,'tcp_connect_timeout_seconds':3,'applies_across_matrix_and_restore_boundaries':True}
 i=0
 for ph in r['phases']:
  for stage in ('during','after_restore'):
   for row in ph[stage]:row.update(pacing_sequence=i,gap_since_previous_probe_ms=None if i==0 else 4000.1);i+=1
 return r
class HTTPSPacingClassification(unittest.TestCase):
 def test_correct_pacing_can_pass_without_broadening_scope(self):
  r=classify_coexistence(report());self.assertEqual(r['outcome'],'passed');self.assertFalse(r['global_whitelist_tested']);self.assertFalse(r['vpn_route_verified'])
 def test_legacy_reports_remain_classifiable_without_claiming_pacing(self):self.assertEqual(classify_coexistence(https_report())['outcome'],'passed')
 def test_short_gap_rejected_even_with_good_connectivity(self):
  r=report();r['phases'][1]['during'][0]['gap_since_previous_probe_ms']=3999.99;self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
 def test_bad_sequence_or_boolean_rejected(self):
  for value in (0,True,None):
   r=report();r['phases'][1]['during'][0]['pacing_sequence']=value;self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
 def test_bad_gap_types_and_nan_rejected(self):
  for value in (True,None,'4000',float('nan'),float('inf'),-1):
   r=report();r['phases'][1]['during'][0]['gap_since_previous_probe_ms']=value;self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
 def test_pacing_does_not_hide_reference_failure(self):
  r=report();row=next(x for x in r['phases'][3]['during'] if x['role']=='REF');row.update(connected=False,handshake_ok=False);self.assertNotEqual(classify_coexistence(r)['outcome'],'passed')
 def test_pacing_does_not_hide_restore_failure(self):
  r=report();r['restore_verified']=False;self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
 def test_declaration_cannot_enable_retry_or_raise_timeout(self):
  for key,value in [('automatic_retries',1),('tcp_connect_timeout_seconds',4),('minimum_gap_ms',0)]:
   r=report();r['https_pacing'][key]=value;self.assertEqual(classify_coexistence(r)['outcome'],'inconclusive')
if __name__=='__main__':unittest.main()
