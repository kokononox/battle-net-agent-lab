import copy,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prearm_quiet as q
from test_meter import good
class Quiet(unittest.TestCase):
 def run_case(self,samples,success):
  old=os.getcwd()
  with tempfile.TemporaryDirectory()as d:
   os.chdir(d);Path('output').mkdir()
   try:
    with patch.object(q.meter_receipt,'read',side_effect=samples),patch.object(q.time,'monotonic',return_value=0),patch.object(q.time,'sleep'):
     if success:q.wait('a'*40,'1')
     else:
      with self.assertRaises(ValueError):q.wait('a'*40,'1')
    r=json.loads(Path('output/prearm-quiet.json').read_text());q.validate(r)
   finally:os.chdir(old)
  return r
 def samples(self,n=12,step=1000,changes=False,stale=False):
  out=[]
  for i in range(n):
   r=good();r['polls']=1 if stale else i*9+1;r['elapsed_ms']=0 if stale else i*250;r['data_bytes_in_delta']=i*step;r['connection_set_changes']=i if changes else 0;out.append(r)
  return out
 def test_three_fresh_low_intervals_required(self):
  r=self.run_case(self.samples(4),True);self.assertEqual(r['reads'],4);self.assertEqual(r['quiet_intervals'],3)
 def test_busy_never_resets_or_raises_global_budget(self):
  r=self.run_case(self.samples(step=2*1048576),False);self.assertEqual(r['status'],'timeout');self.assertFalse(r['global_limits_changed']);self.assertFalse(r['phase_request_sent'])
 def test_turnover_and_stale_data_are_not_quiet(self):
  for rows in (self.samples(changes=True),self.samples(stale=True)):
   self.assertEqual(self.run_case(rows,False)['quiet_intervals'],0)
 def test_mixed_run_refused(self):
  rows=self.samples(1);rows[0]['run_id']='2';self.assertEqual(self.run_case(rows,False)['status'],'meter_refused')
if __name__=='__main__':unittest.main()
