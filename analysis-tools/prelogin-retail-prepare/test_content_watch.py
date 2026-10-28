import unittest,tempfile,time,os,hashlib,copy
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import patch
import content_probe as c,failure_receipt as f
class Watch(unittest.TestCase):
 def setUp(self):
  self.data=b'synthetic known component';self.ref=c.reference();self.ref['components']={k:[dict(ckey=hashlib.md5(self.data).hexdigest(),size=len(self.data))]for k in c.PATHS}
 def context(self):
  s=ExitStack();s.enter_context(patch.dict(os.environ,{'RETAIL_CONTENT_PROBE':'official-install-t9','RETAIL_BUDGET_PROFILE':'approved-2g-512m-t9','RETAIL_CONTENT_WATCH':'concurrent-fixed-t10'}));s.enter_context(patch.object(c,'reference',return_value=self.ref));s.enter_context(patch.object(c,'save',side_effect=c.validate));return s
 def probe(self,t):return c.Probe(Path(t),{k:self.ref[k]for k in ('version','build_config')},'a'*40,'1')
 def until(self,condition):
  deadline=time.monotonic()+2
  while time.monotonic()<deadline:
   if condition():return
   time.sleep(.01)
  self.fail('bounded watcher did not reach expected synthetic state')
 def test_observes_without_any_main_thread_scan(self):
  with tempfile.TemporaryDirectory()as t,self.context():
   p=self.probe(t);p.start_watch()
   try:
    target=Path(t)/'_retail_/Utils/WowVoiceProxy.exe';target.parent.mkdir(parents=True);target.write_bytes(self.data)
    self.until(lambda:p.r['game_component_materialized'])
   finally:p.stop_watch()
   self.assertTrue(p.r['game_component_materialized']);self.assertLessEqual(p.r['scans'],64);self.assertFalse(p.r['network_delivery_of_same_file_proven']);c.validate(p.r)
 def test_path_security_failure_stops_watch(self):
  with tempfile.TemporaryDirectory()as t,self.context():
   p=self.probe(t);other=Path(t)/'other';other.mkdir();(Path(t)/'Utils').symlink_to(other,target_is_directory=True);p.start_watch()
   try:self.until(lambda:p.watch_failed)
   finally:p.stop_watch()
   self.assertEqual(p.r['watcher']['status'],'refused')
   with self.assertRaises(ValueError):p.scan()
 def test_shares_original_scan_budget(self):
  with tempfile.TemporaryDirectory()as t,self.context():
   p=self.probe(t);p.r['scans']=63;p.start_watch()
   try:self.until(lambda:p.r['watcher']['status']=='bounded_complete')
   finally:p.stop_watch()
   self.assertEqual(p.r['scans'],64);self.assertEqual(p.r['watcher']['iterations'],1)
 def test_stop_has_no_surviving_thread(self):
  with tempfile.TemporaryDirectory()as t,self.context():
   p=self.probe(t);p.start_watch();p.stop_watch();self.assertFalse(p.watch_thread.is_alive())
   scans=p.r['scans'];time.sleep(.1);self.assertEqual(p.r['scans'],scans)
 def test_unknown_watch_scope_refused(self):
  with tempfile.TemporaryDirectory()as t,self.context():
   p=self.probe(t)
   with patch.dict(os.environ,{'RETAIL_CONTENT_WATCH':'other'}):
    with self.assertRaises(ValueError):p.start_watch()
 def test_watcher_cannot_change_limit(self):
  r=c.blank('a'*40,'1');r['watcher']=dict(status='observing',iterations=0,interval_ms=50,time_limit_ms=4001,activation='before_owned_update_http')
  with self.assertRaises(ValueError):c.validate(r)
class Legacy(unittest.TestCase):
 def test_old_content_receipts_remain_readable(self):
  r=c.blank('a'*40,'1');r['schema']='bnet-retail-content-probe-1';r['components']={k:v for k,v in r['components'].items()if k in c.LEGACY_COMPONENTS};c.validate(r)
  r['hashed_bytes']=16777217
  with self.assertRaises(ValueError):c.validate(r)
class Failures(unittest.TestCase):
 def test_unknown_exception_values_never_export(self):
  r=f.make('a'*40,'1','snapshot',ValueError('PRIVATE_TOKEN_OR_PATH'));self.assertEqual(r['reason'],'other');self.assertNotIn('PRIVATE',str(r))
 def test_known_code(self):
  r=f.make('a'*40,'1','snapshot',ValueError('tree_limit'));self.assertEqual(r['reason'],'tree_limit');f.validate(r)
 def test_no_extra_diagnostic_fields(self):
  r=f.make('a'*40,'1','identity',ValueError('other'));r['raw']='x'
  with self.assertRaises(ValueError):f.validate(r)
if __name__=='__main__':unittest.main()
