import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from core import ENDPOINTS,REVIEW_ENDPOINTS,Session,validate
from group import GROUP_ENDPOINTS
class ReviewTests(unittest.TestCase):
 def test_six_new_unique_targets(self):
  self.assertEqual(len(REVIEW_ENDPOINTS),6);self.assertEqual(len({(e['ip'],e['port'],e['protocol']) for e in REVIEW_ENDPOINTS}),6)
 def test_exclusions_and_group_separation(self):
  self.assertFalse(any(e['ip'] in {'2.19.198.11','2.21.23.82','37.244.29.11'} for e in REVIEW_ENDPOINTS));self.assertTrue(all(e not in GROUP_ENDPOINTS for e in REVIEW_ENDPOINTS));self.assertTrue(all(e['protocol']=='TCP' for e in REVIEW_ENDPOINTS))
 def test_legacy_catalogue_order_preserved(self):
  self.assertEqual(ENDPOINTS[0]['ip'],'3.124.215.108');self.assertEqual(ENDPOINTS[3]['ip'],'37.244.29.11');self.assertEqual(ENDPOINTS[26]['ip'],'137.221.88.99');self.assertEqual(ENDPOINTS[27:],REVIEW_ENDPOINTS)
 def test_each_new_target_start_restore_report(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');present=set()
   def fw(action,p):
    j=validate(json.loads(p.read_text()))
    if action=='add':present.add((j['ip'],j['port']))
    if action=='remove':present.discard((j['ip'],j['port']))
    return {'ok':True}
   s=Session(exe,root,fw,lambda p:None)
   for e in REVIEW_ENDPOINTS:
    with self.subTest(endpoint=e):
     s.start(ENDPOINTS.index(e),True);self.assertEqual(present,{(e['ip'],e['port'])});s.observe('world_ok',True);self.assertFalse(present);self.assertEqual(s.records[-1]['endpoint'],e);s.baseline('yes')
 def test_new_target_journal_recoverable_on_restart(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);exe=root/'Wow.exe';exe.write_bytes(b'fixture');calls=[]
   fw=lambda action,p:calls.append((action,validate(json.loads(p.read_text()))['ip']))
   s=Session(exe,root,fw,lambda p:None);s.start(ENDPOINTS.index(REVIEW_ENDPOINTS[0]),True);Session(exe,root,fw).recover();self.assertIn(('remove',REVIEW_ENDPOINTS[0]['ip']),calls)
 def test_ui_whitelists_review_and_api_exposes_review(self):
  r=Path(__file__).resolve().parents[1]/'app';s=(r/'ui.html').read_text();self.assertIn('state.review_endpoints||[]',s);self.assertIn("'review_endpoints':REVIEW_ENDPOINTS",(r/'main.py').read_text())
if __name__=='__main__':unittest.main()
