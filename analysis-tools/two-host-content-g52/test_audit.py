import copy, json, unittest
from pathlib import Path
from audit import audit
class Tests(unittest.TestCase):
 def setUp(self):self.d=json.loads(Path('reports/level3-audit-t11-user.json').read_text(encoding='utf-8'))
 def test_headline(self):
  r=audit(self.d,'test');self.assertEqual(r['hosts']['level3.blizzard.com']['captured_request_rows'],26)
  self.assertEqual(r['hosts']['level3.blizzard.com']['methods'],{'GET':26})
 def test_empty_is_unknown(self):
  r=audit(self.d,'test')['hosts']['us.version.battle.net'];self.assertEqual(r['captured_request_rows'],0)
  self.assertIsNone(r['all_observed_bodies_complete']);self.assertTrue(r['disposition'].startswith('unknown_'))
 def test_no_false_clearance(self):
  r=audit(self.d,'test');self.assertFalse(r['fingerprinting_absence_proven'])
  self.assertFalse(r['coverage']['these_443_assigned_to_either_target'])
 def test_bad_schema(self):
  self.d['schema']='bad'
  with self.assertRaises(ValueError):audit(self.d,'test')
 def test_duplicate_rows_preserved(self):
  self.d['audit']['requests'].append(copy.deepcopy(self.d['audit']['requests'][0]))
  self.assertEqual(audit(self.d,'test')['hosts']['level3.blizzard.com']['captured_request_rows'],27)
if __name__=='__main__':unittest.main()
