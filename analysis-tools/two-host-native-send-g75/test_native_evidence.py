import unittest,json
from native_evidence import pack,unpack,encoded,LIMIT
class T(unittest.TestCase):
 def data(self):return {'run_id':'1','source_commit':'a'*40,'passed':True,'rows':[{'case':'synthetic_case_'+str(i),'passed':True,'bytes':i,'reasons':['fixed_reason'],'flags':None} for i in range(48)]}
 def test_round_trip_bounded_messages(self):
  r=self.data();s,c=pack(r);self.assertEqual(unpack(s,list(reversed(c))),r)
  self.assertTrue(all(len(encoded(x).encode())<=LIMIT for x in [s]+c))
 def test_missing_chunk_and_mutation_rejected(self):
  s,c=pack(self.data())
  with self.assertRaises(ValueError):unpack(s,c[:-1])
  c[0]['rows'][0][0]=999
  with self.assertRaises(ValueError):unpack(s,c)
 def test_oversized_evidence_not_silently_truncated(self):
  r=self.data();r['rows'][0]['case']='x'*4000
  with self.assertRaises(ValueError):pack(r)
