import copy
import unittest
from correlate import normalized,socket_streams

def slices():
    total=262241
    return [dict(kind='recv',api='recv',pid=1,socket='s1',operation='o1',order=1,return_code=total,accepted_bytes=n,declared_bytes=n,asynchronous=False,completion_proven=False,ambiguous=False,complete=True,is_slice=True,slice_offset=offset,operation_total_bytes=total,slice_final=(offset+n==total),raw=b'A'*n) for offset,n in [(0,131072),(131072,131072),(262144,97)]]
class SliceIntegrity(unittest.TestCase):
    def test_whole_operation(self):
        e=slices();self.assertEqual(socket_streams(e,'recv'),{(1,'s1'):[b'A'*262241]})
    def test_missing_tail_no_positive(self):
        e=slices()[:-1];self.assertEqual(socket_streams(e,'recv'),{(1,'s1'):[]})
    def test_missing_middle_no_positive(self):
        e=slices()[::2];self.assertEqual(socket_streams(e,'recv'),{(1,'s1'):[]})
    def test_duplicate_offset_no_positive(self):
        e=slices();e.insert(0,dict(e[0]));self.assertEqual(socket_streams(e,'recv'),{(1,'s1'):[]})
    def test_mixed_socket_no_positive(self):
        e=slices();e[1]['socket']='s2';self.assertTrue(all(not x['complete'] for x in normalized(e)))
    def test_wrong_total_no_positive(self):
        e=slices();e[2]['operation_total_bytes']+=1;self.assertTrue(all(not x['complete'] for x in normalized(e)))
    def test_oversized_piece_no_positive(self):
        e=slices();e[0]['accepted_bytes']=131073;self.assertTrue(all(not x['complete'] for x in normalized(e)))
    def test_truncated_piece_no_positive(self):
        e=slices();e[0]['raw']=b'A';self.assertTrue(all(not x['complete'] for x in normalized(e)))
    def test_early_final_no_positive(self):
        e=slices();e[0]['slice_final']=True;self.assertTrue(all(not x['complete'] for x in normalized(e)))
    def test_concurrent_still_excluded(self):
        e=slices();e[1]['ambiguous']=True;self.assertEqual(socket_streams(e,'recv'),{})
if __name__=='__main__':unittest.main()
