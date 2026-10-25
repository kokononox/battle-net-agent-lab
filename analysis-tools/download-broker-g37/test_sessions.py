"""Adversarial fixed-session tests, fixture transport only."""
from dataclasses import FrozenInstanceError
from concurrent.futures import ThreadPoolExecutor
import itertools
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
from broker import Catalog,Denied,InMemoryTransport,OfflineBroker,Reply,digest
from test_broker import PAYLOAD,policy,load,encoded

SECOND=b'SECOND SYNTHETIC FIXTURE\n'
def two_policy():
 p=policy();row=dict(p['resources'][0]);row.update(resource_id='second',host='us.version.battle.net',path='/audit-fixture/second.bin',expected_bytes=len(SECOND),sha256=digest(SECOND))
 p['resources'].append(row)
 p['session']={'resource_ids':['fixture','second'],'max_requests':2,'max_total_bytes':len(PAYLOAD)+len(SECOND)}
 return p

def setup_session():
 c=load(two_policy());replies={}
 for rid,body in [('fixture',PAYLOAD),('second',SECOND)]:
  plan=c.plan(encoded({'resource_id':rid}));replies[(plan.host,plan.request)]=Reply(200,body)
 t=InMemoryTransport(replies)
 return c,t,OfflineBroker(c,t)

def request(rid):return encoded({'resource_id':rid})

class SessionTests(unittest.TestCase):
 def setUp(self):
  guard=patch.object(socket,'socket',side_effect=AssertionError('network_forbidden'))
  guard.start();self.addCleanup(guard.stop)
  self.catalog,self.transport,self.broker=setup_session()
 def test_fixed_sequence_and_exact_budgets(self):
  self.assertEqual(self.broker.download(request('fixture')),PAYLOAD)
  mid=self.broker.snapshot();self.assertEqual((mid.phase,mid.attempts_reserved,mid.expected_bytes_reserved,mid.verified_bytes_delivered),('active',1,len(PAYLOAD),len(PAYLOAD)))
  self.assertEqual(self.broker.download(request('second')),SECOND)
  end=self.broker.snapshot();self.assertEqual((end.phase,end.attempts_reserved,end.expected_bytes_reserved,end.verified_bytes_delivered),('complete',2,len(PAYLOAD)+len(SECOND),len(PAYLOAD)+len(SECOND)))
  self.assertEqual(end.request_wire_bytes,sum(len(p.request) for p in self.transport.calls))
  self.assertEqual([p.resource_id for p in self.transport.calls],['fixture','second'])
 def test_out_of_order_closes_before_fetch(self):
  with self.assertRaises(Denied) as e:self.broker.download(request('second'))
  self.assertEqual(e.exception.code,'session_order_rejected')
  self.assertEqual(self.broker.snapshot().phase,'failed');self.assertEqual(self.transport.calls,[])
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
  self.assertEqual(self.transport.calls,[])
 def test_repeated_first_blocks_remaining(self):
  self.broker.download(request('fixture'))
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
  with self.assertRaises(Denied):self.broker.download(request('second'))
  self.assertEqual(len(self.transport.calls),1)
  self.assertEqual(self.broker.snapshot().phase,'failed')
 def test_completed_session_never_reopens(self):
  self.broker.download(request('fixture'));self.broker.download(request('second'))
  before=self.broker.snapshot()
  for rid in ('fixture','second','unknown'):
   with self.assertRaises(Denied):self.broker.download(request(rid))
  self.assertEqual(before,self.broker.snapshot());self.assertEqual(len(self.transport.calls),2)
 def test_hash_failure_spends_attempt_and_never_retries(self):
  p=self.catalog.plan(request('fixture'));self.transport.replies[(p.host,p.request)]=Reply(200,b'X'*len(PAYLOAD))
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
  self.assertEqual((self.broker.snapshot().attempts_reserved,self.broker.snapshot().expected_bytes_reserved,self.broker.snapshot().verified_bytes_delivered),(1,len(PAYLOAD),0))
  self.transport.replies[(p.host,p.request)]=Reply(200,PAYLOAD)
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
  self.assertEqual(len(self.transport.calls),1)
 def test_redirect_terminal_no_refund(self):
  p=self.catalog.plan(request('fixture'));self.transport.replies[(p.host,p.request)]=Reply(302,b'')
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
  self.assertEqual((self.broker.snapshot().phase,self.broker.snapshot().attempts_reserved),('failed',1))
  with self.assertRaises(Denied):self.broker.download(request('second'))
  self.assertEqual(len(self.transport.calls),1)
 def test_transport_exception_terminal(self):
  with patch.object(self.transport,'fetch',side_effect=OSError('synthetic_failure')) as fetch:
   with self.assertRaises(OSError):self.broker.download(request('fixture'))
   with self.assertRaises(Denied):self.broker.download(request('fixture'))
   self.assertEqual(fetch.call_count,1)
  self.assertEqual((self.broker.snapshot().phase,self.broker.snapshot().attempts_reserved),('failed',1))
 def test_interruption_terminal(self):
  with patch.object(self.transport,'fetch',side_effect=KeyboardInterrupt):
   with self.assertRaises(KeyboardInterrupt):self.broker.download(request('fixture'))
  self.assertEqual(self.broker.snapshot().phase,'failed')
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
 def test_malformed_input_terminal_no_fetch(self):
  with self.assertRaises(Denied):self.broker.download(b'{')
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
  self.assertEqual((self.broker.snapshot().phase,self.broker.snapshot().attempts_reserved),('failed',0))
  self.assertEqual(self.transport.calls,[])
 def test_injected_body_terminal_no_fetch(self):
  with self.assertRaises(Denied):self.broker.download(encoded({'resource_id':'fixture','body':'SYNTHETIC-DEVICE-ID'}))
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
  self.assertEqual(self.transport.calls,[])
 def test_cancel_before_any_fetch(self):
  self.broker.cancel();self.broker.cancel()
  with self.assertRaises(Denied):self.broker.download(request('fixture'))
  self.assertEqual((self.broker.snapshot().phase,len(self.transport.calls)),('cancelled',0))
 def test_cancel_between_resources(self):
  self.broker.download(request('fixture'));self.broker.cancel()
  with self.assertRaises(Denied):self.broker.download(request('second'))
  self.assertEqual(len(self.transport.calls),1)
 def test_cancel_does_not_reset_complete(self):
  self.broker.download(request('fixture'));self.broker.download(request('second'))
  self.broker.cancel();self.assertEqual(self.broker.snapshot().phase,'complete')
 def test_snapshot_readonly(self):
  with self.assertRaises(FrozenInstanceError):self.broker.snapshot().phase='active'
 def test_session_spec_readonly(self):
  with self.assertRaises(FrozenInstanceError):self.catalog.session.max_requests=99
 def test_legacy_policy_no_fallback(self):
  p=policy();p['schema']='offline_download_catalog_v1';del p['session']
  with self.assertRaises(Denied):load(p)
 def test_session_shapes_rejected(self):
  for session in (None,[],{}, {'resource_ids':[],'max_requests':0,'max_total_bytes':0,'retry':True}):
   p=two_policy();p['session']=session
   with self.subTest(session=session),self.assertRaises(Denied):load(p)
 def test_sequence_duplicates_unknown_omission_rejected(self):
  for ids in (['fixture','fixture'],['fixture','unknown'],['fixture'],[],['second',3],'fixture',[['fixture']]):
   p=two_policy();p['session']['resource_ids']=ids
   with self.subTest(ids=ids),self.assertRaises(Denied):load(p)
 def test_request_budget_cannot_expand_or_shrink(self):
  for budget in (-1,0,1,3,True,2.0,'2'):
   p=two_policy();p['session']['max_requests']=budget
   with self.subTest(budget=budget),self.assertRaises(Denied):load(p)
 def test_byte_budget_must_match_exact_total(self):
  for budget in (-1,0,True,'49',1,len(PAYLOAD)+len(SECOND)+1):
   p=two_policy();p['session']['max_total_bytes']=budget
   with self.subTest(budget=budget),self.assertRaises(Denied):load(p)
 def test_aggregate_cap_rejected(self):
  p=two_policy()
  for row in p['resources']:row['expected_bytes']=512*1024*1024
  p['session']['max_total_bytes']=1024*1024*1024
  with self.assertRaises(Denied):load(p)
 def test_concurrent_duplicate_only_one_fetch(self):
  c=load();p=c.plan(request('fixture'));t=InMemoryTransport({(p.host,p.request):Reply(200,PAYLOAD)});b=OfflineBroker(c,t)
  def attempt(_):
   try:b.download(request('fixture'));return 'delivered'
   except Denied:return 'denied'
  with ThreadPoolExecutor(max_workers=8) as pool:out=list(pool.map(attempt,range(32)))
  self.assertEqual(out.count('delivered'),1);self.assertEqual(out.count('denied'),31)
  self.assertEqual(len(t.calls),1);self.assertEqual(b.snapshot().phase,'complete')
 def test_adversarial_sequences_preserve_prefix_and_budget(self):
  checked=0
  for length in range(4):
   for sequence in itertools.product(('fixture','second','unknown','malformed','injected'),repeat=length):
    _,t,b=setup_session();delivered=0
    for token in sequence:
     raw=b'{' if token=='malformed' else encoded({'resource_id':'fixture','body':'SYNTHETIC-ID'}) if token=='injected' else request(token)
     try:delivered+=len(b.download(raw))
     except Denied:pass
    ids=[p.resource_id for p in t.calls];state=b.snapshot()
    self.assertEqual(ids,['fixture','second'][:len(ids)])
    self.assertLessEqual(len(ids),2);self.assertEqual(state.attempts_reserved,len(ids))
    self.assertLessEqual(state.expected_bytes_reserved,len(PAYLOAD)+len(SECOND));self.assertEqual(state.verified_bytes_delivered,delivered)
    checked+=1
  self.assertEqual(checked,156)

if __name__=='__main__':unittest.main(verbosity=2)
