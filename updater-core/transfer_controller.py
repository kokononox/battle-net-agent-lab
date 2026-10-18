"""Sequential owned-scratch transfer controller; no game access or auto retry.
A grant is explicit per run. Its saved JSON is NOT authority: restore requires
approved=True again. Durable reservation precedes every fetch. An ambiguous
pending attempt stops; only explicit local reconciliation can accept a freshly
verified stage commit. No lock breaking,
orphan adoption, automatic recovery, scanning, target switching or apply.
"""
from dataclasses import dataclass
import contextlib,hashlib,json,uuid
from pathlib import Path
from release_core import need,strict_json
from stream_stage import StreamStage,stage_identity,_Segments,SEGMENT
from stream_blte import verify_stream
from windows_stream_stage import WindowsStreamStage
from segment_stage import _read
from archive_transfer import archive_url,ArchiveResponse
from range_resume import strong_etag
MAX_OBJECTS=64
MAX_REQUESTS=4096
MAX_BODY=4*1024**3

def digest(raw):return hashlib.sha256(raw).hexdigest()
def encode(d):return json.dumps(d,sort_keys=True,separators=(',',':')).encode()
def stages_checked(stages):
 need(type(stages)is tuple and 0<len(stages)<=MAX_OBJECTS,'transfer_stage_count')
 need(all(type(s)in(StreamStage,WindowsStreamStage)for s in stages),'transfer_exact_owned_stage_type')
 need(len({str(s.path.absolute())for s in stages})==len(stages),'transfer_duplicate_stage_path')
 cp=stages[0].cp.serialize();need(all(s.cp.serialize()==cp for s in stages),'transfer_checkpoint_mismatch')
 ids=[stage_identity(s.cp,s.spec,s.source)for s in stages];need(len(set(ids))==len(ids),'transfer_duplicate_object');return ids

def entities(stages):
 result={}
 for s in stages:
  if s.doc['committed_bytes']:
   url=archive_url(s.cp,s.source);value={'etag':s.doc['etag'],'total':s.doc['archive_total']};need(url not in result or result[url]==value,'transfer_shared_archive_entity_changed');result[url]=value
 return result

def verify_prefix_locked(stage):
 stage._load();r=_Segments(stage);n=0
 try:
  while True:
   raw=r.read(65536)
   if not raw:break
   n+=len(raw)
 finally:r.close()
 need(n==stage.doc['committed_bytes'],'transfer_prefix_size')

def verify_prefix(stage):
 with stage._lock():verify_prefix_locked(stage)

@dataclass(frozen=True)
class RangeRequest:
 stage_identity:str
 relative:tuple
 url:str
 start:int
 end:int
 expected_etag:object
 expected_total:object

class TransferGrant:
 @classmethod
 def approve(cls,stages,*,max_requests,max_body_bytes,approved):
  need(approved is True,'transfer_explicit_approval_required');ids=stages_checked(stages);rows=[]
  for s,key in zip(stages,ids):
   verify_prefix(s);rows.append({'identity':key,'initial_committed':s.doc['committed_bytes'],'initial_journal_sha256':s.journal_sha})
  return cls._bind(stages,{'format':'owned-transfer-grant-2','scope_nonce':uuid.uuid4().hex,'prior_scopes_sha256':digest(encode([])),'checkpoint_sha256':digest(stages[0].cp.serialize()),'stages':rows,'max_requests':max_requests,'max_body_bytes':max_body_bytes})
 @classmethod
 def restore(cls,raw,stages,*,approved):
  need(approved is True,'transfer_restore_needs_new_explicit_approval');need(type(raw)is bytes and 0<len(raw)<=65536,'transfer_grant_size');return cls._bind(stages,strict_json(raw))
 @classmethod
 def _bind(cls,stages,d):
  ids=stages_checked(stages);need(type(d)is dict,'transfer_grant_shape');keys={'format','checkpoint_sha256','stages','max_requests','max_body_bytes'}
  if d.get('format')=='owned-transfer-grant-2':
   keys.update(('scope_nonce','prior_scopes_sha256'));history=d.get('prior_scopes_sha256');need(type(history)is str and len(history)==64 and all(c in'0123456789abcdef'for c in history),'transfer_prior_scopes_digest');nonce=d.get('scope_nonce');need(type(nonce)is str and len(nonce)==32 and all(c in'0123456789abcdef'for c in nonce),'transfer_scope_nonce')
  else:need(d.get('format')=='owned-transfer-grant-1','transfer_grant_version')
  need(set(d)==keys and d['checkpoint_sha256']==digest(stages[0].cp.serialize()),'transfer_grant_identity')
  need(type(d['max_requests'])is int and 0<=d['max_requests']<=MAX_REQUESTS and type(d['max_body_bytes'])is int and 0<=d['max_body_bytes']<=MAX_BODY,'transfer_grant_budget')
  need(type(d['stages'])is list and len(d['stages'])==len(stages),'transfer_grant_stages');ranges=[]
  for i,(s,key,row)in enumerate(zip(stages,ids,d['stages'])):
   need(type(row)is dict and set(row)=={'identity','initial_committed','initial_journal_sha256'}and row['identity']==key,'transfer_grant_stage_identity');n=row['initial_committed'];h=row['initial_journal_sha256'];need(type(n)is int and 0<=n<=s.spec.encoded_size and type(h)is str and len(h)==64 and all(c in'0123456789abcdef'for c in h),'transfer_grant_initial_state')
   need((s.spec.encoded_size-n+SEGMENT-1)//SEGMENT<=MAX_REQUESTS-len(ranges),'transfer_range_count')
   for a in range(n,s.spec.encoded_size,SEGMENT):ranges.append((i,a,min(a+SEGMENT,s.spec.encoded_size)-1))
  need(len(ranges)<=d['max_requests']and sum(b-a+1 for _,a,b in ranges)<=d['max_body_bytes'],'transfer_plan_exceeds_approval')
  g=cls();g._raw=encode(d);g.identity=digest(g._raw);g.ranges=tuple(ranges);g.rows=tuple(d['stages']);g.identities=tuple(ids);g.checkpoint_sha256=d['checkpoint_sha256'];g.max_requests=d['max_requests'];g.max_body_bytes=d['max_body_bytes'];return g
 def serialize(self):return self._raw
 def match(self,stages):
  fresh=type(self)._bind(stages,strict_json(self._raw));need(self.identity==fresh.identity and self.ranges==fresh.ranges and self.rows==fresh.rows and self.max_requests==fresh.max_requests and self.max_body_bytes==fresh.max_body_bytes and self.identities==fresh.identities and self.checkpoint_sha256==fresh.checkpoint_sha256,'transfer_grant_mutated')

def read_ledger(stage):
 return stage.store.read('transfer.json',1024**2)if type(stage)is WindowsStreamStage else _read(stage.path/'transfer.json',1024**2)

class TransferController:
 @classmethod
 def create(cls,stages,grant,fetch):
  c=cls._attach(stages,grant,fetch)
  for s,row in zip(stages,grant.rows):
   verify_prefix(s);need(s.journal_sha==row['initial_journal_sha256']and s.doc['committed_bytes']==row['initial_committed'],'transfer_initial_state_changed')
  c.doc={'format':'owned-transfer-ledger-2','prior_scopes':[],'grant_sha256':grant.identity,'cursor':0,'pending':False,'reserved_requests':0,'reserved_body_bytes':0,'journal_hashes':[r['initial_journal_sha256']for r in grant.rows],'entities':entities(stages)}
  with stages[0]._lock():stages[0]._write('transfer.json',encode(c.doc));stages[0]._sync(stages[0].path)
  c._load();return c
 @classmethod
 def restore(cls,stages,grant,fetch):
  c=cls._attach(stages,grant,fetch);c._load();need(not c.doc['pending'],'transfer_ambiguous_attempt_stop_no_auto_retry');c._check_stages()
  for s in stages:verify_prefix(s)
  c._check_stages();return c
 @classmethod
 def _attach(cls,stages,grant,fetch):
  need(type(grant)is TransferGrant and callable(fetch),'transfer_grant_and_fetch_required');grant.match(stages);c=cls();c.stages=stages;c.grant=grant;c.fetch=fetch;return c
 def _load(self):return self._validate_ledger(strict_json(read_ledger(self.stages[0])))
 def _validate_ledger(self,d,*,verify_history=True):
  need(type(d)is dict,'transfer_ledger_shape');base={'format','grant_sha256','cursor','pending','reserved_requests','reserved_body_bytes','journal_hashes','entities'}
  if d.get('format')=='owned-transfer-ledger-1':need(set(d)==base,'transfer_ledger_legacy_shape');d=dict(d,format='owned-transfer-ledger-2',prior_scopes=[])
  need(type(d)is dict and set(d)==base|{'prior_scopes'}and d['format']=='owned-transfer-ledger-2'and d['grant_sha256']==self.grant.identity,'transfer_ledger_identity');n=d['cursor'];p=d['pending'];need(type(n)is int and 0<=n<=len(self.grant.ranges)and type(p)is bool and(not p or n<len(self.grant.ranges)),'transfer_ledger_cursor');attempts=n+int(p);body=sum(b-a+1 for _,a,b in self.grant.ranges[:attempts]);need(type(d['reserved_requests'])is int and d['reserved_requests']==attempts<=self.grant.max_requests and type(d['reserved_body_bytes'])is int and d['reserved_body_bytes']==body<=self.grant.max_body_bytes,'transfer_ledger_budget');need(type(d['journal_hashes'])is list and len(d['journal_hashes'])==len(self.stages)and all(type(h)is str and len(h)==64 and all(c in'0123456789abcdef'for c in h)for h in d['journal_hashes']),'transfer_ledger_hashes');need(type(d['entities'])is dict and len(d['entities'])<=len(self.stages),'transfer_entities_shape')
  allowed={archive_url(s.cp,s.source)for s in self.stages}
  for url,value in d['entities'].items():need(url in allowed and type(value)is dict and set(value)=={'etag','total'}and strong_etag(value['etag'])and type(value['total'])is int and 0<value['total']<=2**63-1,'transfer_entity_shape')
  from transfer_scope import validate_history_rows,validate_history
  validate_history_rows(d['prior_scopes']);grant_doc=strict_json(self.grant.serialize())
  if grant_doc['format']=='owned-transfer-grant-2':need(digest(encode(d['prior_scopes']))==grant_doc['prior_scopes_sha256'],'transfer_history_not_bound_to_grant')
  else:need(not d['prior_scopes'],'transfer_legacy_grant_has_no_history')
  need(self.grant.identity not in{r['grant_sha256']for r in d['prior_scopes']},'transfer_closed_scope_reused')
  if verify_history:validate_history(self.stages,d['prior_scopes'])
  self.doc=d;return d
 def _publish(self,d):
  s=self.stages[0];name=uuid.uuid4().hex+'.tmp';s._write(name,encode(d));s._replace(name,'transfer.json');s._sync(s.path);self.doc=d
 def _check_stages(self):
  self.grant.match(self.stages)
  expected=[r['initial_committed']for r in self.grant.rows]
  for i,a,b in self.grant.ranges[:self.doc['cursor']]:expected[i]=b+1
  for s,h,n in zip(self.stages,self.doc['journal_hashes'],expected):
   s._load();need(s.journal_sha==h and s.doc['committed_bytes']==n,'transfer_stage_changed_outside_ledger')
  need(self.doc['entities']==entities(self.stages),'transfer_entities_disagree')
 def step(self,current_baseline,*,cancelled=lambda:False,_fault=None):
  need(callable(cancelled),'transfer_cancel_callback');stop=cancelled();need(type(stop)is bool,'transfer_cancel_boolean')
  if stop:return dict(self.summary(),status='cancelled_before_request')
  with self.stages[0]._lock():
   self._load();need(not self.doc['pending'],'transfer_ambiguous_attempt_stop_no_auto_retry');self._check_stages();self.stages[0].cp.resume(current_baseline)
   n=self.doc['cursor']
   if n==len(self.grant.ranges):return dict(self.summary(),status='transferred_NOT_freshly_verified')
   i,a,b=self.grant.ranges[n];s=self.stages[i];url=archive_url(s.cp,s.source);entity=self.doc['entities'].get(url,{'etag':None,'total':None});req=RangeRequest(self.grant.identities[i],(a,b),url,s.source.offset+a,s.source.offset+b,entity['etag'],entity['total']);d=dict(self.doc,pending=True,reserved_requests=n+1,reserved_body_bytes=self.doc['reserved_body_bytes']+b-a+1);self._publish(d)
  if _fault:_fault('attempt_reserved')
  response=self.fetch(req);need(type(response)is ArchiveResponse and(req.expected_etag is None or response.etag==req.expected_etag)and(req.expected_total is None or response.total==req.expected_total),'transfer_response_entity_changed');stop=cancelled();need(type(stop)is bool,'transfer_cancel_boolean');need(not stop,'transfer_cancelled_after_request_pending');self.grant.match(self.stages);self.stages[0].cp.resume(current_baseline);s.append(response,(a,b))
  if b+1==s.spec.encoded_size:s.verify()
  if _fault:_fault('stage_committed')
  with self.stages[0]._lock():
   self._load();need(self.doc['pending']and self.doc['cursor']==n,'transfer_ledger_changed');hashes=list(self.doc['journal_hashes']);hashes[i]=s.journal_sha;self._publish(dict(self.doc,cursor=n+1,pending=False,journal_hashes=hashes,entities=entities(self.stages)))
  return dict(self.summary(),status='one_range_committed')
 @classmethod
 def reconcile_pending(cls,stages,grant,current_baseline,*,approved,_fault=None):
  """Explicit local-only recovery of ONE already-journaled reserved range.
  Never fetches/retries; uncommitted/ambiguous data stays pending. All stage
  writer locks held, no abandoned lock breaking or power-loss qualification.
  """
  need(approved is True,'transfer_reconciliation_explicit_approval_required')
  def no_fetch(req):need(False,'transfer_reconciliation_network_forbidden')
  c=cls._attach(stages,grant,no_fetch)
  with contextlib.ExitStack()as held:
   for stage in stages:held.enter_context(stage._lock())
   c._load();need(c.doc['pending'],'transfer_reconciliation_requires_pending');grant.match(stages);stages[0].cp.resume(current_baseline);n=c.doc['cursor'];i,a,b=grant.ranges[n];expected=[r['initial_committed']for r in grant.rows]
   for j,x,y in grant.ranges[:n]:expected[j]=y+1
   snapshots=[]
   for j,stage in enumerate(stages):
    stage._load();snapshots.append(stage.journal_sha)
    if j!=i:need(stage.journal_sha==c.doc['journal_hashes'][j]and stage.doc['committed_bytes']==expected[j],'transfer_reconciliation_other_stage_changed')
   stage=stages[i];need(expected[i]==a,'transfer_reconciliation_range_start')
   if stage.journal_sha==c.doc['journal_hashes'][i]:
    need(stage.doc['committed_bytes']==a and entities(stages)==c.doc['entities'],'transfer_reconciliation_unchanged_mismatch')
    for item in stages:verify_prefix_locked(item)
    return dict(c.summary(),status='no_stage_commit_pending_retained_new_scope_required',reconciled=False,network_requests=0,full_object_verified=False)
   d=stage.doc;need(d['committed_bytes']==b+1 and bool(d['segments'])and d['segments'][-1]['start']==a and d['segments'][-1]['size']==b-a+1,'transfer_reconciliation_not_one_reserved_segment');prior=dict(d,segments=d['segments'][:-1],committed_bytes=a)
   if not a:prior.update(etag=None,archive_total=None)
   need(digest(stage._encode(prior))==c.doc['journal_hashes'][i],'transfer_reconciliation_prior_journal_unproven')
   old_entities={}
   for j,item in enumerate(stages):
    old=prior if j==i else item.doc
    if old['committed_bytes']:
     url=archive_url(item.cp,item.source);value={'etag':old['etag'],'total':old['archive_total']};need(url not in old_entities or old_entities[url]==value,'transfer_reconciliation_old_entity_conflict');old_entities[url]=value
   need(old_entities==c.doc['entities'],'transfer_reconciliation_old_entities_unproven');new_entities=entities(stages)
   for url,value in old_entities.items():need(new_entities.get(url)==value,'transfer_reconciliation_entity_changed')
   for item in stages:verify_prefix_locked(item)
   proof=None
   if b+1==stage.spec.encoded_size:
    reader=_Segments(stage)
    try:proof=verify_stream(reader,stage.spec)
    finally:reader.close()
   for item,h in zip(stages,snapshots):item._load();need(item.journal_sha==h,'transfer_reconciliation_journal_changed')
   if _fault:_fault('reconcile_verified')
   hashes=list(c.doc['journal_hashes']);hashes[i]=stage.journal_sha;c._publish(dict(c.doc,cursor=n+1,pending=False,journal_hashes=hashes,entities=new_entities))
   if _fault:_fault('reconcile_committed')
   return dict(c.summary(),status='one_reserved_stage_commit_freshly_reconciled',reconciled=True,network_requests=0,full_object_verified=proof is not None,full_object_proof=proof)
 def finish(self):
  self._load();need(not self.doc['pending']and self.doc['cursor']==len(self.grant.ranges),'transfer_not_complete');self._check_stages();proofs=[s.verify()for s in self.stages];self._check_stages();return dict(self.summary(),status='all_owned_objects_freshly_verified',proofs=proofs,all_objects_freshly_verified=True)
 def summary(self):
  return {'format':'owned-transfer-summary-1','grant_sha256':self.grant.identity,'completed_ranges':self.doc['cursor'],'pending_attempt':self.doc['pending'],'reserved_requests':self.doc['reserved_requests'],'reserved_application_body_bytes':self.doc['reserved_body_bytes'],'retired_scope_count':len(self.doc['prior_scopes']),'lifetime_reserved_requests':self.doc['reserved_requests']+sum(r['reserved_requests']for r in self.doc['prior_scopes']),'lifetime_reserved_application_body_bytes':self.doc['reserved_body_bytes']+sum(r['reserved_body_bytes']for r in self.doc['prior_scopes']),'reservation_is_not_wire_byte_measurement':True,'target_automatically_replaced':False,'game_access':False,'active_generation_proven':False,'vendor_selection_policy_qualified':False,'required_network_download_bytes':None,'installation_ready':False,'apply_authorized':False}
