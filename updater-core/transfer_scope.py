"""Explicit retirement and successor scopes in OWNED scratch only.
No network, automatic retry, budget refund, deletion, scan or lock breaking.
Immutable receipts preserve consumed reservations. New scopes need new approval
and nonce. A cooperative history chain is not signed/hostile-process evidence.
"""
import contextlib
from release_core import need,strict_json
from transfer_controller import TransferController,TransferGrant,verify_prefix_locked,encode,digest,read_ledger,entities,MAX_REQUESTS,MAX_BODY
from windows_stream_stage import WindowsStreamStage
from segment_stage import _read
MAX_PRIOR_SCOPES=16
CAP=262144

def hex64(value):return type(value)is str and len(value)==64 and all(c in'0123456789abcdef'for c in value)
def read_owned(stage,name):
 need(type(name)is str and len(name)==69 and name.endswith('.json')and hex64(name[:-5]),'scope_receipt_name')
 return stage.store.read(name,CAP)if type(stage)is WindowsStreamStage else _read(stage.path/name,CAP)
def no_fetch(req):need(False,'scope_lifecycle_network_forbidden')
def validate_history_rows(rows):
 need(type(rows)is list and len(rows)<=MAX_PRIOR_SCOPES,'scope_history_limit');seen=set()
 for row in rows:
  need(type(row)is dict and set(row)=={'receipt_name','receipt_sha256','grant_sha256','reserved_requests','reserved_body_bytes'},'scope_history_shape');key=row['grant_sha256'];need(hex64(key)and key not in seen and row['receipt_name']==key+'.json'and hex64(row['receipt_sha256']),'scope_history_identity');seen.add(key);need(type(row['reserved_requests'])is int and 0<row['reserved_requests']<=MAX_REQUESTS and type(row['reserved_body_bytes'])is int and 0<row['reserved_body_bytes']<=MAX_BODY,'scope_history_budget')
def validate_record(stages,raw):
 need(type(raw)is bytes and 0<len(raw)<=CAP,'scope_record_size');r=strict_json(raw);need(type(r)is dict and set(r)=={'format','grant','ledger','reason','automatic_retry','budget_refunded'}and r['format']=='owned-scope-retirement-1'and r['reason']=='pending_without_stage_commit'and r['automatic_retry']is False and r['budget_refunded']is False,'scope_record_shape');g=TransferGrant._bind(stages,r['grant']);c=TransferController._attach(stages,g,no_fetch);d=c._validate_ledger(r['ledger'],verify_history=False);need(d['pending'],'scope_retired_ledger_not_pending');return r,g,d,c

def validate_history(stages,rows):
 validate_history_rows(rows)
 for i,row in enumerate(rows):
  raw=read_owned(stages[0],row['receipt_name']);need(digest(raw)==row['receipt_sha256'],'scope_history_receipt_digest');r,g,d,c=validate_record(stages,raw);need(g.identity==row['grant_sha256']and d['prior_scopes']==rows[:i]and d['reserved_requests']==row['reserved_requests']and d['reserved_body_bytes']==row['reserved_body_bytes'],'scope_history_chain_or_budget')

def read_retired(stages):
 t=strict_json(read_ledger(stages[0]));need(type(t)is dict and set(t)=={'format','grant_sha256','receipt_name','receipt_sha256'}and t['format']=='retired-transfer-ledger-1'and hex64(t['grant_sha256'])and t['receipt_name']==t['grant_sha256']+'.json'and hex64(t['receipt_sha256']),'scope_retired_marker');raw=read_owned(stages[0],t['receipt_name']);need(digest(raw)==t['receipt_sha256'],'scope_retired_receipt_digest');r,g,d,c=validate_record(stages,raw);need(g.identity==t['grant_sha256'],'scope_retired_grant');validate_history(stages,d['prior_scopes']);return t,r,g,d,c

def held_stages(stages):
 held=contextlib.ExitStack()
 try:
  for stage in stages:held.enter_context(stage._lock())
  return held
 except BaseException:held.close();raise

def report(d,identity,*,status):
 return {'format':'owned-scope-retirement-summary-1','status':status,'retired_grant_sha256':identity,'retired_reserved_requests':d['reserved_requests'],'retired_reserved_application_body_bytes':d['reserved_body_bytes'],'lifetime_reserved_requests':d['reserved_requests']+sum(r['reserved_requests']for r in d['prior_scopes']),'lifetime_reserved_application_body_bytes':d['reserved_body_bytes']+sum(r['reserved_body_bytes']for r in d['prior_scopes']),'network_requests':0,'budget_refunded':False,'automatic_retry':False,'automatic_continuation':False,'game_access':False,'installation_ready':False,'apply_authorized':False}

def retire_uncommitted(stages,grant,current_baseline,*,approved,_fault=None):
 need(approved is True,'scope_retirement_explicit_approval_required');c=TransferController._attach(stages,grant,no_fetch)
 with held_stages(stages):
  raw=read_ledger(stages[0]);peek=strict_json(raw)
  if type(peek)is dict and peek.get('format')=='retired-transfer-ledger-1':
   t,r,g,d,old=read_retired(stages);need(g.identity==grant.identity,'scope_retired_wrong_grant');stages[0].cp.resume(current_baseline);old._check_stages()
   for s in stages:verify_prefix_locked(s)
   return report(d,g.identity,status='already_retired_no_retry')
  c._validate_ledger(peek);need(c.doc['pending'],'scope_retirement_requires_pending');stages[0].cp.resume(current_baseline);c._check_stages()
  for s in stages:verify_prefix_locked(s)
  c._check_stages();d=c.doc;r={'format':'owned-scope-retirement-1','grant':strict_json(grant.serialize()),'ledger':d,'reason':'pending_without_stage_commit','automatic_retry':False,'budget_refunded':False};body=encode(r);need(len(body)<=CAP,'scope_receipt_size');name=grant.identity+'.json'
  try:stages[0]._write(name,body);stages[0]._sync(stages[0].path)
  except FileExistsError:need(read_owned(stages[0],name)==body,'scope_existing_receipt_conflict')
  if _fault:_fault('retirement_receipt_synced')
  c._publish({'format':'retired-transfer-ledger-1','grant_sha256':grant.identity,'receipt_name':name,'receipt_sha256':digest(body)})
  if _fault:_fault('retirement_committed')
  return report(d,grant.identity,status='scope_retired_no_retry')

def approve_successor(stages,current_baseline,*,max_requests,max_body_bytes,approved):
 need(approved is True,'scope_new_grant_explicit_approval_required')
 # Acquire/type-check through the retired record before issuing any new scope.
 from transfer_controller import stages_checked
 stages_checked(stages)
 with held_stages(stages):
  t,r,old_grant,d,old=read_retired(stages);stages[0].cp.resume(current_baseline);old._check_stages()
  for s in stages:verify_prefix_locked(s)
  history=d['prior_scopes']+[{'receipt_name':t['receipt_name'],'receipt_sha256':t['receipt_sha256'],'grant_sha256':old_grant.identity,'reserved_requests':d['reserved_requests'],'reserved_body_bytes':d['reserved_body_bytes']}];validate_history_rows(history)
 new=TransferGrant.approve(stages,max_requests=max_requests,max_body_bytes=max_body_bytes,approved=True);raw=strict_json(new.serialize());raw['prior_scopes_sha256']=digest(encode(history));return TransferGrant._bind(stages,raw)

def create_successor(stages,new_grant,fetch,current_baseline,*,approved,_fault=None):
 need(approved is True,'scope_successor_explicit_approval_required');c=TransferController._attach(stages,new_grant,fetch);need(strict_json(new_grant.serialize())['format']=='owned-transfer-grant-2','scope_successor_new_nonce_required')
 with held_stages(stages):
  t,r,old_grant,d,old=read_retired(stages);stages[0].cp.resume(current_baseline);old._check_stages();history=d['prior_scopes']+[{'receipt_name':t['receipt_name'],'receipt_sha256':t['receipt_sha256'],'grant_sha256':old_grant.identity,'reserved_requests':d['reserved_requests'],'reserved_body_bytes':d['reserved_body_bytes']}];validate_history_rows(history);need(new_grant.identity not in{row['grant_sha256']for row in history},'scope_closed_grant_cannot_restart')
  for s,row in zip(stages,new_grant.rows):
   verify_prefix_locked(s);need(s.journal_sha==row['initial_journal_sha256']and s.doc['committed_bytes']==row['initial_committed'],'scope_successor_initial_state_changed')
  old._check_stages();new={'format':'owned-transfer-ledger-2','grant_sha256':new_grant.identity,'prior_scopes':history,'cursor':0,'pending':False,'reserved_requests':0,'reserved_body_bytes':0,'journal_hashes':[row['initial_journal_sha256']for row in new_grant.rows],'entities':entities(stages)};c._validate_ledger(new)
  if _fault:_fault('successor_verified')
  c._publish(new)
  if _fault:_fault('successor_committed')
 return c
