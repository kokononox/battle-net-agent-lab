"""Bounded read-only Agent-path and form-shape diagnostics. Never authorizes a session.
Only scoped Agent binaries may be hashed/signed; form values are never exported.
"""
import hashlib
import os
from pathlib import Path
import re

MAX_BINARY=128*1024**2
NAME=re.compile(r'[a-z][a-z0-9_-]{0,31}\Z')
TYPES={'null','boolean','number','string','object','array','other'}
PATH_PATTERN=re.compile(r'(?:Agent\.[0-9]{1,10}/)?Agent(?:[._-][A-Za-z0-9_-]{1,32})?\.exe(?:\.(?:old|bak|tmp|[0-9]{1,10}))?\Z',re.I)
TRANSITION_STATUSES={'not_observed','inspected_read_only','outside_scope','path_refused',
 'process_exited','snapshot_unstable','inspection_failed'}
RELATIONS={None,'same_as_pinned','different_within_agent_root','outside_agent_root'}

def value_type(value):
 return {type(None):'null',bool:'boolean',int:'number',float:'number',str:'string',dict:'object',list:'array'}.get(type(value),'other')

def safe_name(name):
 return name if type(name)is str and NAME.fullmatch(name)else None

def blank_form():return dict(status='not_observed',field_count=0,fields=[])

def summarize_form(form):
 result=blank_form()
 if type(form)is not dict or len(form)>32:
  result['status']='refused';return result
 result['status']='observed';result['field_count']=len(form)
 for name,value in form.items():
  members=[];member_count=None
  if type(value)is dict:
   member_count=min(len(value),33)
   if len(value)<=32:
    members=[dict(name=safe_name(k),type=value_type(v))for k,v in value.items()]
  result['fields'].append(dict(name=safe_name(name),type=value_type(value),member_count=member_count,members=members))
 return validate_form(result)

def validate_form(r):
 if type(r)is not dict or set(r)!={'status','field_count','fields'}:raise ValueError('shape_schema')
 if r['status']not in {'not_observed','observed','refused'}:raise ValueError('shape_status')
 if type(r['field_count'])is not int or not 0<=r['field_count']<=32 or type(r['fields'])is not list or len(r['fields'])!=r['field_count']:raise ValueError('shape_count')
 if r['status']!='observed'and r['field_count']:raise ValueError('shape_unobserved')
 for f in r['fields']:
  if type(f)is not dict or set(f)!={'name','type','member_count','members'}:raise ValueError('shape_field')
  if f['name']is not None and safe_name(f['name'])!=f['name']or f['type']not in TYPES:raise ValueError('shape_name_type')
  if type(f['members'])is not list or len(f['members'])>32:raise ValueError('shape_members')
  if f['type']=='object':
   if type(f['member_count'])is not int or not 0<=f['member_count']<=33:raise ValueError('shape_member_count')
   if len(f['members'])!=(0 if f['member_count']==33 else f['member_count']):raise ValueError('shape_member_sum')
  elif f['member_count']is not None or f['members']:raise ValueError('shape_scalar')
  for m in f['members']:
   if type(m)is not dict or set(m)!={'name','type'}or m['type']not in TYPES:raise ValueError('shape_member')
   if m['name']is not None and safe_name(m['name'])!=m['name']:raise ValueError('shape_member_name')
 return r

def blank_transition():
 return dict(status='not_observed',path_relation=None,initial_relative_path=None,
  observed_relative_path=None,pinned_path_exists=None,observed_path_exists=None,
  same_file_as_pinned=None,observed_signature_accepted=None,observed_sha256=None,
  observed_bytes_hashed=0,matches_initial_sha256=None,original_listener_still_owned=None,
  snapshot_stable=None)

def relative_label(path,root):
 try:text='/'.join(path.relative_to(root).parts)
 except ValueError:return None
 return text if PATH_PATTERN.fullmatch(text)else None

def scoped_file(path,root,is_reparse):
 if not path.is_absolute()or '..'in path.parts:return False
 try:path.relative_to(root)
 except ValueError:return False
 # Test all lexical ancestors before opening anything. No link resolution first.
 for parent in reversed((path,*path.parents)):
  if is_reparse(parent):return False
 return path.is_file()and 2<=path.stat().st_size<=MAX_BINARY

def inspect_transition(process,pinned,selected,root,initial_hash,process_image,listener_rows,is_reparse,signature,env):
 result=blank_transition();result['initial_relative_path']=relative_label(pinned,root)
 try:
  if process.poll()is not None:
   result['status']='process_exited';return result
  observed=process_image(process.pid)
  try:observed.relative_to(root)
  except ValueError:
   result['status']='outside_scope';result['path_relation']='outside_agent_root';return result
  result['path_relation']='same_as_pinned'if observed==pinned else'different_within_agent_root'
  result['observed_relative_path']=relative_label(observed,root)
  if result['observed_relative_path']is None or not scoped_file(observed,root,is_reparse):
   result['status']='path_refused';return result
  result['observed_path_exists']=True
  # Do not open a replacement at the old path unless it passes the same scope guard.
  result['pinned_path_exists']=pinned.exists()
  if result['pinned_path_exists']and scoped_file(pinned,root,is_reparse):result['same_file_as_pinned']=os.path.samefile(pinned,observed)
  h=hashlib.sha256();before=observed.stat();size=before.st_size
  with observed.open('rb')as f:
   remaining=MAX_BINARY+1
   while remaining:
    chunk=f.read(min(1024**2,remaining))
    if not chunk:break
    h.update(chunk);result['observed_bytes_hashed']+=len(chunk);remaining-=len(chunk)
  if result['observed_bytes_hashed']>MAX_BINARY or result['observed_bytes_hashed']!=size:
   result['observed_bytes_hashed']=min(result['observed_bytes_hashed'],MAX_BINARY)
   result['status']='snapshot_unstable';return result
  result['observed_sha256']=h.hexdigest();result['matches_initial_sha256']=result['observed_sha256']==initial_hash
  sig=signature(observed,env)
  accepted=sig.get('accepted_for_execution')
  if type(accepted)is not bool:raise ValueError('signature_result')
  result['observed_signature_accepted']=accepted
  address='127.0.0.1'if selected[1]=='loopback'else'0.0.0.0'
  result['original_listener_still_owned']=listener_rows(process.pid).count((address,selected[0]))==1
  after=observed.stat()
  result['snapshot_stable']=process.poll()is None and process_image(process.pid)==observed and scoped_file(observed,root,is_reparse)and(after.st_size,after.st_mtime_ns,after.st_ino)==(size,before.st_mtime_ns,before.st_ino)
  result['status']='inspected_read_only'if result['snapshot_stable']else'snapshot_unstable'
 except Exception:result['status']='inspection_failed'
 return validate_transition(result)

def validate_transition(r):
 if type(r)is not dict or set(r)!=set(blank_transition()):raise ValueError('transition_schema')
 if r['status']not in TRANSITION_STATUSES or r['path_relation']not in RELATIONS:raise ValueError('transition_enum')
 for k in ('initial_relative_path','observed_relative_path'):
  if r[k]is not None and(type(r[k])is not str or not PATH_PATTERN.fullmatch(r[k])):raise ValueError('transition_path')
 for k in ('pinned_path_exists','observed_path_exists','same_file_as_pinned','observed_signature_accepted','matches_initial_sha256','original_listener_still_owned','snapshot_stable'):
  if r[k]is not None and type(r[k])is not bool:raise ValueError('transition_boolean')
 if type(r['observed_bytes_hashed'])is not int or not 0<=r['observed_bytes_hashed']<=MAX_BINARY:raise ValueError('transition_size')
 if r['observed_sha256']is not None and(type(r['observed_sha256'])is not str or not re.fullmatch('[0-9a-f]{64}',r['observed_sha256'])):raise ValueError('transition_hash')
 if r['status']=='inspected_read_only'and not(r['observed_sha256']is not None and r['observed_signature_accepted']is not None and r['snapshot_stable']is True and r['path_relation']in('same_as_pinned','different_within_agent_root')):raise ValueError('transition_evidence')
 return r
