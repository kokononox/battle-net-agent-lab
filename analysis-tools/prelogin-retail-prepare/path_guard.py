"""Metadata-only ancestor check; never opens game files or trusts outside paths."""
import os,stat
from pathlib import Path
from path_relation import classify
STATES={'not_observed','verified_existing_chain','verified_existing_ancestors_missing_tail','refused'}
def blank():return dict(status='not_observed',existing_components_checked=0,missing_tail=False,reparse_detected=False,absolute_containment_lexically_verified=False,race_free_containment_proven=False)
def validate(r):
 if type(r)is not dict or set(r)!=set(blank()) or r['status']not in STATES:raise ValueError('path_guard')
 if type(r['existing_components_checked'])is not int or not 0<=r['existing_components_checked']<=64:raise ValueError('path_count')
 for k in ('missing_tail','reparse_detected','absolute_containment_lexically_verified','race_free_containment_proven'):
  if type(r[k])is not bool:raise ValueError('path_bool')
 if r['race_free_containment_proven']is not False:raise ValueError('race_proof')
 if r['status']=='not_observed' and r!=blank():raise ValueError('not_observed')
 if r['status'].startswith('verified_') and (not r['absolute_containment_lexically_verified'] or r['reparse_detected'] or r['existing_components_checked']<1 or r['missing_tail']!=(r['status']=='verified_existing_ancestors_missing_tail')):raise ValueError('path_evidence')
 return r
def inspect(requested,returned,lstat=os.lstat):
 r=blank();r['status']='refused'
 if classify(str(requested),returned)['relation']not in {'exact_string','normalized_equal','child_of_owned_target'}:return validate(r)
 r['absolute_containment_lexically_verified']=True
 p=Path(returned);chain=list(reversed((p,*p.parents)))
 if len(chain)>64:return validate(r)
 try:
  for part in chain:
   try:s=lstat(part)
   except FileNotFoundError:r['missing_tail']=True;break
   r['existing_components_checked']+=1
   if getattr(s,'st_file_attributes',0)&0x400 or stat.S_ISLNK(s.st_mode):r['reparse_detected']=True;return validate(r)
   if not stat.S_ISDIR(s.st_mode):return validate(r)
  if r['existing_components_checked']==0:return validate(r)
  r['status']='verified_existing_ancestors_missing_tail' if r['missing_tail'] else 'verified_existing_chain'
 except OSError:pass
 return validate(r)
