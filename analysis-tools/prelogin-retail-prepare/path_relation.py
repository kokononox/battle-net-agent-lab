"""Pure lexical Windows path classification; no filesystem access or path export."""
import ntpath,re
RELATIONS={'not_observed','exact_string','normalized_equal','child_of_owned_target','outside_owned_target','invalid_path'}
def blank():return dict(relation='not_observed',child_depth=None,returned_absolute=None,returned_dot_segments=None,filesystem_containment_proven=False)
def normalize(value):
 if type(value)is not str or not 1<=len(value)<=4096 or any(ord(c)<32 for c in value):raise ValueError('path')
 v=value.replace('/','\\');drive,tail=ntpath.splitdrive(v)
 if re.fullmatch('[A-Za-z]:',drive)is None or not tail.startswith('\\') or ':'in tail:raise ValueError('path')
 # Reject device/UNC paths, stream syntax and ambiguous Win32 components.
 parts=[p for p in tail.split('\\') if p]
 if any(p not in ('.','..') and (p.endswith((' ','.')) or any(c in p for c in '<>"|?*')) for p in parts):raise ValueError('component')
 norm=ntpath.normcase(ntpath.normpath(v))
 return norm,any(p in ('.','..') for p in parts)
def classify(requested,returned):
 r=blank()
 if returned is None:return r
 r['relation']='invalid_path'
 try:
  a,_=normalize(requested);b,dots=normalize(returned)
  r['returned_absolute']=True;r['returned_dot_segments']=dots
  if a==b:r.update(relation='exact_string' if requested==returned else 'normalized_equal',child_depth=0)
  else:
   try:inside=ntpath.commonpath([a,b])==a
   except ValueError:inside=False
   if inside:
    depth=len(ntpath.relpath(b,a).split('\\'))
    if depth>32:raise ValueError('depth')
    r.update(relation='child_of_owned_target',child_depth=depth)
   else:r['relation']='outside_owned_target'
 except ValueError:pass
 return validate(r)
def validate(r):
 if type(r)is not dict or set(r)!=set(blank()) or r['relation']not in RELATIONS or r['filesystem_containment_proven']is not False:raise ValueError('relation_schema')
 for k in ('returned_absolute','returned_dot_segments'):
  if r[k]is not None and type(r[k])is not bool:raise ValueError('relation_bool')
 d=r['child_depth'];rel=r['relation']
 if d is not None and(type(d)is not int or not 0<=d<=32):raise ValueError('relation_depth')
 if rel in {'exact_string','normalized_equal'} and d!=0:raise ValueError('equal_depth')
 if rel=='child_of_owned_target' and(type(d)is not int or not 1<=d<=32):raise ValueError('child_depth')
 if rel in {'not_observed','invalid_path','outside_owned_target'} and d is not None:raise ValueError('no_depth')
 if rel not in {'not_observed','invalid_path'} and (r['returned_absolute']is not True or type(r['returned_dot_segments'])is not bool):raise ValueError('absolute')
 if rel=='not_observed' and r!=blank():raise ValueError('not_observed')
 return r
