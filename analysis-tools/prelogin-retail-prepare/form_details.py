"""Value-free bounded form structure; only fixed labels, locale enums and sizes."""
import re
LABELS={'authentication','game_dir','min_spec','language','eula','finalized','shortcut','tome_path','error','default','dirname','required_space','required_space_info','warning','list','speech','text','allow_arm_emulation','required_cpu_speed','required_os','required_ram','required_subversion','requires_64bit','locale','name','value','id','code','selected','available','display_name','asset','audio','size','install_size','download_size','url','link'}
LOCALES={'enUS','enGB','deDE','esES','esMX','frFR','itIT','koKR','ptBR','ptPT','ruRU','zhCN','zhTW','jaJP','plPL'}
TYPES={'null','boolean','number','string','object','array','other'}
def blank():return dict(status='not_observed',nodes=[],recognized_language_locales=[],language_unknown_string_count=0,required_space_bytes=None,eula_flag=None,eula_text_or_link_in_allowlisted_members=False,unknown_member_count=0)
def describe(form):
 r=blank();nodes=[];locales=set();unknown_strings=0;unknown_members=0
 def visit(v,path):
  nonlocal unknown_strings,unknown_members
  if len(path)>5 or len(nodes)>=128:raise ValueError('structure_limit')
  t={type(None):'null',bool:'boolean',int:'number',float:'number',str:'string',dict:'object',list:'array'}.get(type(v),'other')
  n=dict(path=path,type=t,count=None)
  if type(v)in(dict,list):
   if len(v)>64:raise ValueError('container_limit')
   n['count']=len(v)
  nodes.append(n)
  if path and path[0]=='language' and type(v)is str:
   if v in LOCALES:locales.add(v)
   else:unknown_strings+=1
  if type(v)is dict:
   for k,x in v.items():
    if k not in LABELS:unknown_members+=1;continue
    visit(x,path+[k])
  elif type(v)is list:
   for x in v:visit(x,path+['*'])
 try:
  if type(form)is not dict or len(form)>32:raise ValueError('form')
  for k,v in form.items():
   if k not in LABELS:unknown_members+=1;continue
   visit(v,[k])
  r.update(status='observed',nodes=nodes,recognized_language_locales=sorted(locales),language_unknown_string_count=unknown_strings,unknown_member_count=unknown_members)
  gd=form.get('game_dir',{});space=gd.get('required_space') if type(gd)is dict else None
  if type(space)is int and 0<=space<=2**50:r['required_space_bytes']=space
  eu=form.get('eula',{});flag=eu.get('eula') if type(eu)is dict else None
  if type(flag)is bool:r['eula_flag']=flag
  # Presence-only diagnostic; never exports or follows text/URLs.
  if type(eu)is dict:r['eula_text_or_link_in_allowlisted_members']=any(k in eu and type(eu[k])is str and bool(eu[k]) for k in ('text','name','value','url','link'))
 except ValueError:r=blank();r['status']='refused'
 return validate(r)
def validate(r):
 if type(r)is not dict or set(r)!=set(blank()) or r['status']not in {'not_observed','observed','refused'}:raise ValueError('details_schema')
 if type(r['nodes'])is not list or len(r['nodes'])>128:raise ValueError('nodes')
 for n in r['nodes']:
  if type(n)is not dict or set(n)!={'path','type','count'} or n['type']not in TYPES:raise ValueError('node')
  if type(n['path'])is not list or not 1<=len(n['path'])<=5 or any(type(x)is not str or x not in LABELS|{'*'} for x in n['path']):raise ValueError('path')
  if n['type']in {'object','array'}:
   if type(n['count'])is not int or not 0<=n['count']<=64:raise ValueError('node_count')
  elif n['count']is not None:raise ValueError('scalar_count')
 l=r['recognized_language_locales']
 if type(l)is not list or any(type(x)is not str or x not in LOCALES for x in l) or l!=sorted(set(l)):raise ValueError('locales')
 for k in ('language_unknown_string_count','unknown_member_count'):
  if type(r[k])is not int or not 0<=r[k]<=16384:raise ValueError('count')
 s=r['required_space_bytes']
 if s is not None and(type(s)is not int or not 0<=s<=2**50):raise ValueError('space')
 if r['eula_flag']is not None and type(r['eula_flag'])is not bool:raise ValueError('legal_flag')
 if type(r['eula_text_or_link_in_allowlisted_members'])is not bool:raise ValueError('legal_presence')
 if r['status']!='observed' and any(r[k]!=v for k,v in blank().items() if k!='status'):raise ValueError('unobserved')
 return r
