"""Bounded API-shape diagnostics: fixed field names/codes, never raw text/URLs."""
FIELDS={'error','errors','code','error_code','errorCode','errorcode','message','msg','error_message','errorMessage','error_msg','errorText','error_text','status','result','success','succeeded','failure','failed','data','response','operation','operation_id','operationId','task','task_id','taskId','job','job_id','jobId','id','request_id','requestId','link','links','_links','url','location','resource','path','name','type','uid','game','form','state','action','async','description','reason','text','status_code','statusCode','error_count','errorCount','error_string','errorString'}
CODES={'error','code','error_code','errorCode','errorcode','status_code','statusCode','error_count','errorCount'}
TEXT={'message','msg','error_message','errorMessage','error_msg','errorText','error_text','description','reason','text','error_string','errorString'}
MARKERS={'authentication':('auth','login','log in','account'), 'legal':('eula','terms','consent','agreement'), 'license':('license','entitlement','licence'), 'space':('disk','space'), 'request':('request','argument','parameter','invalid'), 'failure':('fail','error','denied','refused'), 'success':('success','accepted','queued')}
TYPES={'object','array','string','boolean','number','null'}

def blank():return dict(observed=False,recognized_top_fields=[],unknown_top_fields=0,nodes=[],message_markers=[])
def validate(r):
 if type(r)is not dict or set(r)!=set(blank()) or type(r['observed'])is not bool:raise ValueError('diagnostic_schema')
 if type(r['recognized_top_fields'])is not list or len(set(r['recognized_top_fields']))!=len(r['recognized_top_fields']) or any(type(x)is not str or x not in FIELDS for x in r['recognized_top_fields']):raise ValueError('diagnostic_fields')
 if type(r['unknown_top_fields'])is not int or not 0<=r['unknown_top_fields']<=128:raise ValueError('diagnostic_count')
 if type(r['message_markers'])is not list or len(set(r['message_markers']))!=len(r['message_markers']) or any(type(x)is not str or x not in MARKERS for x in r['message_markers']):raise ValueError('diagnostic_markers')
 if type(r['nodes'])is not list or len(r['nodes'])!=len(r['recognized_top_fields']):raise ValueError('diagnostic_nodes')
 for n in r['nodes']:
  if type(n)is not dict or set(n)!={'field','type','length','numeric_code'} or n['field']not in FIELDS or n['type']not in TYPES:raise ValueError('diagnostic_node')
  if n['length']is not None and(type(n['length'])is not int or not 0<=n['length']<=65536):raise ValueError('diagnostic_length')
  if n['numeric_code']is not None and(n['field']not in CODES or type(n['numeric_code'])is not int or not 0<=n['numeric_code']<=2**32):raise ValueError('diagnostic_code')
 if sorted(n['field']for n in r['nodes'])!=sorted(r['recognized_top_fields']):raise ValueError('diagnostic_node_identity')
 if not r['observed'] and (r['recognized_top_fields'] or r['unknown_top_fields'] or r['nodes'] or r['message_markers']):raise ValueError('diagnostic_not_observed')
 return r

def describe(data):
 r=blank()
 if type(data)is not dict or len(data)>128:return r
 r['observed']=True;r['recognized_top_fields']=sorted(set(data)&FIELDS);r['unknown_top_fields']=len(set(data)-FIELDS)
 markers=set()
 for name in r['recognized_top_fields']:
  v=data[name];kind={dict:'object',list:'array',str:'string',bool:'boolean',int:'number',float:'number',type(None):'null'}.get(type(v))
  if kind is None:raise ValueError('diagnostic_type')
  code=v if name in CODES and type(v)is int and 0<=v<=2**32 else None
  r['nodes'].append(dict(field=name,type=kind,length=len(v) if type(v)in (dict,list,str)else None,numeric_code=code))
  if name in TEXT and type(v)is str:
   lower=v.lower()
   markers|={tag for tag,words in MARKERS.items()if any(w in lower for w in words)}
 r['message_markers']=sorted(markers)
 return validate(r)
