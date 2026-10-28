"""Recognize a local product link without publishing/following arbitrary URLs."""
FIELDS={'response_uri','error','form','game','link','uid','installed','download_complete'}
KINDS={'not_observed','form','canonical_game_link','unknown','product_state'}
def blank():return dict(kind='not_observed',recognized_top_fields=[],unknown_top_fields=0,owned_game_link=False)
def validate(r):
 if type(r)is not dict or set(r)!=set(blank()) or r['kind']not in KINDS:raise ValueError('shape_schema')
 if type(r['recognized_top_fields'])is not list or any(type(k)is not str or k not in FIELDS for k in r['recognized_top_fields']) or len(set(r['recognized_top_fields']))!=len(r['recognized_top_fields']):raise ValueError('shape_fields')
 if type(r['unknown_top_fields'])is not int or not 0<=r['unknown_top_fields']<=128 or type(r['owned_game_link'])is not bool:raise ValueError('shape_count')
 if r['kind']=='canonical_game_link' and(not r['owned_game_link'] or r['unknown_top_fields']):raise ValueError('shape_link')
 return r

def classify(data,port):
 r=blank();r['kind']='unknown'
 if type(data)is not dict or len(data)>128:return r
 r['recognized_top_fields']=sorted(set(data)&FIELDS);r['unknown_top_fields']=len(set(data)-FIELDS)
 if type(data.get('form'))is dict:r['kind']='form';return r
 if type(port)is not int or not 1<=port<=65535:return r
 allowed={'/game/wow','http://127.0.0.1:'+str(port)+'/game/wow'}
 # Public ProductEndpoint contract supplies response_uri. Unknown siblings remain unknown.
 if type(data.get('response_uri'))is str and data['response_uri']in allowed:r['owned_game_link']=True
 if r['unknown_top_fields']:return validate(r)
 if set(data)<={'response_uri','error'} and r['owned_game_link'] and ('error'not in data or type(data['error'])is int and data['error']==0):
  r['kind']='canonical_game_link';return validate(r)
 if 'error'in data and(type(data['error'])is not int or data['error']!=0):return r
 if 'uid'in data and data['uid']!='wow':return r
 if set(data)<= {'installed','download_complete','error'} and type(data.get('installed'))is bool and type(data.get('download_complete'))is bool:
  r['kind']='product_state';return validate(r)
 if set(data)<= {'game','error','uid'} and type(data.get('game'))is dict and set(data['game'])=={'link'}:link=data['game']['link']
 elif set(data)<= {'link','error','uid'}:link=data.get('link')
 else:return r
 allowed={'/game/wow','http://127.0.0.1:'+str(port)+'/game/wow'}
 if type(link)is str and link in allowed:r.update(kind='canonical_game_link',owned_game_link=True)
 return validate(r)
