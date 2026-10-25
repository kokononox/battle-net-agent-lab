"""Research-only fetch of three public content-keyed configs. Not a runtime catalog."""
import hashlib,json,re,urllib.parse
from pathlib import Path
from discover import BASE,RAW,OUT,HOSTS,request
HOST='us.cdn.blizzard.com' # Explicitly reviewed HTTPS entry from public US cdns row.
def key(value):
 if not re.fullmatch('[a-f0-9]{32}',value):raise ValueError('content_key_rejected')
 return value

def main():
 d=json.loads((OUT/'discovery.json').read_text());v=d['parsed']['v1-versions']['rows'];c=d['parsed']['v1-cdns']['rows']
 vr=[r for r in v if r['Region']=='us'];cr=[r for r in c if r['Name']=='us']
 if len(vr)!=1 or len(cr)!=1:raise ValueError('region_ambiguous')
 v,c=vr[0],cr[0]
 advertised=[urllib.parse.urlsplit(s) for s in c['Servers'].split()]
 if not any(p.scheme=='https' and p.hostname==HOST and p.port in (None,443) and p.path=='/' and not p.username and not p.password and not p.fragment for p in advertised):raise ValueError('https_server_not_advertised')
 for name in ('Path','ConfigPath'):
  if not re.fullmatch(r'tpr/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*',c[name]):raise ValueError('cdn_path_rejected')
 HOSTS.add(HOST) # This local research process only; product/firewall catalog untouched.
 rows=[]
 for label,field in [('build','BuildConfig'),('cdn','CDNConfig'),('product','ProductConfig')]:
  k=key(v[field]);prefix=c['ConfigPath'] if label=='product' else c['Path']+'/config'
  url='https://'+HOST+'/'+prefix+'/'+k[:2]+'/'+k[2:4]+'/'+k
  r,b=request(url,'bna-us-'+label+'-config',1048576);r.update(kind=label,content_key=k,runtime_approved=False)
  if b is not None:
   r['content_key_md5_matches']=hashlib.md5(b).hexdigest()==k
   if not r['content_key_md5_matches']:r.update(accepted=False,error_code='content_key_mismatch')
   else:
    text=b.decode('utf-8','strict')
    if label=='product':r['parsed']=json.loads(text)
    else:
     values={}
     for line in text.splitlines():
      if not line or line.startswith('#'):continue
      if ' = ' not in line:raise ValueError('config_line_rejected')
      name,value=line.split(' = ',1)
      if not re.fullmatch('[a-z0-9-]{1,80}',name) or name in values:raise ValueError('config_key_rejected')
      values[name]=value
     r['parsed']=values
  rows.append(r)
 e={'schema':'public_configs_g43_v1','region':'us','product':'bna','version':v['VersionsName'],'build_id':v['BuildId'],'server_advertised_https':True,'cdn_server_query_forwarded':False,'requests':rows,'installer_executed':False,'payload_downloaded':False,'production_catalog_modified':False,'catalog_entries_approved':0,'content_key_md5_is_not_publisher_signature':True}
 (OUT/'configs.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'version':e['version'],'requests':[{'kind':r['kind'],'accepted':r['accepted'],'bytes':r.get('bytes'),'content_key_md5_matches':r.get('content_key_md5_matches')} for r in rows]}))
if __name__=='__main__':main()
