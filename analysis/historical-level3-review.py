import collections,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent
files={'G1':'/data/raw/startup-api-g1.json','H1-baseline':'/data/raw/startup-ab-api-h1-baseline-api.json','H1-blocked':'/data/raw/startup-ab-api-h1-block_telemetry-api.json'}
rows=[]
for name,path in files.items():
    p=Path(path);d=json.loads(p.read_text());rs=[r for r in d['requests'] if r.get('host')=='level3.blizzard.com']
    rows.append({'sample':name,'input_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'run_id':d['run_id'],'source_commit':d['source_commit'],
        'target_requests':len(rs),'methods':dict(collections.Counter(r['method'] for r in rs)),
        'nonzero_bodies':sum(r['body_observed_bytes']>0 for r in rs),'query_present':sum('?' in r['target'] for r in rs),
        'all_bodies_complete':all(r['body_complete'] for r in rs),'all_paths_tpr':all(r['target'].split('?',1)[0].startswith('/tpr/') for r in rs),
        'header_names':sorted({k for r in rs for k,v in r['headers']}),
        'unknown_headers':sorted({k for r in rs for k,v in r['headers']}-{'host','user-agent','range','accept','connection'})})
out={'schema':'historical-level3-review-1','scope':'old_disposable_vm_startup_not_user_wow_update','rows':rows,'total_target_requests':sum(x['target_requests'] for x in rows),
     'personal_information_absence_proven':False,'server_receipt_proven':False,'user_agent_values_exported':False,'user_bat06_content_tested':False}
(ROOT/'evidence.json').write_text(json.dumps(out,indent=2)+'\n')
assert [r['target_requests'] for r in rows]==[54,49,34]
assert out['total_target_requests']==137
assert all(not r['nonzero_bodies'] and not r['query_present'] and r['all_bodies_complete'] and r['all_paths_tpr'] for r in rows)
print(json.dumps({'sample_counts':[r['target_requests'] for r in rows],'target_requests':out['total_target_requests'],'all_GET':all(r['methods']=={'GET':r['target_requests']} for r in rows),'nonzero_body_or_query':any(r['nonzero_bodies'] or r['query_present'] for r in rows)}))
