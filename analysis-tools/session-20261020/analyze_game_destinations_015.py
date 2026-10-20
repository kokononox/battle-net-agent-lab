from pathlib import Path
import json
import pandas as pd
raw=Path('/data/raw/game-destinations-015.json')
p=json.loads(raw.read_text());o=p['observation'];rows=o['tcp_destinations']
f=pd.DataFrame(rows);f.to_json('/data/analysis/game-destination-rows-015.jsonl',orient='records',lines=True)
pub=f[f.is_public_ip];wow_indices={r['index'] for r in o['processes'] if r['name']=='wow.exe'};agent_indices={r['index'] for r in o['processes'] if r['name']=='agent.exe'}
e={'source':'session-file://6706aa5f-13a0-4b22-859d-7390c705f0bd','status':p['status'],'error':p['error_code'],
'processes':o['processes'],'sampler_errors':p['sampler_errors'],'identity_read_errors':o['identity_read_errors'],'limit_hit':o['limits_hit'],
'flow_row_count':len(f),'public_flow_rows':len(pub),'loopback_flow_rows':int(f.is_loopback.sum()),
'public_unique_ip_count':pub.remote_address.nunique(),'public_unique_endpoints':pub[['remote_address','remote_port']].drop_duplicates().to_dict('records'),
'public_endpoints_detail':[{'process_index':int(r.process_index),'ip':r.remote_address,'port':int(r.remote_port),'states':r.tcp_states} for r in pub.itertuples()],
'public_established_flow_rows':sum('Established' in a for a in pub.tcp_states),
'wow_public_established_flow_rows':sum(r.process_index in wow_indices and 'Established' in r.tcp_states for r in pub.itertuples()),
'agent_public_established_flow_rows':sum(r.process_index in agent_indices and 'Established' in r.tcp_states for r in pub.itertuples()),
'wow_public_flow_rows':int(pub.process_index.isin(wow_indices).sum()),'agent_public_flow_rows':int(pub.process_index.isin(agent_indices).sum()),
'comparison_plan':[{'grain':'sampled process/IP/port TCP tuple','population':'chosen EXE and observed descendants only','unit':'connection metadata','disposition':'prose','reason':'diagnostic connectivity result; no throughput or content measurement; no meaningful chart'}]}
# Independent direct raw checks avoid treating sampler observations as counts of connections.
assert e['public_flow_rows']==len([r for r in rows if r['is_public_ip']])
assert e['public_established_flow_rows']==len([r for r in rows if r['is_public_ip'] and 'Established' in r['tcp_states']])
assert e['loopback_flow_rows']==len([r for r in rows if r['is_loopback']])
assert len(rows)==len({(r['process_index'],r['remote_address'],r['remote_port']) for r in rows})
Path('/data/analysis/game-destinations-015-evidence.json').write_text(json.dumps(e,indent=2))
print(json.dumps(e,indent=2))
