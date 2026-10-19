import datetime,hashlib,json
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parent;SOURCE=Path('/data/raw/n1-user/inventory.json')

def main():
    d=json.loads(SOURCE.read_text());i=d['inventory'];ps={p['index']:p for p in i['processes']};ms={m['index']:m for m in i['module_files']}
    assert d['schema']=='n1-network-library-inventory-1' and d['status']=='window_ended' and d['error_code'] is None
    assert len(ps)==len(i['processes']) and len(ms)==len(i['module_files'])
    assert all(set(p['module_file_indices'])<=set(ms) for p in ps.values())
    tcp=i['public_tcp_destinations'];https=[c for c in tcp if c['remote_port']==443]
    owners=sorted({c['process_index'] for c in https})
    evidence_owners=[]
    for index in owners:
        p=ps[index];modules=[ms[k] for k in p['module_file_indices']];cef=[m for m in modules if m['category']=='libcef.dll']
        assert p['status']=='verified' and p['authenticode_valid'] and p['blizzard_publisher']
        assert len(cef)==1
        m=cef[0];assert m['pe']['status']=='parsed' and not m['pe']['table_limit_hit']
        assert not {'SSL_write','SSL_write_ex'} & set(m['pe']['exported_api_hints'])
        evidence_owners.append({'process_index':index,'process_name':p['process_name'],'pid':p['pid'],'parent_pid':p['parent_pid'],
            'image_sha256':p['sha256'],'status':p['status'],'module_statuses':p['module_statuses'],
            'loaded_known_modules':sorted(m['category'] for m in modules),'cef_file_sha256':m['sha256'],'cef_file_bytes':m['file_bytes'],
            'cef_exports':m['pe']['exported_api_hints'],'cef_imports':m['pe']['imported_api_hints'],
            'cef_import_libraries':m['pe']['imported_library_categories'],'cef_delay_imports_present':m['pe']['delay_imports_present'],
            'cef_ssl_write_export_present':False,'tls_engine_actually_used_proven':False,
            'public_tcp_destinations':[c for c in https if c['process_index']==index]})
    # Independent headline path: walk raw TCP owners -> raw per-process module refs.
    seen=set()
    for c in d['inventory']['public_tcp_destinations']:
        if c['remote_port']!=443:continue
        p=next(p for p in d['inventory']['processes'] if p['index']==c['process_index'])
        rawmods=[m for m in d['inventory']['module_files'] if m['index'] in p['module_file_indices']]
        assert any(m['category']=='libcef.dll' for m in rawmods)
        seen.add((c['process_index'],c['remote_address'],c['remote_port']))
    assert len(seen)==3 and owners==[5]
    assert all(m['pe']['status']=='parsed' and not m['pe']['table_limit_hit'] for m in ms.values())
    e={'schema':'n1-user-inventory-analysis-1','input_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
       'provenance':'user-uploaded report, not independently signed','started_utc':d['started_utc'],'ended_utc':d['ended_utc'],
       'elapsed_seconds':(datetime.datetime.fromisoformat(d['ended_utc'])-datetime.datetime.fromisoformat(d['started_utc'])).total_seconds(),
       'status':d['status'],'error_code':d['error_code'],'sampling_errors':i['sampling_errors'],'sample_count':i['sample_count'],
       'limit_hit':i['limit_hit'],'process_count':len(ps),'process_name_counts':dict(Counter(p['process_name'] for p in ps.values())),
       'process_status_counts':dict(Counter(p['status'] for p in ps.values())),
       'module_files':len(ms),'pe_status_counts':dict(Counter(m['pe']['status'] for m in ms.values())),
       'https_distinct_process_address_port_tuples':len(seen),'https_owners':evidence_owners,
       'pause_condition':'user confirmed via N1 prompt and conversation, not an independent Battle.net UI measurement',
       'payloads_keys_or_hooks_used':False,'new_download_requested':False,
       'traffic_contents_observed':False,'boringssl_confirmed':False,'no_personal_upload_proven':False,
       'next_step':'route-only API call counters with caller-module classification, before choosing a pre-TLS interception point; not another identical inventory or a new block profile',
       'limits':['Module/import/export presence does not prove calls or identify actual TLS engine.',
          'No SSL_write exported by this parsed file does not exclude statically linked or dynamically resolved TLS.',
          'Delay imports were present and not inspected; UDP/QUIC not sampled.',
          'IP changes from the preceding run are not an A/B privacy improvement or hostname proof.',
          'sample_observations aggregates matching TCP rows across snapshots; may exceed sample_count because concurrent connections share a remote tuple. It is not request/byte count.',
          'No command lines or arbitrary module names/full paths were exported; process roles beyond observed TCP ownership are not established.'],
       'profile_note':'13 distinct module-file records; no duplicates. Constant parsed/status and false limit columns are expected findings, no rows dropped.',
       'presentation':{'disposition':'prose','reason':'categorical diagnostic evidence chain, not a meaningful plotted comparison'}}
    (ROOT/'evidence.json').write_text(json.dumps(e,indent=2)+'\n')
    print(json.dumps({k:e[k] for k in ('sampling_errors','sample_count','process_count','module_files','https_distinct_process_address_port_tuples','boringssl_confirmed')}))
    print('HTTPS owner known modules:',evidence_owners[0]['loaded_known_modules'])
if __name__=='__main__':main()
