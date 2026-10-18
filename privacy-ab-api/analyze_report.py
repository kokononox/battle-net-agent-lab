"""H1 deterministic diagnostic comparison, no causal/all-traffic privacy claims."""
import base64
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys

MODES=('baseline','block_telemetry')
TARGET='telemetry-in.battle.net'
def analyze(raw,out):
    out.mkdir(parents=True,exist_ok=True)
    result={'experiment':'startup-ab-api-h1','arms':{},'checks':{},'limitations':[
        'One fresh VM per arm; shared source/window/image does not make hardware/IP/timing identical.',
        'Startup language only, not full client/game/update compatibility.',
        'SSPI success is local encryption, not successful network delivery/server storage.',
        'No TLS plaintext for HTTP/2/OpenSSL/QUIC or uninstrumented processes.',
        'Bounded capture, socket async completion, context reuse and concurrency can hide or misorder data.',
        'Sampled TCP tuples can miss short connections; DNS candidates are not request destinations.',
        'A host present only in block arm is not by itself proof of telemetry fallback.',
        'Absence of the CPU literal is not absence of compressed/encoded or other system data.',
        'Game-file fingerprints and A-to-B transfer remain untested.'],
        'profiling':{'raw_shape':'Nested protocol report with different-grain arrays, not one rectangular row set.',
            'normalization':'One row per reconstructed request; composite key (mode,index).',
            'warnings_resolved':['Flat profiler cannot directly read unequal-length nested JSON arrays; normalize request table instead.',
                'body_complete is constant True in these samples, not a whole-network coverage claim.',
                'cpu_literal_in_target_headers is constant False; CPU match occurs in body only.',
                'No duplicate normalized rows; PID alone is not a cross-VM join key.']},
        'comparison_plan':[{'grain':'one fresh startup VM per arm','population':'bounded signed root-child process inputs and sampled network connections',
            'unit':'diagnostic presence/absence and coverage','disposition':'table',
            'reason':'Gate and visibility comparison, not a traffic-volume effect or rate estimate; plots would encourage unsupported interpretation.'}]}
    csvrows=[]
    all_raw=[]
    for mode in MODES:
        prefix=raw/f'startup-ab-api-h1-{mode}'
        paths={k:Path(str(prefix)+'-'+k+'.json') for k in ('intervention','api','network','bootstrap')}
        records={k:json.loads(p.read_text()) for k,p in paths.items() if p.exists()}
        all_raw.extend(p for p in paths.values() if p.exists())
        intervention=records.get('intervention',{});api=records.get('api',{});net=records.get('network',{})
        req=api.get('requests',[]);cpu=api.get('reference',{}).get('cpu_model');needle=cpu.encode('ascii') if cpu else None
        byhost=Counter(r['host'] for r in req)
        cpu_requests=[]
        for i,r in enumerate(req):
            body=base64.b64decode(r['body_sample_base64'],validate=True)
            assert hashlib.sha256(body).hexdigest()==r['body_sample_sha256']
            channel='pre_tls_sspi' if r['socket'].startswith('ctx') else 'winsock_http'
            cpu_body=needle in body if needle else None
            cpu_header=cpu in (r['target']+str(r['headers'])) if cpu else None
            if cpu_body or cpu_header:
                cpu_requests.append({'index':i,'pid':r['pid'],'process_sha256':r['process_sha256'],'host':r['host'],'method':r['method'],'target':r['target'],'channel':channel,'body_complete':r['body_complete'],'body_match':cpu_body,'headers_or_target_match':cpu_header})
            csvrows.append(dict(mode=mode,index=i,pid=r['pid'],process_sha256=r['process_sha256'],channel=channel,host=r['host'],method=r['method'],target=r['target'],body_complete=r['body_complete'],body_observed_bytes=r['body_observed_bytes'],cpu_literal_in_body=cpu_body,cpu_literal_in_target_headers=cpu_header))
        tls=api.get('tls_inputs',[]);success=[x for x in tls if x['return_code']==0]
        rows=api.get('processes',[])
        arm={
            'raw_files':{k:{'name':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for k,p in paths.items() if p.exists()},
            'source_commit':intervention.get('source_commit'),'run_id':intervention.get('run_id'),
            'runner_image_version':intervention.get('runner_image_version'),'windows_build':intervention.get('windows_build'),
            'intervention':{k:intervention.get(k) for k in ('launch_precondition_passed','hosts_changed','hosts_restored','resolution_before','resolution_at_launch','pin_match','outcome','error_code')},
            'observation_status':api.get('status'),'observation_error':api.get('error_code'),
            'selftest_passed':api.get('selftest',{}).get('passed') if api.get('selftest') else None,
            'sspi_fixture_passed':api.get('selftest',{}).get('sspi_negative_input_observed') if api.get('selftest') else None,
            'reference_cpu':cpu,'bootstrap_pin_match':api.get('bootstrap_pin_match'),
            'processes':rows,'all_live_rows_resumed':bool(rows) and all(x['status']=='resumed' for x in rows),
            'process_hashes_by_name':{name:sorted({x['sha256'] for x in rows if x['process_name']==name}) for name in sorted({x['process_name'] for x in rows if x['process_name']})},
            'input_events':api.get('input_events'),'dropped_events':api.get('dropped_events'),'fatal':api.get('fatal'),
            'script_errors':sum(x['script_errors'] for x in rows),'stream_gaps':sum(x['api_input_gap'] for x in api.get('streams',[])),
            'request_count':len(req),'complete_body_request_count':sum(x['body_complete'] for x in req),
            'requests_by_host':dict(sorted(byhost.items())),
            'requests_by_channel':dict(Counter('pre_tls_sspi' if x['socket'].startswith('ctx') else 'winsock_http' for x in req)),
            'cpu_literal_requests':cpu_requests,'tls_input_events':len(tls),'tls_local_success_events':len(success),
            'tls_success_with_reference_cpu_literal':sum(x['reference_cpu_literal_present'] is True for x in success),
            'tls_failed_with_reference_cpu_literal':sum(x['reference_cpu_literal_present'] is True and x['return_code']!=0 for x in tls),
            'network_parse_status':net.get('capture',{}).get('parse_status'),
            'network_sampler':net.get('sampler'),
            'telemetry_sni_flow_records':sum(x.get('tls_sni')==TARGET for x in net.get('flows',[])),
            'prior_telemetry_ip_flow_records':sum(x.get('address') in intervention.get('target_public_addresses_before',[]) for x in net.get('flows',[])),
            'observed_network_hosts':sorted({x[k] for x in net.get('flows',[]) for k in ('tls_sni','http_host') if x.get(k)}),
            'bootstrap_status':records.get('bootstrap',{}).get('status'),
            'last_gui_observation_elapsed_seconds':max((x['elapsed_seconds'] for x in records.get('bootstrap',{}).get('gui_observations',[])),default=None),
            'language_step':records.get('bootstrap',{}).get('language_step',{}).get('status'),
            'install_step':records.get('bootstrap',{}).get('install_step',{}).get('status'),
        }
        # Independent path: direct filtering, not the host Counter or derived CPU-event list.
        direct_telemetry=sum(1 for x in api.get('requests',[]) if x.get('host')==TARGET)
        assert direct_telemetry==byhost.get(TARGET,0)
        assert len(cpu_requests)==sum(1 for x in req if cpu and (cpu in str(x['headers']) or cpu in x['target'] or needle in base64.b64decode(x['body_sample_base64'])))
        assert sum(byhost.values())==len(req)
        result['arms'][mode]=arm
    a,b=(result['arms'][m] for m in MODES)
    result['checks']={
        'same_source':a['source_commit']==b['source_commit'],
        'same_run':a['run_id']==b['run_id'],
        'same_runner_image':a['runner_image_version'] is not None and a['runner_image_version']==b['runner_image_version'],
        'same_windows_build':a['windows_build']==b['windows_build'],
        'same_cpu_model':a['reference_cpu']==b['reference_cpu'],
        'same_observed_image_sets':a['process_hashes_by_name']==b['process_hashes_by_name'],
        'independent_counts_verified':True,
        'requests_hosts_only_in_block':sorted(set(b['requests_by_host'])-set(a['requests_by_host'])),
        'network_hosts_only_in_block':sorted(set(b['observed_network_hosts'])-set(a['observed_network_hosts'])),
    }
    with (out/'requests.csv').open('w') as f:
        fields=list(csvrows[0]) if csvrows else ['mode','index','pid','process_sha256','channel','host','method','target','body_complete','body_observed_bytes','cpu_literal_in_body','cpu_literal_in_target_headers']
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();writer.writerows(csvrows)
    (out/'evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'checks':result['checks'],'arms':{m:{k:r[k] for k in ('observation_status','selftest_passed','sspi_fixture_passed','request_count','requests_by_host','requests_by_channel','tls_input_events','tls_local_success_events','tls_success_with_reference_cpu_literal','telemetry_sni_flow_records','network_parse_status','dropped_events','fatal')} for m,r in result['arms'].items()}},indent=2))
if __name__=='__main__':analyze(Path(sys.argv[1]),Path(sys.argv[2]))
