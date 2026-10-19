import hashlib,json,socket,sys,tempfile
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parent
SOURCE=Path('/data/raw/t1-dns/user-diagnostic.json')
sys.path.insert(0,'/data/level3-request-audit-t1/app')
from request_audit import BLOCKED,TARGET
from profile_gate import resolution_probe,check_profile,NO_DATA_WITH_EXPLICIT_SINK

def main():
    d=json.loads(SOURCE.read_text());rows=d['rows'];by={r['host']:r for r in rows}
    assert len(rows)==25 and len(by)==25 and set(by)==set((*BLOCKED,TARGET))
    blocked=[by[h] for h in BLOCKED];target=by[TARGET]
    assert all(r['hosts_addresses']==['0.0.0.0'] and r['resolver_state']=='resolution_failed' and r['error_code']==11004 and not r['resolved_addresses'] for r in blocked)
    assert target['resolver_state']=='public_only' and target['matches_t1_requirement'] and not target['hosts_addresses']
    # Independent raw predicates, not derived from failed_hosts or prior boolean.
    independent=sum(r['host']!=TARGET and r['hosts_addresses']==['0.0.0.0'] and r['error_code']==11004 for r in rows)
    assert independent==24 and len(d['failed_hosts'])==24
    text=''.join(address+' '+r['host']+'\n' for r in rows for address in r['hosts_addresses'])
    def replay(h,*args):
        r=by[h]
        if r['error_code'] is not None:raise socket.gaierror(r['error_code'],'recorded_user_error')
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(address,0)) for address in r['resolved_addresses']]
    with tempfile.TemporaryDirectory() as t:
        p=Path(t)/'hosts';p.write_text(text);before=p.read_bytes();states=resolution_probe(BLOCKED,TARGET,p,replay,'win32')
        assert check_profile(states,BLOCKED,TARGET) and p.read_bytes()==before
    evidence={'schema':'t1-dns-stop-analysis-1','input_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'source_created_utc':d['created_utc'],'grain':'one fixed hostname per row','rows':len(rows),
        'blocked_rows':len(blocked),'blocked_explicit_zero_and_11004':independent,
        'original_failed_hosts':len(d['failed_hosts']),'target':TARGET,'target_public_addresses':target['resolved_addresses'],
        'target_had_hosts_override':bool(target['hosts_addresses']),'original_gate_passed':d['t1_profile_confirmed'],
        'corrected_gate_report_replay_passed':check_profile(states,BLOCKED,TARGET),
        'corrected_gate_state_counts':dict(Counter(states.values())),
        'real_windows_rerun_yet':False,'actual_network_enforcement_proven':False,'user_content_observed':False,
        'profile_note':'Nested diagnostic JSON is not a rectangular dataframe; profile_data was rerun on 25 derived rows. Numeric error-code null is expected for the successful target; no rows excluded.',
        'presentation':{'disposition':'prose','reason':'diagnostic branch evidence, not a time series or meaningful plotted comparison'}}
    (ROOT/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({k:evidence[k] for k in ('rows','blocked_explicit_zero_and_11004','original_gate_passed','corrected_gate_report_replay_passed','corrected_gate_state_counts')}))
if __name__=='__main__':main()
