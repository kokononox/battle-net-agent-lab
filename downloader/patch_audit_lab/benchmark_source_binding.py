"""Optional synthetic metadata-scale test. Not a user game proof or real scan.

Uses real pinned PA metadata and generated prior DB rows. No network; no archive
payload read. Temp databases are removed after the test, report only is retained.
"""
import argparse,json,sqlite3,tempfile,time,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent/'tests'))
from test_source_binding import Fixture
import source_binding as b

def run(output,plan_rows=2881619,candidate_rows=1531167):
    output=Path(output).absolute();b.safe(output.parent);b.need(not output.exists(),'new_output_required');output.mkdir()
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='patch-binding-scale-',dir=output) as tmp:
        root=Path(tmp);audit=Path(__file__).parent/'pinned_metadata'
        options,_,_=b.load_metadata(audit,b.Watch());option=options[0]
        f=Fixture(root,option)
        target_sizes={o.target_ckey:o.target_size for o in options}
        con=sqlite3.connect(f.plan)
        con.executemany('INSERT INTO plan VALUES (?,?,?,?,?,?)',[(b'\xfd'*8+i.to_bytes(8,'big'),bytes.fromhex(k),8,v,'mapped',1)
             for i,(k,v) in enumerate(target_sizes.items()) if k!=option.target_ckey])
        have=con.execute('SELECT COUNT(*) FROM plan').fetchone()[0]
        for i in range(0,plan_rows-have,4096):
            con.executemany('INSERT INTO plan VALUES (?,?,?,?,?,?)',[(b'\xfe'*8+j.to_bytes(8,'big'),b'\xfc'*8+j.to_bytes(8,'big'),8,4,'mapped',1)
                for j in range(i,min(i+4096,plan_rows-have))])
        con.commit();con.close()
        con=sqlite3.connect(f.inv)
        for i in range(2,candidate_rows+1,4096):
            con.executemany('INSERT INTO candidates VALUES (?,?,0,0,4,?,3)',[(j,b'\xfe'*8+j.to_bytes(8,'big'),b'\xfc'*8+j.to_bytes(8,'big'))
                for j in range(i,min(i+4096,candidate_rows+1))])
        con.commit();con.close()
        con=sqlite3.connect(f.ev)
        for i in range(2,candidate_rows+1,4096):
            con.executemany('INSERT INTO evidence VALUES (?, ?,\'casc_span\',\'unsupported_or_encrypted_content\',0,0,0,?)',[(j,b'\xfe'*8+j.to_bytes(8,'big'),str(f.archive))
                for j in range(i,min(i+4096,candidate_rows+1))])
        con.commit();con.close();f.refresh()
        setup=time.monotonic()-started
        report,private=b.bind(f.lab,audit,time_limit=180)
        bound=report['options_by_state'].get('prior_full_source_proof_bound_reverification_required',0)
        b.need(bound>=1 and sum(report['options_by_state'].values())==len(options),'scale_reconciliation')
        result={'status':'synthetic_metadata_scale_passed','real_user_lab_tested':False,
                'real_game_content_verified':False,'input_type':'real PA metadata plus generated prior-proof rows; not actual source-content proofs',
                'plan_rows':plan_rows,'candidate_rows':candidate_rows,'evidence_rows':candidate_rows,
                'generated_database_setup_seconds':round(setup,3),'binding_seconds':report['elapsed_seconds'],
                'all_real_pa_options_accounted_for':True,'report':report,'private_plan_not_published':True}
    (output/'SOURCE-BINDING-SCALE-RESULTS.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('status','plan_rows','candidate_rows','binding_seconds','real_user_lab_tested')}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True)
    p.add_argument('--plan-rows',type=int,default=2881619);p.add_argument('--candidates',type=int,default=1531167)
    args=p.parse_args();run(args.output,args.plan_rows,args.candidates)
