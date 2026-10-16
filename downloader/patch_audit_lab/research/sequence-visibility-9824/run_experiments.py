"""Offline sequence visibility experiment with original fragments and mocked I/O.
No game or Lab operations. Optional cycle-store is a READ-ONLY previous owned fixture.
"""
import argparse,hashlib,json,random,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
import agent_sequence_visibility as m
import patch_audit as a
import retail_storage_poc as safety
import retail_update_cycle as cycle
import source_binding as b

def run(oracle,out,cycle_store=None,cycle_native=None):
    out=safety.safe_new(out);oracle=b.safe(oracle,True)
    a.require((cycle_store is None)==(cycle_native is None),'visibility_pair_optional_cycle_inputs')
    out.mkdir();rng=random.Random(982471);digest=hashlib.sha256();total=0
    for op in range(3):
        for mode in range(6):
            for bucket in range(16):
                for cached,header in ((1,1),(1,2),(2,1),(0,0xffffffff),(0xffffffff,0)):
                    inputs=dict(operation=op,mode=mode,bucket=bucket,cached=cached,header=header,count=rng.randrange(2),**{k:rng.choice([0,0,0,73,0xffffffff]) for k in ('temp_error','serialize_error','flush_error','bind_error','open_error')})
                    row=m.compare(oracle,**inputs);digest.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n');total+=1
    explicit={}
    for name,kwargs in {
        'writer_success':{'operation':0,'header':1},
        'writer_temp_error':{'operation':0,'header':1,'temp_error':73},
        'writer_serialize_error':{'operation':0,'header':1,'serialize_error':73},
        'writer_flush_error':{'operation':0,'header':1,'flush_error':73},
        'writer_bind_error_cache_ahead_header_old':{'operation':0,'header':1,'bind_error':73},
        'reader_cache_ahead_of_header':{'header':1,'cached':2},
        'reader_fresh_cache_opens_old_header':{'header':1,'cached':0},
        'reader_success':{},
        'reader_open_error':{'open_error':73},
        'reader_bind_error_zero_return':{'bind_error':73},
        'reader_bind_error_second_call_no_retry':{'operation':2,'bind_error':73},
        'reader_equal_skips_even_with_injected_bind_error':{'header':2,'cached':2,'bind_error':73},
        'reader_mode_5_skips':{'mode':5,'bind_error':73},
        'reader_unsigned_max_cache_zero_header':{'cached':0xffffffff,'header':0},
        'reader_unsigned_zero_cache_max_header':{'cached':0,'header':0xffffffff},
    }.items():explicit[name]=m.compare(oracle,**kwargs)
    real=None
    if cycle_store is not None:
        cycle_store=b.safe(cycle_store);watch=b.Watch()
        for f in sorted(cycle_store.iterdir()):watch.file(f)
        real=cycle.native_status(cycle_store,cycle_native/'cycle_oracle',cycle_native/'real_object_oracle');watch.check()
        a.require(real['source']['decoded_ckey_verified'] and real['target']['decoded_ckey_verified'],'visibility_real_readback')
        real={'existing_cycle_read_only':True,'file_identities_unchanged':True,'native_readback':real,'bind_mock_error_is_not_a_real_file_or_windows_error':True,'note':'Separate evidence: this real fixture readback is NOT performed by the mocked Agent helpers.'}
    report={'format':'agent-sequence-visibility-experiment-1','matrix':{'vectors':total,'all_model_original_fragment_matches':True,'observations_sha256':digest.hexdigest(),'random_seed':982471,'scope':'operations0/1/2, modes0..5, buckets0..15, 5 unsigned sequence order pairs, controlled helper codes'},'explicit_cases':explicit,'real_retail_cycle_crosscheck':real,'key_observation':'Under nonthrowing mocked helpers, reader open-success plus bind-error updates cache yet returns zero; an immediate second refresh skips opening/binding. Writer bind-error returns error and leaves header unchanged, but also advances cache.','interpretation':'Raw zero return and sequence equality alone are not proof of successful binding. Higher-level production error handling and reachability are not established.','original_fragments_executed':4,'external_helpers_mocked':True,'windows_agent_process_executed':False,'windows_apis_executed':False,'file_io_by_agent_helpers_executed':False,'exceptions_or_seh_executed':False,'process_shared_locking_proven':False,'power_loss_proven':False,'full_profile_activation':False,'installation_ready':False,'game_or_lab_written':False,'network_requests':0}
    (out/'EXPERIMENT-RESULTS.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('oracle','out-new'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('cycle-store','cycle-native'):p.add_argument('--'+name,type=Path)
    x=p.parse_args();r=run(x.oracle,x.out_new,x.cycle_store,x.cycle_native);print(json.dumps({'matrix_vectors':r['matrix']['vectors'],'all_matched':True,'explicit_cases':len(r['explicit_cases']),'installation_ready':False}))
