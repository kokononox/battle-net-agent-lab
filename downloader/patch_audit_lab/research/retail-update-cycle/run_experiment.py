"""Offline one-object Retail update/resume experiment, fresh output only.
Run from patch_audit_lab. Never points at or updates an installation.
"""
import argparse,json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
import retail_update_cycle as c
import source_binding as b
import portable_run
import patch_audit as a

def snapshot(root):return {p.name:a.sha256(p.read_bytes()) for p in sorted(root.iterdir())}
def run(fixture,out,native,name_oracle):
    out=c.old.safe_new(out);out.mkdir();fixture=b.safe(fixture);watch=b.Watch()
    for n in sorted(portable_run.FIXED|{'PORTABLE-MANIFEST.json'}):watch.file(fixture/n)
    initial=c.init(fixture,out/'initial',name_oracle)
    seed_result=json.loads((out/'initial'/c.MARKER).read_bytes())['name_seed'];origin=json.loads((out/'initial'/'ORIGIN.json').read_bytes())
    source=watch.read(fixture/'source.blte');patch=watch.read(fixture/'sample.zbsdiff')
    base=c.status(out/'initial');baseline=(out/'initial'/'data.000').read_bytes()
    def make(name):
        p=out/name;c.create(p,source,patch,seed_result,origin);return p
    def read(p):return c.native_status(p,native/'cycle_oracle',native/'real_object_oracle')
    def advance(p):return c.advance(p,bind=lambda root:c.native_bind(native/'real_object_oracle',root))
    rows=[]
    for phase in c.PHASES:
        p=make('stop-'+phase)
        child=subprocess.run([sys.executable,'-B',str(Path(c.__file__).resolve()),'advance','--root',str(p),'--native-object-oracle',str(native/'real_object_oracle'),'--test-exit-after',phase],capture_output=True,timeout=10)
        a.require(child.returncode==91,'experiment_expected_child_exit')
        stopped=c.status(p);native_stopped=read(p);expected=phase in ('control_published','committed')
        a.require(stopped['target_published']==expected and native_stopped['selection']['target_visible']==expected,'experiment_publication_boundary')
        resumed=advance(p);native_after=read(p);a.require(native_after['source']['decoded_ckey_verified'] and native_after['target']['decoded_ckey_verified'],'experiment_native_after')
        a.require((p/'data.000').read_bytes()[:668]==baseline,'experiment_old_bytes_changed')
        snap=snapshot(p);again=advance(p);a.require(again['idempotent_noop'] and snap==snapshot(p),'experiment_noop_changed')
        rows.append({'stopped_after':phase,'exit_code':child.returncode,'stopped_status':stopped,'native_stopped':native_stopped,'resumed_status':resumed,'native_after':native_after,'reapply_noop_file_hashes_unchanged':True,'original_668_bytes_unchanged':True,'final_data_sha256':a.sha256((p/'data.000').read_bytes())})
    p=make('orphan-higher-index');(p/c.idx(2,2)).write_bytes(c.tables(bytes.fromhex(seed_result['seed']),True)[2]);orphan_before=snapshot(p);orphan_native=read(p)
    try:advance(p);raise RuntimeError('orphan_not_rejected')
    except a.AuditError as e:a.require(str(e)=='cycle_refuse_existing_unowned_transaction_files','experiment_wrong_orphan_error')
    a.require(orphan_before==snapshot(p) and not orphan_native['selection']['target_visible'],'experiment_orphan_changed')
    p=make('bind-failure')
    try:c.advance(p,bind=lambda root:False);raise RuntimeError('bind_not_rejected')
    except a.AuditError as e:a.require(str(e)=='cycle_index_bind_failed','experiment_wrong_bind_error')
    bind_before=read(p);a.require(not bind_before['selection']['target_visible'],'experiment_failed_bind_published');advance(p);bind_after=read(p)
    watch.check()
    report={'format':'real-retail-single-object-cycle-experiment-1','scope':'fresh owned Linux research copies; one pinned Retail source/patch/target; archive0; synthetic LAB-PC identity','initial_status':initial,'crash_cases':rows,'orphan_newer_index':{'native':orphan_native,'advance_rejected_without_changes':True},'bind_failure':{'native_before_retry':bind_before,'native_after_retry':bind_after},'original_fixture_identities_unchanged':True,'all_9_resumes_verified':True,'source_ckey_is_derived_not_independent':True,'target_ckey_independently_from_encoding_metadata':c.old.CK,'target_encoded_sha256':c.old.ENCODED_SHA,'native_index_capture':'actual pinned CascLib functions; custom header sequence selector and reserved-header policy','publication':'Linux renameat2 RENAME_NOREPLACE for index; whole-file atomic replace for research control','recovery':'custom journal + cooperating POSIX flock; not Agent journal or Windows lock','crash_scope':'9 explicit subprocess os._exit(91) boundaries; not power-loss or arbitrary-instruction crash proof','native_bind_gate_exercised':True,'windows_agent_process_executed':False,'windows_publication_executed':False,'game_or_lab_written':False,'full_profile_activation':False,'installation_ready':False,'network_requests':0}
    (out/'EXPERIMENT-RESULTS.json').write_text(json.dumps(report,indent=2)+'\n');return report
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('fixture','out-new','native','name-oracle'):p.add_argument('--'+name,required=True,type=Path)
    x=p.parse_args();r=run(x.fixture,x.out_new,x.native,x.name_oracle);print(json.dumps({'crash_cases':len(r['crash_cases']),'all_resumed':r['all_9_resumes_verified'],'installation_ready':False}))
