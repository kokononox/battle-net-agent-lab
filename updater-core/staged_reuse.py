"""Admit a freshly reverified owned-stage object as candidate input, not apply.
This does not grant installed-file reuse, native generation or network savings.
Raw bytes are returned only after full target keys/size and content verification.
"""
import json,sqlite3
from pathlib import Path
from release_core import need,TargetSnapshot
from segment_stage import SegmentStage
from reuse_candidates import sha_file


def reverify_candidate_stage(stage,plan_dir,catalogue_dir):
 need(type(stage)is SegmentStage,'owned_stage_required');plan_dir,catalogue_dir=Path(plan_dir),Path(catalogue_dir)
 plan=json.loads((plan_dir/'CANDIDATE-PLAN-to-share.json').read_bytes());cat=json.loads((catalogue_dir/'CATALOGUE-VERIFIED-to-share.json').read_bytes());t=TargetSnapshot.restore(plan['target']);need(t.public()==cat['target']==stage.cp.target.public(),'cache_target_mismatch');need(plan['source_catalogue_sha256']==cat['database']['sha256'],'cache_catalogue_disagreement')
 pd=plan_dir/'CANDIDATE-PLAN.sqlite';cd=catalogue_dir/'TARGET-CATALOGUE.sqlite'
 for path,receipt in ((pd,plan),(cd,cat)):
  need(path.is_file()and not path.is_symlink()and path.stat().st_size==receipt['database']['bytes']and sha_file(path)==receipt['database']['sha256'],'cache_plan_or_catalogue_identity')
 a=sqlite3.connect('file:'+str(pd.resolve())+'?mode=ro',uri=True);b=sqlite3.connect('file:'+str(cd.resolve())+'?mode=ro',uri=True)
 try:
  spec=stage.spec;key=bytes.fromhex(spec.ekey);candidates=a.execute('SELECT encoded_size FROM selected_download WHERE ekey=?',(key,)).fetchall();need(candidates==[(spec.encoded_size,)],'cache_not_selected_candidate');links=b.execute('SELECT c.ckey,c.decoded_size,e.encoded_size FROM content_links c JOIN encodings e USING(ekey) WHERE c.ekey=?',(key,)).fetchall();need(links==[(bytes.fromhex(spec.ckey),spec.decoded_size,spec.encoded_size)],'cache_target_object_identity')
 finally:a.close();b.close()
 raw,proof=stage.read_verified()
 report={'format':'reverified-owned-stage-candidate-1','status':'owned_staged_object_reverified_for_candidate_input','target':t.public(),'object':spec.public(),'encoded_sha256':proof['encoded_sha256'],'decoded_sha256':proof['decoded_sha256'],'full_ekey_verified':True,'full_ckey_verified':True,'chunk_checksums_verified':True,'verified_staging_input_bytes':len(raw),'eligible_as_verified_staging_input':True,'installed_content_reuse_authorized':False,'installed_current_disk_state_proven':False,'active_generation_proven':False,'vendor_required_set_selected':False,'required_network_download_bytes':None,'network_requests':0,'live_game_access':False,'installation_ready':False,'apply_authorized':False}
 return raw,report
