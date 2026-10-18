"""Fresh bounded-memory reverify of a selected owned staged archive object.
Proof-only API: no raw/decoded payload returned; not installed reuse or apply.
"""
import sqlite3
from pathlib import Path
from release_core import need,strict_json,TargetSnapshot
from reuse_candidates import sha_file
from stream_stage import StreamStage
from windows_stream_stage import WindowsStreamStage

def reverify_stream_candidate(stage,plan_dir,catalogue_dir):
 need(type(stage)in(StreamStage,WindowsStreamStage),'stream_owned_stage_required');plan_dir,catalogue_dir=Path(plan_dir),Path(catalogue_dir);plan=strict_json((plan_dir/'CANDIDATE-PLAN-to-share.json').read_bytes());cat=strict_json((catalogue_dir/'CATALOGUE-VERIFIED-to-share.json').read_bytes());t=TargetSnapshot.restore(plan['target']);need(t.public()==cat['target']==stage.cp.target.public(),'stream_cache_target_mismatch');need(plan['status']=='candidate_selection_and_crosswalk_checked_NOT_vendor_required_set'and cat['status']=='full_target_metadata_crosswalk_verified','stream_cache_receipt_status');need(plan['source_catalogue_sha256']==cat['database']['sha256'],'stream_cache_catalogue_disagreement')
 pd=plan_dir/'CANDIDATE-PLAN.sqlite';cd=catalogue_dir/'TARGET-CATALOGUE.sqlite'
 for path,receipt in((pd,plan),(cd,cat)):
  need(path.is_file()and not path.is_symlink()and path.stat().st_size==receipt['database']['bytes']and sha_file(path)==receipt['database']['sha256'],'stream_cache_database_identity')
 a=sqlite3.connect(pd.resolve().as_uri()+'?mode=ro',uri=True);b=sqlite3.connect(cd.resolve().as_uri()+'?mode=ro',uri=True)
 try:
  s=stage.spec;ek=bytes.fromhex(s.ekey);need(a.execute('SELECT encoded_size FROM selected_download WHERE ekey=?',(ek,)).fetchall()==[(s.encoded_size,)],'stream_cache_not_selected');need(b.execute('SELECT c.ckey,c.decoded_size,e.encoded_size FROM content_links c JOIN encodings e USING(ekey) WHERE c.ekey=?',(ek,)).fetchall()==[(bytes.fromhex(s.ckey),s.decoded_size,s.encoded_size)],'stream_cache_target_identity')
 finally:a.close();b.close()
 proof=stage.verify()
 return {'format':'streaming-staged-candidate-reverify-1','target':t.public(),'object':s.public(),'status':'one_owned_staged_candidate_freshly_stream_verified','proof':proof,'eligible_as_verified_staging_input':True,'verified_staging_input_bytes':s.encoded_size,'installed_content_reuse_authorized':False,'active_generation_proven':False,'vendor_selection_policy_qualified':False,'required_network_download_bytes':None,'network_requests':0,'game_access':False,'installation_ready':False,'apply_authorized':False}
