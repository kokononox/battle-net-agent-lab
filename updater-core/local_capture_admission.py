"""Bind an independent temporary capture to exact target candidate/catalogue.
Candidate input admission only; no required-set/installer or network-savings grant.
"""
import sqlite3
from pathlib import Path
from release_core import need,strict_json,TargetSnapshot
from reuse_candidates import sha_file
from local_content_capture import LocalContentCapture

def admit_capture(capture,plan_dir,catalogue_dir):
 need(type(capture)is LocalContentCapture and not capture.closed,'local_capture_instance_required')
 plan_dir,catalogue_dir=Path(plan_dir),Path(catalogue_dir)
 plan=strict_json((plan_dir/'CANDIDATE-PLAN-to-share.json').read_bytes());cat=strict_json((catalogue_dir/'CATALOGUE-VERIFIED-to-share.json').read_bytes())
 target=TargetSnapshot.restore(plan['target'])
 need(target.public()==cat['target']==capture.target.public(),'local_capture_target_mismatch')
 need(plan['status']=='candidate_selection_and_crosswalk_checked_NOT_vendor_required_set'and cat['status']=='full_target_metadata_crosswalk_verified','local_capture_receipt_status')
 need(plan['source_catalogue_sha256']==cat['database']['sha256'],'local_capture_catalogue_disagreement')
 pd=plan_dir/'CANDIDATE-PLAN.sqlite';cd=catalogue_dir/'TARGET-CATALOGUE.sqlite'
 for p,r in ((pd,plan),(cd,cat)):
  need(p.is_file()and not p.is_symlink()and p.stat().st_size==r['database']['bytes']and sha_file(p)==r['database']['sha256'],'local_capture_database_identity')
 a=sqlite3.connect(pd.resolve().as_uri()+'?mode=ro',uri=True)
 try:
  b=sqlite3.connect(cd.resolve().as_uri()+'?mode=ro',uri=True)
  try:
   s=capture.spec;ek=bytes.fromhex(s.ekey)
   need(a.execute('SELECT encoded_size FROM selected_download WHERE ekey=?',(ek,)).fetchall()==[(s.encoded_size,)],'local_capture_not_selected')
   need(b.execute('SELECT c.ckey,c.decoded_size,e.encoded_size FROM content_links c JOIN encodings e USING(ekey) WHERE c.ekey=?',(ek,)).fetchall()==[(bytes.fromhex(s.ckey),s.decoded_size,s.encoded_size)],'local_capture_target_object_identity')
  finally:b.close()
 finally:a.close()
 proof=capture.verify()
 # Detect ordinary changes during catalogue lookup/reverification as well.
 need(sha_file(pd)==plan['database']['sha256']and sha_file(cd)==cat['database']['sha256'],'local_capture_database_changed')
 return dict(format='local-capture-candidate-admission-1',target=target.public(),object=capture.spec.public(),proof=proof,
   status='independent_copy_verified_against_target_candidate_NOT_installation_reuse',eligible_as_verified_staging_input=True,
   verified_staging_input_bytes=capture.spec.encoded_size,source_generation_proven=False,source_store_binding_proven=False,
   generation_proof_needed_for_copied_content_identity=False,vendor_selection_policy_qualified=False,
   required_set_selected=False,installed_content_reuse_authorized=False,required_network_download_bytes=None,
   network_requests=0,game_access=None,installation_ready=False,apply_authorized=False)
