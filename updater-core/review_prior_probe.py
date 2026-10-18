"""Offline receipt/one uploaded-index cross-check. No live game, network or payload I/O."""
import argparse,json,zipfile,hashlib
from pathlib import Path
from release_core import need,TargetSnapshot
from local_candidates import ObjectSpec,parse_v7,classify
from proof_history import import_receipt

def review(source):
 base=Path(__file__).parent;reports=base/'reports';scope=json.loads((reports/'ONE-OBJECT-SCOPE.json').read_bytes());target=TargetSnapshot.restore(json.loads((reports/'CATALOGUE-VERIFIED-to-share.json').read_bytes())['target']);spec=ObjectSpec(scope['ckey'].lower(),scope['ekey'].lower(),scope['decoded_size'],scope['encoded_size']);history=import_receipt((reports/'LOCAL-OBJECT-PROOF-user.json').read_bytes(),target,spec,scope)
 with zipfile.ZipFile(source) as z:
  members=[i for i in z.infolist() if i.filename==scope['index_member']];need(len(members)==1 and members[0].file_size==scope['index_bytes'] and not members[0].flag_bits&1,'one_uploaded_index_scope');raw=z.read(members[0])
 need(hashlib.sha256(raw).hexdigest()==scope['index_sha256'],'uploaded_index_digest');refs,proof=parse_v7(raw,scope['index_member']);ref=refs[scope['index_ordinal']];need(ref.prefix.hex()==scope['ekey'][:18].lower() and ref.archive_id==scope['archive_id'] and ref.offset==scope['offset'] and ref.span==scope['encoded_size'],'uploaded_candidate_row_conflict');need(classify(ref,spec,scope['archive_bytes'])=='direct_blte_candidate_NOT_proof','direct_candidate_required')
 history['uploaded_index_independently_reparsed']=proof;history['archive_payload_bytes_read_by_importer']=0;history['raw_archive_payload_independently_replayed_here']=False;history['scope_index_row_revalidated_from_uploaded_copy']=True
 (reports/'LOCAL-PROOF-HISTORY-to-share.json').write_text(json.dumps(history,indent=2)+'\n');print(json.dumps({'status':history['status'],'index_records_verified':proof['records'],'historical_proven_objects':1,'current_reuse_authorized':False,'installation_ready':False},indent=2));return history
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--uploaded-index-zip',type=Path,required=True);review(p.parse_args().uploaded_index_zip)
