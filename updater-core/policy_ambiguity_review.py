"""Owned copied metadata audit only. No live install, network or plan writes.
Run with explicit existing research paths. Deterministic sample questions cannot
qualify policy, even if a future independent reference agrees with every sample.
"""
import json,hashlib,sqlite3
from pathlib import Path
from release_core import need,strict_json
from selection_policy import review_existing_candidate,review_tags
from catalogue_readers import parse_install,DownloadReader
from policy_ambiguity import audit_membership,audit_install_variants
from reuse_candidates import sha_file

def review(base,objects,plan,profile):
 base,objects,plan=map(Path,(base,objects,plan));prior=review_existing_candidate(base,objects,plan,profile)
 it,entries=parse_install((objects/'install.decoded').read_bytes())
 with (objects/'download.decoded').open('rb')as f:dr=DownloadReader(f,(objects/'download.decoded').stat().st_size);dt=list(dr.tags());n=dr.n
 expression,masks,gate=review_tags(it,len(entries),dt,n,profile)
 report={'format':'selection-ambiguity-questions-1','target':prior['target'],'profile':prior['profile'],'expression':expression,'source_metadata_sha256':prior['source_metadata_sha256'],'candidate_database_sha256':prior['candidate_database_sha256'],'source_catalogue_sha256':prior['source_catalogue_sha256'],'install':audit_membership(it,len(entries),masks['install']),'download':audit_membership(dt,n,masks['download']),'install_variants':audit_install_variants(entries,masks['install']),'independent_reference_available':False,'sample_agreement_would_qualify_policy':False,'vendor_selection_policy_qualified':False,'required_set_selected':False,'candidate_plan_modified':False,'fresh_installed_preferences_proven':False,'active_generation_proven':False,'required_network_download_bytes':None,'network_requests':0,'game_access':False,'installation_ready':False,'apply_authorized':False}
 # Independent ordinal-wise reference: do not reuse int mask intersections or
 # first_indices to verify candidate counts, feature cells and sample membership.
 for label,tags,count in (('install',it,len(entries)),('download',dt,n)):
  chosen=masks[label];actual=sum(bool(chosen[i//8]&(0x80>>(i%8)))for i in range(count));need(actual==report[label]['candidate_records'],'audit_independent_candidate_count')
  for feature in report[label]['feature_partitions']:
   bits=next(b for _,name,kind,b in tags if name==feature['tag']);cells={(False,False):0,(False,True):0,(True,False):0,(True,True):0}
   for i in range(count):bit=0x80>>(i%8);cells[(bool(chosen[i//8]&bit),bool(bits[i//8]&bit))]+=1
   for c in feature['cells']:
    need(c['records']==cells[(c['candidate_selected'],c['tag_member'])],'audit_independent_feature_count')
    for i in c['sample_indices']:bit=0x80>>(i%8);need(bool(chosen[i//8]&bit)==c['candidate_selected']and bool(bits[i//8]&bit)==c['tag_member'],'audit_sample_membership')
 # Resolve only bounded sample ordinals, not game content or host paths.
 for label in ('install','download'):
  questions=report[label]['feature_partitions'];indices={i for q in questions for c in q['cells']for i in c['sample_indices']}
  if label=='install':lookup={i:{'record_index':i,'manifest_label':label_,'ckey':key.hex(),'decoded_size':size}for i,label_,key,size in entries if i in indices}
  else:
   lookup={}
   with (objects/'download.decoded').open('rb')as f:
    for i in sorted(indices):
     f.seek(11+i*22);raw=f.read(22);need(len(raw)==22,'audit_sample_record_short');lookup[i]={'record_index':i,'ekey':raw[:16].hex(),'encoded_size':int.from_bytes(raw[16:21],'big'),'priority':raw[21]}
  for q in questions:
   for c in q['cells']:c['samples']=[lookup[i]for i in c['sample_indices']]
 # Opaque content identities, never arbitrate multiple EKeys by picking first.
 connection=sqlite3.connect((objects/'TARGET-CATALOGUE.sqlite').as_uri()+'?mode=ro',uri=True)
 try:
  representation_questions=[]
  for i,label,key,size in entries:
   if not masks['install'][i//8]&(0x80>>(i%8)):continue
   links=list(connection.execute('SELECT ekey,decoded_size FROM content_links WHERE ckey=? ORDER BY ekey',(key,)));need(all(n==size for e,n in links),'audit_encoding_size_disagreement')
   if len(links)>1:representation_questions.append({'install_record_index':i,'ckey':key.hex(),'representations':len(links),'sample_ekeys':[e.hex()for e,n in links[:2]],'chosen_ekey':None})
  report['selected_install_multi_encoding']={'records':len(representation_questions),'examples':representation_questions[:16],'omitted_examples':max(0,len(representation_questions)-16),'encoding_route_qualified':False}
 finally:connection.close()
 for name,expected in prior['source_metadata_sha256'].items():
  if name in ('install','download'):need(sha_file(objects/(name+'.decoded'))==expected,'audit_metadata_changed')
 need(sha_file(plan/'CANDIDATE-PLAN.sqlite')==prior['candidate_database_sha256'],'audit_candidate_changed');report['independent_ordinal_checks_passed']=True
 report['interpretation']='Partitions and deterministic examples are questions for an independent oracle, not verified inclusion/exclusion rules; possible overlaps are not additive.'
 return report
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__)
 for key in ('binding-workspace','objects-workspace','candidate-workspace','profile-json','output'):p.add_argument('--'+key,required=True)
 a=p.parse_args();r=review(a.binding_workspace,a.objects_workspace,a.candidate_workspace,strict_json(Path(a.profile_json).read_bytes()))
 with Path(a.output).open('x')as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps({'status':'ambiguity_questions_only_NOT_vendor_policy','independent_ordinal_checks_passed':True,'required_set_selected':False}))
