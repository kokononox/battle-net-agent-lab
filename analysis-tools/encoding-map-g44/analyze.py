"""Offline encoding/install/download reconciliation. No network and no runtime approval."""
import base64,hashlib,json,sys,csv,importlib.util
from pathlib import Path
import pandas as pd
import numpy as np
from encoding import parse_encoding,Rejected
from codec import decode_blte,parse_install,parse_download
BASE=Path(__file__).resolve().parents[2];G43=BASE if (BASE/'reports/public-manifest-g43/public-fixtures.json').exists() else BASE.parent/'g43'
OLD=G43/'reports/public-manifest-g43';OUT=BASE/'reports/encoding-map-g44'
def load(name):return json.loads((OLD/name).read_text())
def inputs():
 pins=json.loads((OUT/'source-inputs.json').read_text())
 for name,pin in pins['files'].items():
  if Path(name).name!=name:raise Rejected('source_pin_path')
  b=(OLD/name).read_bytes()
  if len(b)!=pin['bytes'] or hashlib.sha256(b).hexdigest()!=pin['sha256']:raise Rejected('source_snapshot_changed')
 f=load('public-fixtures.json');objects=load('manifest-objects.json');data={}
 for row in objects['requests']:
  source=f['objects'][Path(row['snapshot']).name];b=base64.b64decode(source['base64'],validate=True)
  if len(b)!=row['expected_encoded_bytes'] or len(b)!=source['bytes'] or hashlib.sha256(b).hexdigest()!=row['sha256'] or row['sha256']!=source['sha256']:raise Rejected('source_encoded_binding')
  plain=decode_blte(b,row['expected_decoded_bytes'],row['ekey'])
  if len(plain)!=row['expected_decoded_bytes'] or hashlib.md5(plain).hexdigest()!=row['ckey'] or hashlib.sha256(plain).hexdigest()!=row['decoded_sha256']:raise Rejected('source_decoded_binding')
  data[row['kind']]=plain
 configs=load('configs.json');build=next(x for x in configs['requests'] if x['kind']=='build');product=next(x for x in configs['requests'] if x['kind']=='product')
 for row in (build,product):
  frow=f['objects'][Path(row['snapshot']).name];b=base64.b64decode(frow['base64'],validate=True)
  if hashlib.md5(b).hexdigest()!=row['content_key'] or hashlib.sha256(b).hexdigest()!=row['sha256']:raise Rejected('config_source_binding')
 if json.loads(base64.b64decode(f['objects'][Path(product['snapshot']).name]['base64']))!=product['parsed']:raise Rejected('product_json_binding')
 for row in objects['requests']:
  if build['parsed'][row['kind']].split()!=[row['ckey'],row['ekey']] or list(map(int,build['parsed'][row['kind']+'-size'].split()))!=[row['expected_decoded_bytes'],row['expected_encoded_bytes']]:raise Rejected('build_reference_binding')
 return data,objects,build['parsed'],product['parsed']
def membership(m):
 masks={};n=m['entry_count']
 if len(m['entries'])!=n or [r['index'] for r in m['entries']]!=list(range(n)):raise Rejected('manifest_index_shape')
 for t in m['tags']:
  k=(t['name'],t['type'])
  if k in masks:raise Rejected('duplicate_tag')
  mask=bytes.fromhex(t['mask_hex'])
  if len(mask)!=(n+7)//8:raise Rejected('tag_mask_bound')
  # Bits beyond entry_count are preserved but never interpreted as file rows.
  masks[k]=mask
 if ('Windows',2) not in masks or ('OSX',2) not in masks:raise Rejected('platform_tags_missing')
 return [[name for (name,typ),b in masks.items() if b[i//8]&(0x80>>(i%8))] for i in range(n)]
def reconcile(enc,install,download,build,product):
 cm={r['ckey']:r for r in enc['ckey_mappings']};em={r['ekey']:r for r in enc['ekey_specs']};dm={r['ekey']:r for r in download['entries']}
 if len(dm)!=len(download['entries']):raise Rejected('download_ekey_duplicate')
 imem,dmem=membership(install),membership(download)
 rows=[];issues=[]
 download_issues=[{'ekey':k,'code':'encoding_spec_missing_or_size_mismatch'} for k,r in dm.items() if k not in em or r['encoded_bytes']!=em[k]['encoded_bytes']]
 for ir in install['entries']:
  cr=cm.get(ir['ckey']);r=dict(ir,tags=imem[ir['index']],candidates=[],mapping_verified=False,runtime_approved=False)
  if cr is None:issues.append({'index':ir['index'],'code':'ckey_missing'})
  elif cr['decoded_bytes']!=ir['decoded_bytes']:issues.append({'index':ir['index'],'code':'decoded_size_mismatch'})
  else:
   for ek in cr['ekeys']:
    er=em[ek];dr=dm.get(ek);ok=dr is not None and er['encoded_bytes']==dr['encoded_bytes']
    if not ok:issues.append({'index':ir['index'],'ekey':ek,'code':'download_missing_or_encoded_size_mismatch'})
    r['candidates'].append({'ekey':ek,'encoded_bytes':er['encoded_bytes'],'espec_index':er['espec_index'],'download_index':dr['index'] if dr else None,'download_tags':dmem[dr['index']] if dr else [],'metadata_consistent':ok})
   r['mapping_verified']=bool(r['candidates']) and all(x['metadata_consistent'] for x in r['candidates'])
  rows.append(r)
 windows=[r for r in rows if 'Windows' in r['tags']]
 unclassified=[r['index'] for r in rows if 'Windows' not in r['tags'] and 'OSX' not in r['tags']]
 root_ck=build['root'];root=cm.get(root_ck);root_keys=root['ekeys'] if root else []
 install_eks={x['ekey'] for r in rows for x in r['candidates']};extra=[r for r in download['entries'] if r['ekey'] not in install_eks]
 unknown_extra=[r for r in extra if r['ekey'] not in root_keys]
 default_tags=product['platform']['win']['config']['tags']
 if default_tags!=['Windows','Volatile']:raise Rejected('unsupported_default_tag_profile')
 candidates={};windows_issues=[]
 for r in windows:
  if not r['mapping_verified'] or len(r['candidates'])!=1:windows_issues.append({'install_index':r['index'],'code':'ambiguous_or_missing_mapping'});continue
  k=r['candidates'][0];ek=k['ekey']
  if 'Windows' not in k['download_tags']:windows_issues.append({'install_index':r['index'],'code':'platform_tag_inconsistent'});continue
  if ek not in candidates:candidates[ek]={'ekey':ek,'ckey':r['ckey'],'decoded_bytes':r['decoded_bytes'],'encoded_bytes':k['encoded_bytes'],'espec_index':k['espec_index'],'install_indices':[],'download_index':k['download_index'],'download_tags':k['download_tags'],'proposed_standalone_url':'https://us.cdn.blizzard.com/tpr/bnt002/data/'+ek[:2]+'/'+ek[2:4]+'/'+ek,'standalone_availability_verified':False,'payload_sha256':None,'approval_state':'pending_payload_and_tag_review'}
  candidates[ek]['install_indices'].append(r['index'])
 # Independent data-frame joins over a separate expansion verify the headline reconciliation.
 left=pd.DataFrame(install['entries']);ck=pd.DataFrame(enc['ckey_mappings']).rename(columns={'decoded_bytes':'en_decoded_bytes'});es=pd.DataFrame(enc['ekey_specs']).rename(columns={'encoded_bytes':'en_encoded_bytes'})
 joined=left.merge(ck,on='ckey',how='left',validate='many_to_one').explode('ekeys').rename(columns={'ekeys':'ekey'})
 joined=joined.merge(es,on='ekey',how='left',validate='many_to_one').merge(pd.DataFrame(download['entries'])[['ekey','encoded_bytes']],on='ekey',how='left',validate='many_to_one')
 independently_good=(joined['decoded_bytes']==joined['en_decoded_bytes'])&(joined['en_encoded_bytes']==joined['encoded_bytes'])
 if independently_good.sum()!=sum(len(r['candidates']) for r in rows if r['mapping_verified']):raise Rejected('independent_join_disagrees')
 if len(joined)!=sum(len(r['candidates']) for r in rows):raise Rejected('independent_grain_disagrees')
 wm=next(bytes.fromhex(t['mask_hex']) for t in install['tags'] if t['name']=='Windows' and t['type']==2)
 win_indices=np.flatnonzero(np.unpackbits(np.frombuffer(wm,dtype=np.uint8),bitorder='big')[:len(left)]).tolist()
 independent_win=joined[joined['index'].isin(win_indices)]
 if len(win_indices)!=len(windows) or independent_win['ekey'].nunique()!=len(candidates):raise Rejected('independent_windows_disagrees')
 summary={'reconciliation_status':'metadata_consistent' if not issues and not download_issues and not windows_issues and not unknown_extra else 'unresolved','schema':'offline_encoding_join_g44_v1','product':'bna','build_id':'17952','version':'2.53.6.17952','encoding_ckey_rows':len(cm),'encoding_ekey_rows':len(em),'encoding_pages_verified':len(enc['pages']),'install_path_rows':len(rows),'install_unique_ckeys':len({r['ckey'] for r in rows}),'install_paths_mapping_verified':sum(r['mapping_verified'] for r in rows),'mapping_issues':issues,'download_metadata_issues':download_issues,'download_object_rows':len(dm),'download_extra_objects':extra,'download_extra_explained_as_root':bool(extra) and not unknown_extra,'root_ckey':root_ck,'root_ekeys':root_keys,'windows_literal_tag_install_paths':len(windows),'windows_candidate_unique_objects':len(candidates),'windows_mapping_issues':windows_issues,'install_platform_unclassified_indices':unclassified,'independent_join_validated_rows':int(independently_good.sum()),'independent_windows_paths':len(win_indices),'independent_windows_unique_objects':int(independent_win['ekey'].nunique()),'product_default_windows_tags':default_tags,'tags_override_by_os':product['platform']['win']['config'].get('tags_override_by_os'),'casc_language_agnostic':product['all']['config']['casc_language_agnostic'],'selection_policy':{'kind':'literal_Windows_tag_candidates_only','bit_order':'MSB_first','volatile_semantics_resolved':False,'locale_filter_applied':False,'os_override_applied':False,'final_install_plan':False},'footer_semantics_interpreted':False,'installer_executed':False,'payload_downloaded':False,'new_battlenet_requests':0,'runtime_approved_entries':0,'production_catalog_modified':False,'agent_dependency_resolved':False,'comparison_plan':[{'disposition':'prose','reason':'Security parser reconciliation across unlike grains, not a visual funnel or time comparison.'}]}
 return summary,rows,sorted(candidates.values(),key=lambda r:r['ekey'])
def legacy_compatibility(candidates):
 path=BASE/'analysis-tools/download-broker-g37/broker.py'
 if not path.exists():path=BASE.parent/'g37/analysis-tools/download-broker-g37/broker.py'
 spec=importlib.util.spec_from_file_location('g44_legacy_probe',path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
 review={'schema':'review_only_windows_candidates_g44_v1','entries':candidates[:1],'runtime_approved_entries':0}
 raw=json.dumps(review,separators=(',',':')).encode();denied=None
 try:module.Catalog.load(raw,hashlib.sha256(raw).hexdigest())
 except module.Denied as e:denied=e.code
 if denied is None:raise Rejected('legacy_catalog_unexpectedly_accepted_review_data')
 total=sum(c['encoded_bytes'] for c in candidates)
 return {'g37_source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'review_schema_rejected':True,'rejection_code':denied,'existing_hosts':sorted(module.HOSTS),'candidate_host_allowed_by_g37':'us.cdn.blizzard.com' in module.HOSTS,'existing_catalog_max_bytes':module.MAX_POLICY,'source_literal_resource_limit':64,'candidate_object_count':len(candidates),'within_existing_resource_count_limit':len(candidates)<=64,'candidate_encoded_bytes':total,'existing_payload_limit_bytes':512*1024*1024,'candidate_bytes_within_existing_payload_limit':total<=512*1024*1024,'limits_modified':False}
def main():
 data,objects,build,product=inputs();enc=parse_encoding(data['encoding']);install=parse_install(data['install']);download=parse_download(data['download']);summary,rows,candidates=reconcile(enc,install,download,build,product)
 compatibility=legacy_compatibility(candidates)
 for name,obj in [('g37-compatibility',compatibility),('encoding-decoded',enc),('reconciliation',summary),('install-mapping',{'rows':rows}),('windows-candidates.review-only',{'schema':'review_only_windows_candidates_g44_v1','not_loadable_as_runtime_catalog':True,'runtime_approved_entries':0,'entries':candidates})]:
  (OUT/(name+'.json')).write_text(json.dumps(obj,separators=(',',':'))+'\n')
 with (OUT/'install-key-map.csv').open('w',newline='',encoding='utf-8') as f:
  writer=csv.writer(f);writer.writerow(['install_index','install_path','ckey','decoded_bytes','ekey','encoded_bytes','literal_windows_tag','metadata_consistent'])
  for r in rows:
   for c in r['candidates']:writer.writerow([r['index'],r['name'],r['ckey'],r['decoded_bytes'],c['ekey'],c['encoded_bytes'],'Windows' in r['tags'],r['mapping_verified']])
 print(json.dumps(summary))
if __name__=='__main__':main()
