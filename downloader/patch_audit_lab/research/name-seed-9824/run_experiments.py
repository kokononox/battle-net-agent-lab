"""Reproduce bounded ASCII seed/fragment parity and real Retail prefix readback.
All names/paths are synthetic; no hostname/cwd discovery, Windows API or network.
"""
import argparse,hashlib,json,random,subprocess
from pathlib import Path
import name_seed_model as m
import agent_name_seed_audit as audit
import archive_prefix_poc as prefix
import retail_storage_poc as old
import patch_audit as a

CASES=[
 ('LAB-PC',r'C:\Games\World of Warcraft\Data',None),
 ('LAB-PC','c:/Games/World of Warcraft/Data',None),
 ('lab-pc','C:/Games/World of Warcraft/Data',None),
 ('LAB-PC','C:/Games/world of warcraft/Data',None),
 ('LAB-PC','C:/A//B/./C/../',None),
 ('LAB-PC',r'\\Server\Share\A\..\Data',None),
 ('LAB-PC','A/../Data','C:/Games/WoW'),
 ('LAB-PC','Data','//Server/Share/Game'),
 ('X'*15,'C:/'+('a'*772),None),
]

def rawcheck(oracle,host,raw):
    got=m.oracle(oracle,host,raw);canonical=m.lexical(raw);seed=m.derive(host,canonical)
    a.require(got['canonical_path']==canonical and got['seed']==seed.hex() and got['reserved_keys']==[k.hex() for k in prefix.keys(seed,0,1024)],'experiment_fragment_mismatch');return got

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--agent',type=Path,required=True);p.add_argument('--isolated-oracle',type=Path,required=True);p.add_argument('--prefix-native-dir',type=Path,required=True);p.add_argument('--report-new',type=Path,required=True);args=p.parse_args()
    out=old.safe_new(args.report_new);out.mkdir();static=audit.analyze(args.agent.read_bytes())
    cases=[m.compare(args.isolated_oracle,*v) for v in CASES]
    digest=hashlib.sha256();rng=random.Random(9824);random_count=1024
    for _ in range(random_count):
        raw=rng.choice(['C:/','//server/share/','/',''])+rng.choice(['/','\\']).join(rng.choice(['A','b','..','.','','WoW','Data']) for _ in range(rng.randrange(1,10)))
        raw=raw or '.';got=rawcheck(args.isolated_oracle,'LAB-PC',raw);digest.update(old.canonical({'raw':raw,**got}))
    boundaries=[]
    for total in (54,55,56,57,63,64,65,119,120,127,128,129,255,512,778):
        raw='C:/'+('x'*(total-6));got=rawcheck(args.isolated_oracle,'LAB',raw);boundaries.append({'combined_hash_input_bytes':total,'seed':got['seed'],'matched':True})
    negative_inputs=[('missing_cwd','LAB-PC','Data',None),('drive_relative','LAB-PC','C:Data',None),('root_relative','LAB-PC','/Data',None),('device','LAB-PC',r'\\?\C:\Data',None),('root_escape','LAB-PC','C:/../Other',None),('non_ascii_name','کامپیوتر','C:/Data',None),('non_ascii_path','LAB-PC','C:/بازی',None),('host_long','X'*16,'C:/Data',None),('path_nul','LAB-PC','C:/D\0ata',None),('unc_escape','LAB-PC','//Server/Share/../Other',None)]
    negatives=[]
    for name,host,path,cwd in negative_inputs:
        try:m.model(host,path,cwd)
        except a.AuditError as e:negatives.append({'case':name,'rejected':True,'code':str(e)})
        else:raise AssertionError(name)
    native_rejections=[]
    for host,path in [('X'*16,'C:/Data'),('LAB','C:/بازی'),('','C:/Data'),('LAB','')]:
        r=subprocess.run([str(args.isolated_oracle),host,path],capture_output=True,timeout=5);a.require(r.returncode==90 and not r.stdout,'experiment_native_input_rejection');native_rejections.append({'exit':90,'stdout_bytes':0})
    # Rebuild real object from original local portable metadata and source+patch.
    baseline=out/'baseline';base=old.run(args.fixture,baseline,args.prefix_native_dir/'storage_oracle')
    selected=cases[0];fixture=out/'derived-prefix';real=prefix.build(baseline,fixture,bytes.fromhex(selected['seed']));real['seed_derivation']={k:selected[k] for k in ('canonical_path','seed','fragment_comparison','explicit_synthetic_inputs','actual_user_installation_binding_proven')};real['prefix_native']=prefix.native(fixture,args.prefix_native_dir/'prefix_oracle')
    r=subprocess.run([str(args.prefix_native_dir/'real_object_oracle'),str(fixture/old.expected_index()),str(fixture/'data.000'),old.EK,old.CK],capture_output=True,text=True,timeout=15);a.require(r.returncode==0 and len(r.stdout)<8192,'experiment_real_native');real['real_object_native']=json.loads(r.stdout);a.require(real['real_object_native']['decoded_ckey_verified'],'experiment_real_ckey');prefix.verify(fixture);old.verify(baseline)
    experiments={'format':'name-seed-fragment-experiments-1','supported_name_path_cases':cases,'deterministic_raw_lexical_vectors':{'count':random_count,'random_seed':9824,'result_stream_sha256':digest.hexdigest(),'all_canonical_seed_and_16_keys_matched':True,'includes_raw_paths_not_accepted_by_safe_wrapper':True},'md5_boundary_vectors':boundaries,'model_policy_rejections':negatives,'native_input_rejections':native_rejections,'isolated_agent_pure_fragments_executed':True,'windows_agent_process_executed':False,'windows_apis_executed':False,'actual_user_installation_binding_proven':False,'installation_ready':False,'network_requests':0,'real_retail_prefix_and_ckey_native_verified':True}
    for name,obj in [('AGENT-NAME-SEED-STATIC.json',static),('EXPERIMENT-RESULTS.json',experiments),('BASELINE-REAL-READBACK.json',base),('DERIVED-SEED-REAL-READBACK.json',real)]: (out/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'supported_cases':len(cases),'random_raw_vectors':random_count,'md5_boundary_vectors':len(boundaries),'model_rejections':len(negatives),'native_input_rejections':len(native_rejections),'real_retail_ckey_native_verified':True,'windows_agent_process_executed':False}))
if __name__=='__main__':main()
