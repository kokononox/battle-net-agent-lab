"""Offline real patch-to-prefix proof; existing local fixture and oracles only."""
import argparse,json,struct,subprocess,tempfile
from pathlib import Path
import archive_prefix_poc as p
import retail_storage_poc as old
import agent_archive_prefix_audit as audit
import synthetic_casc_format as f

SEED=bytes.fromhex('00112233445566778899aabbccddeeff')
def invoke(binary,*args):
    r=subprocess.run([str(binary),*map(str,args)],capture_output=True,text=True,timeout=15)
    assert len(r.stdout)<8192 and len(r.stderr)<8192
    result=json.loads(r.stdout);assert result['accepted']==(r.returncode==0);return result

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--fixture',type=Path,required=True);ap.add_argument('--native-dir',type=Path,required=True);ap.add_argument('--agent',type=Path,required=True);ap.add_argument('--report-new',type=Path,required=True);args=ap.parse_args()
    report=old.safe_new(args.report_new);report.mkdir();native=args.native_dir
    static=audit.analyze(args.agent.read_bytes())
    baseline=report/'baseline';base=old.run(args.fixture,baseline,native/'storage_oracle')
    root=report/'prefix-fixture';real=p.build(baseline,root,SEED);real['prefix_native']=p.native(root,native/'prefix_oracle');real['real_object_native']=invoke(native/'real_object_oracle',root/old.expected_index(),root/'data.000',old.EK,old.CK);assert real['real_object_native']['accepted']
    positives=[];rejects={};data=root/'data.000';original=data.read_bytes()
    for at in range(480):
        raw=bytearray(original);raw[at]^=1;data.write_bytes(raw);r=invoke(native/'prefix_oracle',root,SEED.hex(),1024);assert not r['accepted'];rejects[r['code']]=rejects.get(r['code'],0)+1
    data.write_bytes(original)
    idx_rejected=0
    for file in sorted(root.glob('*.idx')):
        before=file.read_bytes();raw=bytearray(before);raw[-1]^=1;file.write_bytes(raw);assert not invoke(native/'prefix_oracle',root,SEED.hex(),1024)['accepted'];idx_rejected+=1;file.write_bytes(before)
    semantic=[]
    # Correct checksums do not make ordinary flags valid for reserved headers.
    raw=bytearray(original);raw[20]=0;struct.pack_into('<I',raw,22,f.hashlittle2(bytes(raw[:22]),0x3d6be971)[0]);raw[26:30]=f.checksum_b(bytes(raw[:26]),0,0);data.write_bytes(raw)
    r=invoke(native/'prefix_oracle',root,SEED.hex(),1024);assert not r['accepted'];semantic.append({'case':'reserved_flag_zero_with_recomputed_checksums',**r});data.write_bytes(original)
    # Put a reserved entry in ordinary-mode bucket with valid block checksum.
    file=root/'0000000001.idx';before=file.read_bytes();raw=bytearray(before);raw[40:58]=bytes.fromhex(p.keys(SEED,0,1024)[1].hex())[:9]+f.location(0,30)+struct.pack('<I',30);struct.pack_into('<I',raw,36,f.hashlittle2(bytes(raw[40:58]))[0]);file.write_bytes(raw)
    r=invoke(native/'prefix_oracle',root,SEED.hex(),1024);assert not r['accepted'];semantic.append({'case':'wrong_reserved_slot_with_valid_index_checksum',**r});file.write_bytes(before)
    for name,at in [('real_payload_corrupt',667),('real_full_ekey_corrupt',480)]:
        raw=bytearray(original);raw[at]^=1;data.write_bytes(raw);r=invoke(native/'real_object_oracle',root/old.expected_index(),data,old.EK,old.CK);assert not r['accepted'];semantic.append({'case':name,**r})
    data.write_bytes(original)
    for name,seed,ck in [('wrong_seed',bytes(16),None),('wrong_decoded_ckey',None,'0'*32)]:
        r=invoke(native/'prefix_oracle',root,seed.hex(),1024) if seed is not None else invoke(native/'real_object_oracle',root/old.expected_index(),data,old.EK,ck)
        assert not r['accepted'];semantic.append({'case':name,**r})
    with tempfile.TemporaryDirectory() as t:
        for n in range(16):
            seed=bytes((i*17+n*13)&255 for i in range(16));rroot=Path(t)/f'seed-{n}';p.build(baseline,rroot,seed)
            one=invoke(native/'prefix_oracle',rroot,seed.hex(),1024);two=invoke(native/'real_object_oracle',rroot/old.expected_index(),rroot/'data.000',old.EK,old.CK);assert one['accepted'] and two['accepted'];positives.append({'seed':seed.hex(),'prefix_accepted':True,'real_object_accepted':True})
    assert p.verify(root)['archive_prefix_placeholder'] is False
    # Baseline is historical-format output, preserved and verified, not source installation.
    old.verify(baseline)
    experiment={'format':'archive-prefix-experiments-1','positive_seed_vectors':positives,'prefix_byte_flip_rejections':{'count':480,'positions':'0..479 inclusive; each XOR 1 separately','by_code':rejects},'index_file_checksum_rejections':idx_rejected,'semantic_rejections':semantic,'negative_cases_total':480+idx_rejected+len(semantic),'all_negative_cases_rejected':True,'final_fixture_restored_and_verified':True,'installation_ready':False,'agent_executed':False,'network_requests':0}
    for name,obj in [('BASELINE-REAL-READBACK.json',base),('REAL-PREFIX-READBACK.json',real),('AGENT-PREFIX-STATIC.json',static),('EXPERIMENT-RESULTS.json',experiment)]: (report/name).write_text(json.dumps(obj,indent=2)+'\n')
    print(json.dumps({'positive_seed_vectors':len(positives),'native_rejections':experiment['negative_cases_total'],'reserved_headers':16,'total_index_rows':17,'installation_ready':False}))
if __name__=='__main__':main()
