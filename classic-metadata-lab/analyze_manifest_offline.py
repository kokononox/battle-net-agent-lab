import hashlib,io,json,pathlib,struct,sys
import pandas as pd
import argparse
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent/'updater-core'))
from catalogue_readers import DownloadReader,parse_install
args=argparse.ArgumentParser();args.add_argument('--input',type=pathlib.Path,required=True);args.add_argument('--out',type=pathlib.Path,required=True);opts=args.parse_args()
root=opts.input;raw=(root/'download.metadata').read_bytes();r=DownloadReader(io.BytesIO(raw),len(raw));records=list(r.records());tags=list(r.tags())
df=pd.read_csv(root/'download-objects.csv',dtype={'ekey':'str','encoded_bytes':'int64','priority':'int64'})
# Independent raw fixed-width binary path, not the dataframe/parser iterator.
n=int.from_bytes(raw[5:9],'big');independent_total=0;keys=set()
for i in range(n):
 pos=11+22*i;keys.add(raw[pos:pos+16]);independent_total+=int.from_bytes(raw[pos+16:pos+21],'big')
assert n==len(df)==len(records)==len(keys)
assert int(df.encoded_bytes.sum())==sum(x[2] for x in records)==independent_total
assert df.isna().sum().sum()==0 and not df.duplicated('ekey').any() and (df.encoded_bytes>0).all()
install_tags,install_rows=parse_install((root/'install.metadata').read_bytes())
x={'schema':'classic-era-manifest-sizing-1','grain':'one encoded object in unfiltered download manifest','population':'all platforms, architectures, locales, regions and variants; no profile selection','source_decoded_sha256':hashlib.sha256(raw).hexdigest(),'download_object_count':n,'distinct_download_ekeys':len(keys),'unfiltered_encoded_object_bytes':independent_total,'unfiltered_encoded_object_GiB':independent_total/2**30,'independent_raw_binary_crosscheck':True,'install_manifest_entries':len(install_rows),'download_tag_count':len(tags),'selection_policy_qualified':False,'full_install_size_bytes':None,'selected_profile_download_bytes':None,'staging_space_bytes':None,'required_update_bytes':None,'duplicate_ekeys':0,'missing_values':0,'variant_tag_names':[name for _,name,kind,bits in tags if kind==16384],'warnings':['Unfiltered manifest sum is not game installation size, not actual Agent network traffic, not a Windows/enUS selection and not an update delta.','Config install-size describes metadata size, not the complete installation.','Actual Agent staging, patch strategy, archive layout and disk space must be observed separately.'],'presentation':{'disposition':'prose','reason':'One catalogue total and two counts; no trend or meaningful comparison; avoid false installation-size chart.'}}
opts.out.write_text(json.dumps(x,indent=2)+'\n')
print(json.dumps({k:x[k] for k in ('download_object_count','unfiltered_encoded_object_bytes','unfiltered_encoded_object_GiB','install_manifest_entries','independent_raw_binary_crosscheck')},indent=2))
