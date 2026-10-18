"""Continue the same 64MiB/600s approval; fetch only declared IN/DL manifests."""
import datetime,hashlib,io,json,pathlib,signal,struct,sys,time,zlib
from preflight import Client,Stop,ROOT,key,config
sys.path.insert(0,str(ROOT.parent/'updater-core'))
from stream_blte import StreamObjectSpec,verify_stream
from catalogue_readers import parse_install,DownloadReader

def decode_verified(raw,spec):
 proof=verify_stream(io.BytesIO(raw),spec)
 hs=int.from_bytes(raw[4:8],'big');parts=[]
 if hs:
  rows=[struct.unpack_from('>II',raw,12+24*i) for i in range(int.from_bytes(raw[9:12],'big'))];pos=hs
 else:rows=[(len(raw)-8,spec.decoded_size)];pos=8
 for n,out in rows:
  b=raw[pos:pos+n];pos+=n
  if b[:1]==b'N':value=b[1:]
  else:
   z=zlib.decompressobj();value=z.decompress(b[1:],out+1)
   if len(value)!=out or not z.eof or z.unconsumed_tail or z.unused_data:raise Stop('decode_geometry')
  if len(value)!=out:raise Stop('decode_length')
  parts.append(value)
 data=b''.join(parts)
 if len(data)!=spec.decoded_size or hashlib.md5(data).hexdigest()!=spec.ckey:raise Stop('decoded_identity')
 return data,proof

def run():
 report=json.loads((ROOT/'preflight-report.json').read_text());c=Client()
 elapsed=(datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(report['started_utc'])).total_seconds()
 c.started=time.monotonic()-elapsed;c.used=report['body_bytes_received'];c.receipts=report['requests']
 report['manifests']={}
 try:
  if report['status']!='version_and_configs_verified' or elapsed>=600:raise Stop('continuation_not_allowed')
  signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('deadline')));signal.alarm(max(1,int(600-elapsed)))
  build=config((ROOT/'build.config').read_bytes(),report['build_config_hash']);root='https://'+report['cdn_host']+'/'+report['cdn_path']
  for name in ('install','download'):
   keys=build[name].split();sizes=build[name+'-size'].split()
   if len(keys)!=2 or len(sizes)!=2 or not all(x.isdecimal() for x in sizes):raise Stop('metadata_pair_required')
   ck,ek=map(key,keys);ds,es=map(int,sizes)
   if not 0<ds<=16*1024**2 or not 9<=es<=16*1024**2 or es>64*1024**2-c.used:raise Stop('manifest_budget')
   raw=c.fetch(root+'/data/'+ek[:2]+'/'+ek[2:4]+'/'+ek,es,es)
   data,proof=decode_verified(raw,StreamObjectSpec(ck,ek,ds,es))
   (ROOT/(name+'.blte')).write_bytes(raw);(ROOT/(name+'.metadata')).write_bytes(data)
   entry={'ckey':ck,'ekey':ek,'encoded_bytes':es,'decoded_bytes':ds,'full_ckey_verified':proof['full_ckey_verified'],'full_ekey_verified':proof['full_ekey_verified'],'decoded_sha256':proof['decoded_sha256'],'header_hex':data[:11].hex()}
   report['manifests'][name]=entry
   if name=='install':
    tags,records=parse_install(data);entry['layout']='IN_v1';entry['entry_count']=len(records);entry['tag_count']=len(tags)
   else:
    # Unknown layouts remain unknown; no guessed offsets or game fetch fallback.
    try:
     reader=DownloadReader(io.BytesIO(data),len(data));records=list(reader.records());tags=list(reader.tags());entry['layout']='DL_v1';entry['entry_count']=len(records);entry['tag_count']=len(tags)
    except Exception as e:entry['layout']='unqualified';entry['parser_stop_reason']=str(e)
  report['status']='small_manifests_identity_verified'
 except Exception as e:report['status']='stopped_safely';report['stop_reason']=str(e) if isinstance(e,Stop) else type(e).__name__
 finally:
  report['body_bytes_received']=c.used;report['elapsed_seconds']=round(time.monotonic()-c.started,3)
  (ROOT/'preflight-report.json').write_text(json.dumps(report,indent=2)+'\n')
 return report
if __name__=='__main__':
 r=run();print(json.dumps({k:r[k] for k in ('status','body_bytes_received','elapsed_seconds','manifests')},indent=2))
