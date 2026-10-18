"""Bounded metadata-only transfer and streaming N/Z BLTE verification.
No archive/game paths, game asset lists, repair, install, shell or ACL operations.
"""
from pathlib import Path
import hashlib,struct,zlib,json,urllib.request,urllib.error,http.client,datetime
from release_core import need,InvalidRelease,NoRedirect,TargetSnapshot,digest,CAP
from config_binding import bind,ManifestDescriptor
BLOCK=65536

def decode_file(source,dest,spec):
 need(type(spec)is ManifestDescriptor,'descriptor_required');need(source.stat().st_size==spec.encoded_size,'encoded_size_conflict');need(not dest.exists(),'decoded_output_exists');tmp=dest.with_suffix('.partial');need(not tmp.exists(),'decoded_partial_exists')
 total=0;md=hashlib.md5();sha=hashlib.sha256();chunks=0
 with source.open('rb') as f,tmp.open('xb') as out:
  def exact(n):
   b=f.read(n);need(len(b)==n,'blte_truncated');return b
  first=exact(8);need(first[:4]==b'BLTE','blte_magic');hs=int.from_bytes(first[4:],'big')
  if hs:
   need(12<=hs<=12+65536*24 and hs<=spec.encoded_size,'blte_header_size');header=first+exact(hs-8);need(header[8]==15,'blte_flags');count=int.from_bytes(header[9:12],'big');need(0<count<=65536 and hs==12+24*count,'blte_chunk_table');need(hashlib.md5(header).hexdigest()==spec.ekey,'encoded_header_ekey_conflict')
   rows=[]
   for i in range(count):
    at=12+24*i;cs,ds=struct.unpack_from('>II',header,at);need(cs>0 and ds>0,'blte_chunk_size');rows.append((cs,ds,header[at+8:at+24]))
   need(sum(r[0] for r in rows)+hs==spec.encoded_size and sum(r[1] for r in rows)==spec.decoded_size,'blte_declared_geometry')
  else:
   with source.open('rb') as g:need(hashlib.file_digest(g,'md5').hexdigest()==spec.ekey,'headerless_ekey_conflict')
   rows=[(spec.encoded_size-8,spec.decoded_size,None)]
  for cs,ds,wanted in rows:
   ch=hashlib.md5();mode=exact(1);ch.update(mode);need(mode in (b'N',b'Z'),'unsupported_blte_mode');z=zlib.decompressobj() if mode==b'Z' else None;remain=cs-1;written=0
   def emit(raw):
    nonlocal written,total
    written+=len(raw);total+=len(raw);need(written<=ds and total<=spec.decoded_size,'blte_decoded_limit');out.write(raw);md.update(raw);sha.update(raw)
   while remain:
    raw=exact(min(BLOCK,remain));remain-=len(raw);ch.update(raw)
    if z is None:emit(raw)
    else:
     pending=raw
     while pending:
      decoded=z.decompress(pending,min(BLOCK,ds-written+1));emit(decoded);next_data=z.unconsumed_tail;need(not z.unused_data,'zlib_trailing');need(not next_data or decoded or len(next_data)<len(pending),'zlib_no_progress');pending=next_data
   if z is not None:
    while True:
     raw=z.decompress(b'',min(BLOCK,ds-written+1));emit(raw)
     if not raw:break
    need(z.eof and not z.unused_data and not z.unconsumed_tail,'zlib_truncated_or_trailing')
   need(written==ds,'blte_chunk_decoded_size');need(wanted is None or ch.digest()==wanted,'blte_chunk_checksum');chunks+=1
  need(not f.read(1) and total==spec.decoded_size and md.hexdigest()==spec.ckey,'decoded_content_ckey_conflict')
 tmp.rename(dest)
 with dest.open('rb') as g:need(hashlib.file_digest(g,'md5').hexdigest()==spec.ckey,'decoded_readback_conflict')
 return {'name':spec.name,'encoded_bytes':spec.encoded_size,'decoded_bytes':total,'ckey':md.hexdigest(),'decoded_sha256':sha.hexdigest(),'ekey':spec.ekey,'blte_chunks_verified':chunks,'decoded_readback_verified':True}

class MetadataSession:
 def __init__(self,target,specs,byte_budget):
  need(type(target)is TargetSnapshot,'target_type');need({s.name for s in specs}=={'install','download','encoding'} and len(specs)==3,'only_three_metadata_objects');need(sum(s.encoded_size for s in specs)==byte_budget,'approval_byte_budget_conflict');self.allowed={target.origins[0]+'/tpr/wow/data/'+s.ekey[:2]+'/'+s.ekey[2:4]+'/'+s.ekey:s for s in specs};need(len(self.allowed)==3,'metadata_url_alias_requires_review');self.used=0;self.requested=set();self.budget=byte_budget
 def fetch(self,url,output):
  need(url in self.allowed and url not in self.requested,'object_request_not_approved');self.requested.add(url);s=self.allowed[url];need(not output.exists(),'encoded_output_exists');partial=output.with_suffix('.partial');need(not partial.exists(),'encoded_partial_exists')
  req=urllib.request.Request(url,headers={'User-Agent':'WoW-Updater-Metadata-Research/0.5','Accept-Encoding':'identity'})
  md=hashlib.md5();sha=hashlib.sha256();n=0
  try:response=urllib.request.build_opener(NoRedirect).open(req,timeout=90)
  except urllib.error.HTTPError as e:e.close();raise
  with response as r:
   need(r.status==200 and r.geturl()==url and not r.headers.get('Content-Range') and r.headers.get('Content-Encoding','identity').lower() in ('','identity'),'object_response_invalid');length=r.headers.get('Content-Length');need(length==str(s.encoded_size),'object_response_size')
   with partial.open('xb') as f:
    while n<s.encoded_size:
     limit=min(BLOCK,s.encoded_size-n)
     try:raw=r.read(limit)
     except http.client.IncompleteRead as e:self.used+=len(e.partial);raise
     need(type(raw)is bytes and 0<len(raw)<=limit,'object_truncated_or_oversized_read');n+=len(raw);self.used+=len(raw);need(self.used<=self.budget,'approved_byte_limit');f.write(raw);md.update(raw);sha.update(raw)
  partial.rename(output);return {'encoded_file_sha256':sha.hexdigest(),'encoded_file_md5_not_always_ekey':md.hexdigest()}

def run(base,out):
 observation=json.loads((base/'LIVE-CONFIG-BINDING.json').read_bytes());target=TargetSnapshot.restore(observation['target']);actual=bind(target,(base/'observed-build.config').read_bytes(),(base/'observed-cdn.config').read_bytes());need(actual=={k:v for k,v in observation.items() if k not in ('config_requests','config_bytes','observed_at_utc')},'bound_receipt_changed')
 specs=tuple(ManifestDescriptor(**d) for d in actual['manifest_descriptors']);budget=sum(s.encoded_size for s in specs);approval=json.loads((out/'APPROVAL.json').read_bytes());need(approval['approved'] is True and approval['target']==target.public() and approval['expected_encoded_bytes']==budget,'approval_missing_or_mismatch');session=MetadataSession(target,specs,budget);records=[]
 for url,s in session.allowed.items():
  print('Receiving metadata:',s.name,s.encoded_size,flush=True);enc=out/(s.name+'.blte');transfer=session.fetch(url,enc);proof=decode_file(enc,out/(s.name+'.decoded'),s);proof.update(transfer);records.append(proof);(out/(s.name+'-VERIFIED.json')).write_text(json.dumps(proof,indent=2)+'\n');print('Verified:',s.name,proof['decoded_bytes'],flush=True)
 report={'format':'approved-dynamic-metadata-receipt-1','status':'three_metadata_objects_identity_and_blte_verified','target':target.public(),'metadata':records,'network_requests':len(session.requested),'encoded_metadata_network_bytes':session.used,'approved_encoded_byte_budget':budget,'game_asset_requests':0,'live_game_or_lab_access':False,'installation_ready':False,'apply_authorized':False,'required_game_download_bytes':None,'completed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()};(out/'METADATA-VERIFIED-to-share.json').write_text(json.dumps(report,indent=2)+'\n');return report
if __name__=='__main__':
 try:
  import argparse
  parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binding-workspace',type=Path,required=True);parser.add_argument('--objects-workspace',type=Path,required=True);args=parser.parse_args()
  result=run(args.binding_workspace,args.objects_workspace);print(json.dumps({'status':result['status'],'bytes':result['encoded_metadata_network_bytes'],'game_asset_requests':0}))
 except Exception as e:
  print('Stopped:',str(e) if isinstance(e,InvalidRelease) else type(e).__name__,flush=True);raise SystemExit(2)
