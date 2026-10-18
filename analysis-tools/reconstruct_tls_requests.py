import base64,collections,hashlib,json,pathlib,re,sys,zlib
p=pathlib.Path(sys.argv[1]);r=json.loads(p.read_text());out=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else pathlib.Path('analysis-output/tls-values');out.mkdir(exist_ok=True)
groups=collections.defaultdict(list)
for s in r['samples']:
 b=base64.b64decode(s['base64'],validate=True);assert hashlib.sha256(b).hexdigest()==s['sample_sha256']
 if s['api']=='EncryptMessage' and s['context']:groups[(s['pid'],s['process_sha256'],s['context'])].append((s['sequence'],b))
requests=[];pattern=re.compile(rb'(GET|POST|PUT|HEAD|OPTIONS|CONNECT|DELETE|PATCH) ([^\r\n]{1,4096}) HTTP/1\.[01]\r\n')
for (pid,sha,ctx),chunks in groups.items():
 data=b''.join(b for _,b in sorted(chunks));pos=0
 while pos<len(data):
  m=pattern.search(data,pos)
  if not m:break
  hend=data.find(b'\r\n\r\n',m.end())
  if hend<0 or hend-m.start()>16384:break
  header=data[m.start():hend];headers={}
  for line in header.split(b'\r\n')[1:]:
   k,sep,v=line.partition(b':')
   if sep:headers[k.strip().decode('ascii','replace').lower()]=v.strip().decode('latin1')
  start=hend+4;body=b'';complete=True
  if 'chunked' in headers.get('transfer-encoding','').lower():
   cur=start;pieces=[]
   try:
    while True:
     e=data.index(b'\r\n',cur);n=int(data[cur:e].split(b';',1)[0],16);cur=e+2
     if n==0:
      cur+=2;break
     if n>1048576 or cur+n+2>len(data) or data[cur+n:cur+n+2]!=b'\r\n':raise ValueError('chunk_bounds')
     pieces.append(data[cur:cur+n]);cur+=n+2
    body=b''.join(pieces);pos=cur
   except (ValueError,IndexError):complete=False;body=b''.join(pieces);pos=len(data)
  elif headers.get('content-length','').isdigit():
   n=int(headers['content-length']);body=data[start:start+n];complete=len(body)==n;pos=start+len(body)
  else:pos=start
  encoded=body;encoding=headers.get('content-encoding','').lower();decoded=False;decode_status='not_compressed'
  modes=[31] if encoding=='gzip' or body.startswith(b'\x1f\x8b') else ([15,-15] if encoding=='deflate' else ([15] if body[:2] in (b'x\x01',b'x\x9c',b'x\xda') else []))
  if modes:
   decode_status='decompression_failed'
   for mode in modes:
    try:
     z=zlib.decompressobj(mode);plain=z.decompress(body,1048576)
     if z.eof:body=plain;decoded=True;decode_status='decompressed';break
     decode_status='decompression_incomplete'
    except zlib.error:pass
  index=len(requests)+1
  (out/f'request-{index:02d}-body.bin').write_bytes(body)
  strings=[s.decode('ascii') for s in re.findall(rb'[\x20-\x7e]{5,}',body)]
  (out/f'request-{index:02d}-strings.txt').write_text('\n'.join(strings))
  parsed=None
  try:parsed=json.loads(body)
  except (ValueError,UnicodeError):pass
  if parsed is not None:(out/f'request-{index:02d}-decoded.json').write_text(json.dumps(parsed,ensure_ascii=False,indent=2))
  cpu=r['reference'].get('cpu_model');cpu_match=bool(cpu and cpu.encode().lower() in body.lower())
  hints=[s[:240] for s in strings if re.search(r'cpu|gpu|memory|hardware|processor|windows|systeminfo|device',s,re.I)]
  req={'index':index,'pid':pid,'process_sha256':sha,'context':ctx,'method':m.group(1).decode(),'target':m.group(2).decode('latin1'),'host':headers.get('host'),'content_type':headers.get('content-type'),'content_encoding':encoding or None,'transfer_encoding':headers.get('transfer-encoding'),'body_complete':complete,'encoded_body_bytes':len(encoded),'decoded_body_bytes':len(body),'decode_status':decode_status,'json_parsed':parsed is not None,'reference_cpu_model_found':cpu_match,'body_prefix_hex':body[:20].hex(),'hardware_related_strings':hints[:30]}
  requests.append(req)
result={'run_id':r['run_id'],'source_commit':r['source_commit'],'reference':r['reference'],'sample_count':len(r['samples']),'context_groups':len(groups),'requests':requests,'limits':['context stream reconstruction is local API observation, not server acknowledgement','schema unknown for binary bodies','missing samples or reused context address can limit reconstruction']}
(out/'evidence.json').write_text(json.dumps(result,ensure_ascii=False,indent=2));print(json.dumps(result,ensure_ascii=False,indent=2))
