"""Bounded, offline CASC early-download comparison. Candidate evidence, not identity proof."""
import csv,hashlib,hmac,io,json,os,re,stat,time
from pathlib import Path
import lookup3
MIB=1024*1024
PREFIX=MIB
MAX_ARCHIVES=64
MAX_RECORDS=64
BUDGET=128*MIB
MAX_MANIFEST=8*MIB
SCHEMA='casc-phase1-private-snapshot-1'
LABELS=('A1','A2','B1')
class Refused(Exception):pass

def safe(path):
 p=Path(os.path.abspath(path))
 for q in reversed((p,*p.parents)):
  try:s=q.lstat()
  except FileNotFoundError:raise Refused('path_missing')
  if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0)&0x400:raise Refused('link_or_reparse')
  if q!=p and not stat.S_ISDIR(s.st_mode):raise Refused('ancestor_not_directory')
 return p

def fp(s):return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_nlink)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def token(key,domain,raw):return hmac.new(key,domain.encode('ascii')+b'\x00'+raw,hashlib.sha256).hexdigest()
def key_ok(key):
 if type(key)is not bytes or len(key)!=32:raise Refused('invalid_comparison_key')
 return key

def resolve(root):
 r=safe(root)
 if not r.is_dir():raise Refused('directory_required')
 if r.name.casefold()=='_retail_':r=safe(r.parent)
 elif r.name.casefold()=='data'and r.parent.name.casefold()=='data':r=safe(r.parent.parent)
 return r,safe(r/'Data'/'data')

def scan_names(folder):
 names=[]
 with os.scandir(folder)as it:
  for item in it:
   names.append(item.name)
   if len(names)>4096:raise Refused('directory_entry_limit')
 archives=[];indices=[];seen=set()
 for name in sorted(names):
  m=re.fullmatch(r'data\.([0-9]{3,5})',name,re.I)
  if m:
   n=int(m[1])
   if n>65535:raise Refused('archive_id_limit')
   if n in seen:raise Refused('duplicate_archive_id')
   seen.add(n);archives.append((n,name))
  elif re.fullmatch(r'[0-9a-f]{10}\.idx',name,re.I):indices.append(name)
 return sorted(archives),indices

class Reader:
 def __init__(self):self.used=0;self.watched=[];self.deadline=time.monotonic()+180
 def read(self,path,limit,whole=False):
  p=safe(path);s=p.stat()
  if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1:raise Refused('not_regular_unshared')
  if whole and s.st_size>limit:raise Refused('file_size_limit')
  n=min(s.st_size,limit)
  if self.used+n>BUDGET:raise Refused('read_budget_limit')
  before=fp(s);chunks=[];remaining=n
  with p.open('rb')as f:
   if fp(os.fstat(f.fileno()))!=before:raise Refused('source_changed')
   while remaining:
    if time.monotonic()>self.deadline:raise Refused('sampled_time_limit')
    b=f.read(min(65536,remaining))
    if not b:raise Refused('source_changed')
    self.used+=len(b);remaining-=len(b);chunks.append(b)
   if fp(os.fstat(f.fileno()))!=before:raise Refused('source_changed')
  if fp(safe(p).stat())!=before:raise Refused('source_changed')
  self.watched.append((p,before));return b''.join(chunks),s.st_size
 def finish(self):
  for p,before in self.watched:
   if fp(safe(p).stat())!=before:raise Refused('source_changed')

def active_build(raw,key):
 try:rows=list(csv.reader(io.StringIO(raw.decode('utf-8-sig')),delimiter='|'))
 except (UnicodeError,csv.Error):raise Refused('build_info_format')
 if not rows or len(rows)>65 or not 1<=len(rows[0])<=32:raise Refused('build_info_format')
 names=[x.split('!',1)[0].strip()for x in rows[0]]
 if len(set(names))!=len(names)or not {'Product','Active','Version','Build Key'}<=set(names):raise Refused('build_info_format')
 active=[]
 for row in rows[1:]:
  if not any(row):continue
  if len(row)!=len(names):raise Refused('build_info_format')
  r=dict(zip(names,row))
  if r['Product']=='wow'and r['Active']=='1':active.append(r)
 if len(active)!=1:raise Refused('active_retail_build_ambiguous')
 r=active[0]
 if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+',r['Version'])or not re.fullmatch(r'[0-9a-f]{32}',r['Build Key']):raise Refused('build_info_format')
 return token(key,'active-build',canonical({k:r[k]for k in('Product','Version','Build Key')}))

def checksum(h):return len(h)==30 and lookup3.hashlittle(h[:22],0x3D6BE971)==int.from_bytes(h[22:26],'little')
def candidate(raw,archive,key):
 # Conservative STRUCTURAL CANDIDATES only; checksum B and host derivation NOT verified.
 if len(raw)<480:return None
 keys=[]
 for i in range(16):
  h=raw[30*i:30*i+30]
  if h[16:20]!=b'\x1e\x00\x00\x00'or h[20:22]!=b'\x01\x00'or not checksum(h):return None
  keys.append(h[:16][::-1])
 if {k[0]for k in keys}!=set(range(16)):return None
 if archive<=255 and all(k[1]==archive and k[9:]==bytes(7)for k in keys)and len({k[2:9]for k in keys})==1 and keys[0][2:9]!=bytes(7):
  return dict(layout='legacy7_candidate',tag=token(key,'legacy7-candidate',keys[0][2:9]))
 if all(int.from_bytes(k[1:3],'little')==archive for k in keys)and len({k[3:]for k in keys})==1 and keys[0][3:]!=bytes(13):
  return dict(layout='suffix13_candidate',tag=token(key,'suffix13-candidate',keys[0][3:]))
 return None

def records(raw,key):
 out=[];offset=0;valid=0;stop='record_count_limit'
 for _ in range(MAX_RECORDS):
  if offset+30>len(raw):stop='prefix_end_or_short_header';break
  h=raw[offset:offset+30];span=int.from_bytes(h[16:20],'little')
  if span<30:stop='unrecognized_span';break
  if not checksum(h):stop='unverified_header_checksum_a';break
  valid+=1
  if offset+span>len(raw):stop='record_extends_sample';break
  body=raw[offset+30:offset+span]
  if body.startswith(b'BLTE'):
   out.append(dict(record_key=token(key,'encoded-record-key',h[:16][::-1]),body=token(key,'complete-encoded-body',body),size=len(body)))
  offset+=span
 return out,valid,stop

def capture(root,label,key,confirmed=False):
 key_ok(key)
 if label not in LABELS:raise Refused('invalid_sample_label')
 if confirmed is not True:raise Refused('conditions_confirmation_required')
 root,folder=resolve(root);reader=Reader();raw,_=reader.read(root/'.build.info',65536,whole=True);build=active_build(raw,key)
 initial=scan_names(folder);archives,indices=initial
 if not archives:raise Refused('no_archives_yet')
 observed=[]
 for number,name in archives[:MAX_ARCHIVES]:
  raw,size=reader.read(folder/name,PREFIX);items,valid,stop=records(raw,key)
  observed.append(dict(archive=number,size=size,prefix_bytes=len(raw),prefix_tag=token(key,'archive-prefix',raw),candidate=candidate(raw,number,key),records=items,verified_header_a_count=valid,walk_stop=stop))
 idx=[];idx_skipped=0
 for name in indices:
  if len(idx)>=64:idx_skipped+=1;continue
  p=safe(folder/name);s=p.stat()
  if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1:raise Refused('not_regular_unshared')
  if s.st_size>4*MIB or reader.used+s.st_size>BUDGET:idx_skipped+=1;continue
  raw,_=reader.read(p,4*MIB,whole=True);idx.append(dict(name_tag=token(key,'index-filename',name.casefold().encode('ascii')),body=token(key,'whole-index',raw),size=len(raw)))
 reader.finish()
 if scan_names(folder)!=initial:raise Refused('source_directory_changed')
 doc=dict(schema=SCHEMA,label=label,comparison_key_id=token(key,'key-id',b''),build_tag=build,operator_confirmed_conditions=True,bytes_read=reader.used,archives_found=len(archives),archives=observed,indices_found=len(indices),indices_skipped=idx_skipped,indices=idx)
 return dict(document=doc,authentication=token(key,'snapshot-authentication',canonical(doc)))

def write_new(path,data,source_root=None):
 p=Path(os.path.abspath(path));parent=safe(p.parent)
 if source_root is not None:
  root,_=resolve(source_root)
  if p==root or root in p.parents:raise Refused('export_inside_game_refused')
 # No overwrite, no following existing destination links.
 with (parent/p.name).open('xb')as f:f.write(data)

def read_small(path,limit):
 p=safe(path);s=p.stat()
 if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1 or s.st_size>limit:raise Refused('input_file_limit_or_type')
 before=fp(s)
 with p.open('rb')as f:
  if fp(os.fstat(f.fileno()))!=before:raise Refused('source_changed')
  data=f.read(limit+1)
  if fp(os.fstat(f.fileno()))!=before:raise Refused('source_changed')
 if len(data)>limit or fp(safe(p).stat())!=before:raise Refused('source_changed')
 return data

def no_duplicates(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise Refused('duplicate_json_key')
  d[k]=v
 return d

def parse_snapshot(raw,key):
 key_ok(key)
 if len(raw)>MAX_MANIFEST:raise Refused('snapshot_size_limit')
 try:s=json.loads(raw,object_pairs_hook=no_duplicates)
 except (ValueError,UnicodeError,RecursionError):raise Refused('snapshot_format')
 if type(s)is not dict or set(s)!={'document','authentication'}or type(s['authentication'])is not str:raise Refused('snapshot_format')
 d=s['document']
 if not hmac.compare_digest(s['authentication'],token(key,'snapshot-authentication',canonical(d))):raise Refused('wrong_key_or_snapshot_changed')
 validate(d)
 if d['comparison_key_id']!=token(key,'key-id',b''):raise Refused('wrong_key_or_snapshot_changed')
 return d

def validate(d):
 def need(v):
  if not v:raise Refused('snapshot_schema')
 def num(v,hi):return type(v)is int and 0<=v<=hi
 def tag(v):return type(v)is str and re.fullmatch('[0-9a-f]{64}',v)is not None
 need(type(d)is dict and set(d)=={'schema','label','comparison_key_id','build_tag','operator_confirmed_conditions','bytes_read','archives_found','archives','indices_found','indices_skipped','indices'})
 need(d['schema']==SCHEMA and d['label']in LABELS and d['operator_confirmed_conditions']is True and tag(d['comparison_key_id'])and tag(d['build_tag']))
 need(num(d['bytes_read'],BUDGET)and num(d['archives_found'],4096)and num(d['indices_found'],4096)and num(d['indices_skipped'],4096))
 need(type(d['archives'])is list and 1<=len(d['archives'])<=MAX_ARCHIVES and len(d['archives'])<=d['archives_found'])
 seen=set()
 for a in d['archives']:
  need(type(a)is dict and set(a)=={'archive','size','prefix_bytes','prefix_tag','candidate','records','verified_header_a_count','walk_stop'})
  need(num(a['archive'],65535)and a['archive']not in seen);seen.add(a['archive'])
  need(num(a['size'],2**63-1)and num(a['prefix_bytes'],PREFIX)and a['prefix_bytes']<=a['size']and tag(a['prefix_tag'])and num(a['verified_header_a_count'],MAX_RECORDS))
  need(a['walk_stop']in('record_count_limit','prefix_end_or_short_header','unrecognized_span','unverified_header_checksum_a','record_extends_sample'))
  c=a['candidate']
  need(c is None or(type(c)is dict and set(c)=={'layout','tag'}and c['layout']in('legacy7_candidate','suffix13_candidate')and tag(c['tag'])))
  need(type(a['records'])is list and len(a['records'])<=MAX_RECORDS)
  for r in a['records']:need(type(r)is dict and set(r)=={'record_key','body','size'}and tag(r['record_key'])and tag(r['body'])and num(r['size'],PREFIX))
 need(type(d['indices'])is list and len(d['indices'])<=64 and len(d['indices'])+d['indices_skipped']==d['indices_found'])
 seen=set()
 for i in d['indices']:
  need(type(i)is dict and set(i)=={'name_tag','body','size'}and tag(i['name_tag'])and tag(i['body'])and num(i['size'],4*MIB)and i['name_tag']not in seen);seen.add(i['name_tag'])
 return d

def public_capture(d):
 validate(d)
 return dict(schema='casc-phase1-public-capture-1',read_budget_bytes=BUDGET,read_time_limit_seconds=180,read_timeout_is_sampled=True,candidate_layout_counts={k:sum(a['candidate']is not None and a['candidate']['layout']==k for a in d['archives'])for k in ('legacy7_candidate','suffix13_candidate')},candidate_value_variants=len(set(candidate_map(d).values())),archive_walk_stops={k:sum(a['walk_stop']==k for a in d['archives'])for k in ('record_count_limit','prefix_end_or_short_header','unrecognized_span','unverified_header_checksum_a','record_extends_sample')},header_checksum_a_verified_count=sum(a['verified_header_a_count']for a in d['archives']),status='completed',sample=d['label'],bytes_read=d['bytes_read'],archives_found=d['archives_found'],archive_prefixes_sampled=len(d['archives']),archives_not_sampled=d['archives_found']-len(d['archives']),prefix_bytes_per_archive_limit=PREFIX,candidate_blocks=sum(a['candidate']is not None for a in d['archives']),complete_encoded_blte_records_sampled=sum(len(a['records'])for a in d['archives']),whole_indices_hashed=len(d['indices']),indices_skipped=d['indices_skipped'],**limits())

def limits():return dict(whole_game_scanned=False,decoded_game_payloads_compared=False,checksum_b_verified=False,machine_identity_proven=False,hostname_derivation_verified=False,account_identity_proven=False,upload_or_server_receipt_proven=False,network_requested=False,game_executed=False,game_files_written=False,raw_paths_exported=False,raw_hostname_exported=False,raw_marker_values_exported=False,private_comparison_tokens_in_public_report=False)

def candidate_map(d):return {a['archive']:(a['candidate']['layout'],a['candidate']['tag'])for a in d['archives']if a['candidate']is not None}
def payload_map(d):
 result={}
 for a in d['archives']:
  for r in a['records']:result.setdefault(r['record_key'],set()).add((r['body'],r['size']))
 return result

def pair(a,b):
 aa={x['archive']:x for x in a['archives']};bb={x['archive']:x for x in b['archives']};shared=aa.keys()&bb.keys();ca=candidate_map(a);cb=candidate_map(b);cs=ca.keys()&cb.keys()
 pa=payload_map(a);pb=payload_map(b);ps=pa.keys()&pb.keys();ia={x['name_tag']:(x['body'],x['size'])for x in a['indices']};ib={x['name_tag']:(x['body'],x['size'])for x in b['indices']};ii=ia.keys()&ib.keys()
 same_span=[n for n in shared if aa[n]['prefix_bytes']==bb[n]['prefix_bytes']]
 return dict(samples=[a['label'],b['label']],observed_candidate_value_sets_equal=(set(ca.values())==set(cb.values()))if ca and cb else None,common_candidate_values=len(set(ca.values())&set(cb.values())),common_archive_ids=len(shared),equal_length_prefix_pairs=len(same_span),equal_prefix_pairs=sum(aa[n]['prefix_tag']==bb[n]['prefix_tag']for n in same_span),different_equal_length_prefix_pairs=sum(aa[n]['prefix_tag']!=bb[n]['prefix_tag']for n in same_span),common_candidate_archive_ids=len(cs),same_candidate_pairs=sum(ca[n]==cb[n]for n in cs),different_candidate_pairs=sum(ca[n]!=cb[n]for n in cs),common_complete_encoded_record_keys=len(ps),equal_encoded_body_sets=sum(pa[n]==pb[n]for n in ps),different_encoded_body_sets=sum(pa[n]!=pb[n]for n in ps),common_index_names=len(ii),equal_whole_index_pairs=sum(ia[n]==ib[n]for n in ii),different_whole_index_pairs=sum(ia[n]!=ib[n]for n in ii))

def compare(documents,key):
 key_ok(key)
 if not 2<=len(documents)<=3:raise Refused('two_or_three_samples_required')
 docs={}
 for d in documents:
  validate(d)
  if d['label']in docs:raise Refused('duplicate_sample_label')
  if d['comparison_key_id']!=token(key,'key-id',b''):raise Refused('wrong_comparison_key')
  docs[d['label']]=d
 if not {'A1','B1'}<=docs.keys():raise Refused('A1_and_B1_required')
 if len({d['build_tag']for d in docs.values()})!=1:raise Refused('active_build_mismatch')
 pairs=[pair(docs['A1'],docs['B1'])];stable=changed=common=0
 if 'A2'in docs:
  pairs.extend([pair(docs['A1'],docs['A2']),pair(docs['A2'],docs['B1'])]);a,b,c=[candidate_map(docs[k])for k in('A1','A2','B1')];shared=a.keys()&b.keys()&c.keys();common=len(shared);stable=sum(a[n]==b[n]and a[n]!=c[n]for n in shared);changed=sum(a[n]!=b[n]for n in a.keys()&b.keys())
 result='environment_linked_candidate_requires_controls'if stable else'candidate_difference_only'if any(p['different_candidate_pairs']for p in pairs)else'no_distinguishing_candidate_in_sample'
 return dict(schema='casc-phase1-public-comparison-1',status='completed',samples=sorted(docs),same_active_build_metadata=True,operator_conditions_attested_not_verified=True,pairs=pairs,three_way_common_candidate_archives=common,a_repeat_stable_b_distinct_candidate_archives=stable,a_repeat_changed_candidate_archives=changed,assessment=result,evidence_scope='bounded_archive_prefixes_and_selected_whole_indices_only',absence_of_fingerprint_proven=False,**limits())
