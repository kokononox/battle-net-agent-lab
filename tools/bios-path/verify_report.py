"""Independent file-offset/RVA and reported-byte checks; no analyzer/pefile import.
Does NOT independently validate CFG, API semantics or runtime behavior.
"""
import hashlib,struct
def require(condition,message):
 if not condition:raise ValueError(message)
PIN='1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a'
def verify(path,r):
 b=open(path,'rb').read();sha=hashlib.sha256(b).hexdigest();require(sha==r['input']['sha256'],'Input SHA mismatch')
 nt=struct.unpack_from('<I',b,0x3c)[0];count=struct.unpack_from('<H',b,nt+6)[0];opt_size=struct.unpack_from('<H',b,nt+20)[0]
 sections=[]
 for i in range(count):
  off=nt+24+opt_size+40*i;vs,va,n,raw=struct.unpack_from('<IIII',b,off+8);sections.append((va,va+n,raw))
 def data(rva,n):
  for lo,hi,raw in sections:
   if lo<=rva and rva+n<=hi:return b[raw+rva-lo:raw+rva-lo+n]
  raise AssertionError('Unmapped reported RVA')
 require(r['profile']['matched'] == (sha==PIN),'Profile does not match the pinned hash')
 require(r['profile']['message_layout_hints_enabled']==(sha==PIN),'Unsafe layout hints')
 expected={'input_executed','input_modified','hardware_read_executed_proven','hardware_population_proven','serialization_of_hardware_proven','runtime_send_proven','destination_or_port_3724_binding_proven'}
 require(set(r['claims'])==expected,'Claims schema mismatch')
 require(all(v is False for v in r['claims'].values()),'Unsupported claim')
 nlit=ncode=nptr=0
 for item in r['literals']:
  expected_bytes=(item['text']+'\0').encode(item['encoding'])
  for h in item['occurrences']:
   require(data(h['rva'],len(expected_bytes))==expected_bytes,'Literal bytes mismatch');nlit+=1
 for h in r['code_candidates']:
  raw=bytes.fromhex(h['bytes']);require(data(h['site_rva'],len(raw))==raw,'Instruction bytes mismatch')
  # Candidate scanner supports an optional REX + opcode + RIP ModRM + disp32.
  i=1 if 0x40<=raw[0]<=0x4f else 0
  require(raw[i] in (0x8b,0x8d,0x89,0xff),'Unexpected candidate opcode')
  require(raw[i+1]&0xc7==5,'Not a supported RIP-relative operand')
  disp=struct.unpack_from('<i',raw,i+2)[0]
  require(h['site_rva']+len(raw)+disp==h['target_rva'],'RIP target mismatch');ncode+=1
 for h in r['data_pointer_candidates']:
  target=struct.unpack('<Q',data(h['site_rva'],8))[0]-r['input']['image_base']
  require(target==h['target_rva'],'Data pointer target mismatch');nptr+=1
 for f in r['functions']:
  for w in f['offset_only_write_candidates']:
   require(w['object_identity_proven'] is False,'Unproven object identity')
   require(sha==PIN,'Offset hints in an unknown build')
 return {'status':'PASS','checks':{'literal_byte_locations':nlit,'code_candidate_bytes_and_rip_targets':ncode,'data_pointer_bytes':nptr,'hash_profile_and_claim_guards':True},
  'scope':'Independent manual PE mapping and byte/target/claim checks only; NOT CFG correctness, object identity, import semantics, runtime behavior or port binding.'}
