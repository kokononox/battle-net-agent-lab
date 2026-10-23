"""Independent V2 length-walk and negative parser/prefix tests; no decryption."""
import json,hashlib,copy
from reassemble import rebuild,D
from frame import parse,check_prefix
r=json.loads((D/'reports/framing.json').read_text());streams=[x for x in rebuild() if x['has_syn']];checked=0;buffers={}
for s in streams:
 b=s['data'];buffers[(s['flow'],s['direction'])]=b;row=next(x for x in r['streams'] if x['flow']==s['flow'] and x['direction']==s['direction']);assert hashlib.sha256(b).hexdigest()==row['stream_sha256'];at=53;out=[]
 while at<len(b):
  # Independent integers / slices, deliberately not the producer parser.
  n=int.from_bytes(b[at:at+4],'little');assert n>=4 and at+16+n<=len(b);zero=not any(b[at+4:at+16]);opcode=hex(int.from_bytes(b[at+16:at+20],'little')) if zero else None
  out.append((at,n,zero,opcode));at+=16+n
 assert at==len(b) and len(out)==row['message_count']
 for x,f in zip(out,row['frames']):assert x==(f['stream_offset'],f['payload_length_including_opcode'],f['tag_is_zero'],f['clear_opcode_hex'])
 assert all(x[2] for x in out[:2]) and all(not x[2] for x in out[2:]);checked+=len(out)
assert checked==319 and r['totals']['clear_prefix_messages']==12 and r['totals']['opaque_nonzero_tag_messages']==307
refs=json.loads((D/'reference/public-sources.json').read_text());assert len(refs['sources'])==6
for source in refs['sources']:
 for ex in source['excerpts']:assert hashlib.sha256(ex['text'].encode()).hexdigest()==ex['sha256']
text='\n'.join(ex['text'] for source in refs['sources'] for ex in source['excerpts']);assert all(op in text for op in ['CMSG_AUTH_SESSION','CMSG_AUTH_CONTINUED_SESSION','SMSG_AUTH_CHALLENGE','SMSG_ENTER_ENCRYPTED_MODE','CMSG_ENTER_ENCRYPTED_MODE_ACK'])
# Seven malformed/changed-prefix cases must be rejected, not silently resynchronized.
tests=[];b=buffers[('F03','server_to_client')]
for label in ['wrong_banner_version','zero_payload_length','oversized_payload_length','partial_body','partial_header','wrong_challenge_opcode','enable_bit_disabled']:
 changed=bytearray(b)
 if label=='wrong_banner_version':changed[50]=ord('3')
 elif label=='zero_payload_length':changed[53:57]=bytes(4)
 elif label=='oversized_payload_length':changed[53:57]=(2**31).to_bytes(4,'little')
 elif label=='partial_body':changed=changed[:-1]
 elif label=='partial_header':changed=changed[:54]
 elif label=='wrong_challenge_opcode':changed[69:73]=(0x123456).to_bytes(4,'little')
 elif label=='enable_bit_disabled':changed[226]=0
 try:
  fs=parse(bytes(changed),'server_to_client');check_prefix(bytes(changed),fs,'server_to_client')
 except AssertionError:tests.append({'case':label,'rejected':True})
 else:raise AssertionError(label)
# Clear prefix remains fully parsed; opaque opcode is never mislabeled from random body bytes.
for s in streams:
 for f in parse(s['data'],s['direction'])[2:]:assert f['clear_opcode_hex'] is None and f['matched_reference_name'] is None
result={'baseline_stream_hashes_checked_again':True,'outer_frames_independently_walked':checked,'clear_prefix_messages':12,'opaque_nonzero_tag_messages':307,'public_excerpt_hashes_checked':True,'negative_tests':tests,'opaque_opcodes_not_interpreted':True,'limits':'Independent walk checks framing, not AEAD tags, cipher keys, server implementation identity, exact client build, or hardware fields. Negative tests do not constitute full parser fuzzing.'}
(D/'reports/verification.json').write_text(json.dumps(result,indent=2)+'\n');print('Independent walk:',checked,'frames; negative cases rejected:',len(tests))
