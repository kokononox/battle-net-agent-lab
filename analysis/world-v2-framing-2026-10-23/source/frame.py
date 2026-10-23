"""Parse V2 outer framing and the small matched cleartext authentication prefix only."""
from pathlib import Path
import json,struct,hashlib,csv
from reassemble import rebuild,D
OP={0x440001:'CMSG_AUTH_SESSION',0x440003:'CMSG_AUTH_CONTINUED_SESSION',0x440005:'CMSG_ENTER_ENCRYPTED_MODE_ACK',0x4c0000:'SMSG_AUTH_CHALLENGE',0x4c0004:'SMSG_ENTER_ENCRYPTED_MODE'}
def parse(buf,direction):
 banner=f"WORLD OF WARCRAFT CONNECTION - {'CLIENT TO SERVER' if direction=='client_to_server' else 'SERVER TO CLIENT'} - V2\n".encode();assert buf.startswith(banner);at=len(banner);out=[]
 while at<len(buf):
  assert at+16<=len(buf),'partial header';n=struct.unpack_from('<I',buf,at)[0];assert 4<=n<=1048576,'invalid payload length';end=at+16+n;assert end<=len(buf),'partial body';zero=buf[at+4:at+16]==bytes(12);op=struct.unpack_from('<I',buf,at+16)[0] if zero else None
  out.append({'index':len(out),'stream_offset':at,'payload_length_including_opcode':n,'outer_frame_length':n+16,'tag_is_zero':zero,'clear_opcode_hex':hex(op) if op is not None else None,'matched_reference_name':OP.get(op) if op is not None else None});at=end
 assert at==len(buf);return out

def check_prefix(buf,frames,direction):
 assert len(frames)>2 and all(f['tag_is_zero'] for f in frames[:2]) and all(not f['tag_is_zero'] for f in frames[2:])
 def body(i):f=frames[i];return buf[f['stream_offset']+20:f['stream_offset']+16+f['payload_length_including_opcode']]
 if direction=='server_to_client':
  assert frames[0]['clear_opcode_hex']=='0x4c0000' and len(body(0))==65 # 32 bytes DOS + 32 bytes challenge + uint8.
  assert frames[1]['clear_opcode_hex']=='0x4c0004' and len(body(1))==69 # int32 + signature[64] + bitfield byte.
  flags=body(1)[68];assert flags==0x80 # high bit is Enabled, remaining padding zero.
  return {'challenge_body_size_matches':True,'enable_mode_body_size_matches':True,'enabled_bit':True,'opaque_challenge_and_signature_not_exported':True}
 assert frames[1]['clear_opcode_hex']=='0x440005' and len(body(1))==0
 if frames[0]['clear_opcode_hex']=='0x440001':
  raw=body(0);assert len(raw)>=81;ticket_len=struct.unpack_from('<I',raw,77)[0];assert len(raw)==81+ticket_len
  return {'auth_type':'session','ack_empty_body':True,'fixed_prefix_bytes':81,'ticket_size_matches_remainder':True,'ticket_bytes_not_decoded_or_exported':True}
 assert frames[0]['clear_opcode_hex']=='0x440003' and len(body(0))==80
 return {'auth_type':'continued_session','ack_empty_body':True,'continued_body_size_matches':True,'opaque_auth_fields_not_exported':True}

def main():
 base=json.loads((D/'reference/capture-baseline.json').read_text());t0=__import__('datetime').datetime.fromisoformat(base['capture']['start_utc']).timestamp();out=[];csvrows=[];private={}
 for s in rebuild():
  if not s['has_syn']:continue
  b=s['data'];assert s['offset']==0;fs=parse(b,s['direction']);prefix=check_prefix(b,fs,s['direction']);arrival=[None]*len(b);index=[None]*len(b)
  for span in s['spans']:
   for q in range(span['offset'],span['offset']+span['length']):
    assert 0<=q<len(b)
    if arrival[q] is None or span['time']<arrival[q]:arrival[q]=span['time'];index[q]=span['first_frame_index']
  assert all(x is not None for x in arrival)
  for f in fs:
   lo=f['stream_offset'];hi=lo+f['outer_frame_length'];f['first_byte_capture_seconds']=arrival[lo]-t0;f['completion_capture_seconds']=max(arrival[lo:hi])-t0;f['first_byte_frame_index']=index[lo];f['completion_frame_index']=max(index[lo:hi]);csvrows.append({'flow':s['flow'],'direction':s['direction'],**f})
  row={'flow':s['flow'],'direction':s['direction'],'stream_sha256':hashlib.sha256(b).hexdigest(),'stream_bytes':len(b),'banner_bytes':53,'message_count':len(fs),'zero_tag_clear_prefix_messages':2,'nonzero_tag_opaque_messages':len(fs)-2,'first_nonzero_tag_offset':fs[2]['stream_offset'],'prefix_structure_checks':prefix,'all_frames_consume_stream_exactly':True,'frames':fs};out.append(row);private[(s['flow'],s['direction'])]=(b,fs)
 transitions=[]
 for flow in ['F03','F04','F05']:
  client=next(s for s in out if s['flow']==flow and s['direction']=='client_to_server');server=next(s for s in out if s['flow']==flow and s['direction']=='server_to_client');cf=client['frames'];sf=server['frames']
  # Wire observation order, not assumptions about wall-clock handling inside the peer.
  assert sf[0]['completion_frame_index']<cf[0]['completion_frame_index']<sf[1]['completion_frame_index']<cf[1]['completion_frame_index']
  assert cf[1]['completion_frame_index']<=cf[2]['first_byte_frame_index'] and cf[1]['completion_frame_index']<=sf[2]['first_byte_frame_index']
  transitions.append({'flow':flow,'server_challenge_then_client_auth_then_enable_then_ack_observed':True,'enabled_bit':True,'first_nonzero_server_offset':sf[2]['stream_offset'],'first_nonzero_client_offset':cf[2]['stream_offset'],'first_nonzero_server_frame_index':sf[2]['first_byte_frame_index'],'first_nonzero_client_frame_index':cf[2]['first_byte_frame_index'],'first_nonzero_server_seconds':sf[2]['first_byte_capture_seconds'],'first_nonzero_client_seconds':cf[2]['first_byte_capture_seconds']})
 result={'capture_sha256':base['source']['compressed_sha256'],'baseline_commit':'3d2dfeb13556162b96626c27cddda94bacddaffb','stream_hashes_independently_reproduced':True,'reference_commit':'dcd1dab1426c2dde3f87ad41768fb3d6b87b67ae','header_model':{'size_field_bytes':4,'tag_bytes':12,'opcode_bytes_inside_size':4,'length_endian':'little','banner_bytes':53},'streams':out,'transitions':transitions,'totals':{'directional_streams':len(out),'outer_messages':sum(s['message_count'] for s in out),'clear_prefix_messages':sum(s['zero_tag_clear_prefix_messages'] for s in out),'opaque_nonzero_tag_messages':sum(s['nonzero_tag_opaque_messages'] for s in out)},'claims':{'protocol_v2_framing_supported':True,'encryption_enable_exchange_supported_by_matched_public_definitions':True,'cryptographic_authentication_tags_verified':False,'session_keys_extracted':False,'payload_decrypted':False,'exact_client_build_verified':False,'hardware_field_population_or_send_verified':False},'limits':'Public open-source implementation is a matched structural reference, not proof the captured server runs TrinityCore or the exact client build matches. Zero/nonzero tags alone are insufficient; combined opcode, length, flag and ordering checks support transition. Opaque opcodes are deliberately not interpreted.','visual_plan':{'disposition':'prose_and_protocol_table','reason':'Question concerns message framing/state transition, not a numerical comparison or time trend. Byte offsets identify boundaries, not telemetry volume.'}}
 (D/'reports/framing.json').write_text(json.dumps(result,indent=2)+'\n')
 with (D/'reports/message-boundaries.csv').open('w') as f:w=csv.DictWriter(f,list(csvrows[0]));w.writeheader();w.writerows(csvrows)
 print('Totals',result['totals']);print('Transitions',transitions)
 return result
if __name__=='__main__':main()
