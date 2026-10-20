import ctypes,os
os.environ.setdefault("SystemRoot",r"C:\Windows")
import sys,unittest,tempfile,struct,socket,json
from pathlib import Path
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from passive_packets import *
from capture_platform import Capture,WNODE,PROPERTIES,sessions

def dnswire(name):return b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'
def hello(name='example.com'):
 n=name.encode();entry=b'\0'+len(n).to_bytes(2,'big')+n;names=len(entry).to_bytes(2,'big')+entry
 ext=b'\0\0'+len(names).to_bytes(2,'big')+names
 body=b'\3\3'+b'X'*32+b'\0\0\2\0\x2f\1\0'+len(ext).to_bytes(2,'big')+ext
 hs=b'\1'+len(body).to_bytes(3,'big')+body
 return b'\x16\3\1'+len(hs).to_bytes(2,'big')+hs

def tcp(payload,src='10.0.0.2',dst='1.1.1.1',sp=40000,dp=443,seq=100,flags=24):
 th=struct.pack('!HHIIBBHHH',sp,dp,seq,0,80,flags,1000,0,0)
 ih=struct.pack('!BBHHHBBH4s4s',69,0,20+len(th)+len(payload),1,0,64,6,0,socket.inet_aton(src),socket.inet_aton(dst))
 return b'\0'*12+b'\x08\x00'+ih+th+payload

def block(kind,body,endian='<'):
 body+=b'\0'*((-len(body))%4);n=len(body)+12
 return struct.pack(endian+'II',kind,n)+body+struct.pack(endian+'I',n)
def pcap(data,endian='<'):
 sh=block(0x0a0d0d0a,struct.pack(endian+'IHHq',0x1a2b3c4d,1,0,-1),endian)
 idb=block(1,struct.pack(endian+'HHI',1,0,4096),endian)
 epb=block(6,struct.pack(endian+'IIIII',0,0,100000000,len(data),len(data))+data,endian)
 return sh+idb+epb

def packet(data,ts=100):return {'data':data,'linktype':1,'timestamp':ts,'capture_truncated':False,'interface':(0,0)}
def analyzer():return Analyzer({('10.0.0.2',40000,'1.1.1.1',443):[{'process_index':1,'first_seen_epoch':100,'last_seen_epoch':120}]})
class Tests(unittest.TestCase):
 def test_native_structures(self):self.assertEqual(ctypes.sizeof(WNODE),48);self.assertEqual(ctypes.sizeof(PROPERTIES),120)
 def test_pcapng_little(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.pcapng';p.write_bytes(pcap(tcp(hello())));r=list(packets(p));self.assertEqual(len(r),1);self.assertEqual(r[0]['timestamp'],100)
 def test_pcapng_big(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.pcapng';p.write_bytes(pcap(tcp(hello()),'>'));self.assertEqual(list(packets(p))[0]['timestamp'],100)
 def test_pcap_bad_trailer(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a';b=pcap(tcp(hello()));p.write_bytes(b[:-4]+b'BAD!')
   with self.assertRaises(ValueError):list(packets(p))
 def test_ip_tcp(self):
  p=ip_packet(tcp(b'abc'),1);self.assertEqual(p['src'],'10.0.0.2');self.assertEqual(p['declared_payload_bytes'],3)
 def test_ip_fragment_not_guessed(self):
  b=bytearray(tcp(b'abc'));b[20:22]=b'\x20\0';self.assertIsNone(ip_packet(b,1))
 def test_unsupported_link(self):self.assertIsNone(ip_packet(b'abc',999))
 def test_sni(self):self.assertEqual(clienthello_sni(hello()),('example.com','clienthello_outer_sni'))
 def test_sni_partial(self):self.assertIsNone(clienthello_sni(hello()[:-1])[0])
 def test_sni_cross_records(self):
  h=hello()[5:];a=h[:30];b=h[30:];raw=b'\x16\3\1'+len(a).to_bytes(2,'big')+a+b'\x16\3\1'+len(b).to_bytes(2,'big')+b
  self.assertEqual(clienthello_sni(raw)[0],'example.com')
 def test_not_tls(self):self.assertIsNone(clienthello_sni(b'GET / HTTP/1.1\r\n')[0])
 def test_domain_rejects_ip(self):self.assertIsNone(domain('1.1.1.1'))
 def test_dns_response_compressed(self):
  d=struct.pack('!HHHHHH',1,0x8180,1,1,0,0)+dnswire('example.com')+struct.pack('!HH',1,1)+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+b'\1\1\1\1'
  r=dns_message(d);self.assertEqual(r['questions'][0]['domain'],'example.com');self.assertEqual(r['answers'][0]['ip'],'1.1.1.1')
 def test_dns_loop_rejected(self):
  with self.assertRaises(ValueError):dns_name(b'\xc0\x00',0)
 def test_analyzer_sni_attributed(self):
  a=analyzer();a.add(packet(tcp(hello())));r=a.finish()['selected_process_tcp_flows'][0];self.assertEqual(r['sni'],'example.com');self.assertEqual(r['process_index'],1)
 def test_analyzer_fragmented_tcp(self):
  a=analyzer();h=hello();a.add(packet(tcp(h[:40],seq=100)));a.add(packet(tcp(h[40:],seq=140),101));self.assertEqual(a.finish()['selected_process_tcp_flows'][0]['sni'],'example.com')
 def test_syn_first_out_of_order(self):
  a=analyzer();h=hello();a.add(packet(tcp(b'',seq=99,flags=2)));a.add(packet(tcp(h[40:],seq=140)));a.add(packet(tcp(h[:40],seq=100)))
  self.assertEqual(a.finish()['selected_process_tcp_flows'][0]['sni'],'example.com')
 def test_gap_not_guessed(self):
  a=analyzer();h=hello();a.add(packet(tcp(h[:20],seq=100)));a.add(packet(tcp(h[40:],seq=140)));self.assertIsNone(a.finish()['selected_process_tcp_flows'][0]['sni'])
 def test_unrelated_tuple_not_attributed(self):
  a=analyzer();a.add(packet(tcp(hello(),sp=50000)));self.assertEqual(a.finish()['selected_process_tcp_flows'],[])
 def test_conflicting_owners_not_attributed(self):
  a=analyzer();a.ownership[('10.0.0.2',40000,'1.1.1.1',443)].append({'process_index':None,'first_seen_epoch':100,'last_seen_epoch':120})
  a.add(packet(tcp(hello())));self.assertEqual(a.finish()['selected_process_tcp_flows'],[])
 def test_outside_time_window_not_attributed(self):
  a=analyzer();a.add(packet(tcp(hello()),50));self.assertEqual(a.finish()['selected_process_tcp_flows'],[])
 def test_volume_is_not_unique(self):
  a=analyzer();p=packet(tcp(hello()));a.add(p);a.add(p);r=a.finish();self.assertEqual(r['selected_process_tcp_flows'][0]['outgoing_tcp_payload_bytes_observed'],2*len(hello()));self.assertTrue(r['retransmissions_duplicate_capture_interfaces_offload_and_packet_loss_not_corrected'])
 def test_incoming_direction(self):
  a=analyzer();a.add(packet(tcp(b'xyz',src='1.1.1.1',dst='10.0.0.2',sp=443,dp=40000)));self.assertEqual(a.finish()['selected_process_tcp_flows'][0]['incoming_tcp_payload_bytes_observed'],3)
 def test_http_credentials_not_exported(self):
  a=analyzer();raw=b'GET /secret?token=SECRET HTTP/1.1\r\nHost: example.com\r\nAuthorization: SECRET\r\n\r\n'
  a.add(packet(tcp(raw)));r=a.finish();self.assertEqual(r['selected_process_tcp_flows'][0]['plaintext_http_host'],'example.com');self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('/secret',json.dumps(r))
 def test_owned_capture_stop_only(self):
  cap=Capture(r'C:\tool\run-123');cap.started=True;row={'name':'PktMon','handle':4,'file':r'C:\tool\run-123\pktmon-owned1.etl','events_lost':0,'log_buffers_lost':0};cap.owner=row;calls=[];cap.command=lambda args:(calls.append(args) or (0,''))
  with patch('capture_platform.sessions',return_value=[row]):cap.stop()
  self.assertEqual(calls,[['stop']]);self.assertTrue(cap.stop_verified)
 def test_foreign_capture_not_stopped(self):
  cap=Capture(r'C:\tool\run-123');cap.started=True;cap.owner={'name':'PktMon','handle':4};calls=[];cap.command=lambda args:(calls.append(args) or (0,''))
  with patch('capture_platform.sessions',return_value=[{'name':'PktMon','handle':5,'file':r'C:\other\PktMon.etl'}]):
   with self.assertRaises(ValueError):cap.stop()
  self.assertEqual(calls,[])
 def test_unowned_start_recovery_requires_exact_folder(self):
  cap=Capture(r'C:\tool\run-123');cap.started=True;calls=[];cap.command=lambda args:(calls.append(args) or (0,''))
  with patch('capture_platform.sessions',return_value=[{'name':'PktMon','handle':5,'file':r'C:\other\pktmon-owned1.etl'}]):
   with self.assertRaises(ValueError):cap.stop()
  self.assertEqual(calls,[])
 def test_session_query_starts_with_small_supported_count(self):
  import types
  def query(props,count,n):n._obj.value=0;return 0
  api=Mock(side_effect=query)
  with patch('capture_platform.c.WinDLL',create=True,return_value=types.SimpleNamespace(QueryAllTracesW=api)):
   self.assertEqual(sessions(),[])
  self.assertEqual(api.call_args.args[1],32)
 def test_session_query_grows_to_reported_actual_count(self):
  import types
  def query(props,count,n):
   if count==32:n._obj.value=40;return 234
   n._obj.value=0;return 0
  api=Mock(side_effect=query)
  with patch('capture_platform.c.WinDLL',create=True,return_value=types.SimpleNamespace(QueryAllTracesW=api)):self.assertEqual(sessions(),[])
  self.assertEqual([c.args[1] for c in api.call_args_list],[32,40])

 def test_plaintext_hardware_marker_checks_no_value_export(self):
  a=analyzer();a.refs={'cpu_model':['LOCAL-CPU-TEST']}
  body=b'{"cpu":"LOCAL-CPU-TEST"}'
  raw=b'POST /data HTTP/1.1\r\nHost: telemetry.example.com\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
  a.add(packet(tcp(raw)));r=a.finish();rq=r['selected_process_tcp_flows'][0]['readable_http_requests'][0]
  self.assertEqual(rq['hardware_literal_categories'],['cpu_model']);self.assertNotIn('LOCAL-CPU-TEST',json.dumps(r));self.assertEqual(a.refs,{})


 def test_pcapng_to_report_integration(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'fixture.pcapng';p.write_bytes(pcap(tcp(hello('game.example.com'))));a=analyzer()
   for row in packets(p):a.add(row)
   r=json.loads(json.dumps(a.finish()));self.assertEqual(r['selected_process_tcp_flows'][0]['sni'],'game.example.com')
 def test_ipv6_tcp_decode(self):
  raw=tcp(b'xyz')[34:]
  h=struct.pack('!IHBB16s16s',6<<28,len(raw),6,64,socket.inet_pton(socket.AF_INET6,'2001:db8::1'),socket.inet_pton(socket.AF_INET6,'2001:db8::2'))
  p=ip_packet(b'\0'*12+b'\x86\xdd'+h+raw,1)
  self.assertEqual(p['src'],'2001:db8::1');self.assertEqual(p['payload'],b'xyz')
 def test_udp_dns_system_not_game_attributed(self):
  d=struct.pack('!HHHHHH',1,0x0100,1,0,0,0)+dnswire('example.com')+struct.pack('!HH',1,1)
  udp=struct.pack('!HHHH',40000,53,len(d)+8,0)+d
  ih=struct.pack('!BBHHHBBH4s4s',69,0,20+len(udp),1,0,64,17,0,socket.inet_aton('10.0.0.2'),socket.inet_aton('1.1.1.1'))
  a=analyzer();a.add(packet(b'\0'*12+b'\x08\x00'+ih+udp));r=a.finish()
  self.assertEqual(r['selected_process_tcp_flows'],[]);self.assertFalse(r['dns_to_game_attribution_proven']);self.assertEqual(len(r['system_dns_observations_not_process_attributed']),1)

if __name__=='__main__':unittest.main(verbosity=2)
