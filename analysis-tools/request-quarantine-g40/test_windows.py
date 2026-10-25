"""Windows-only synthetic private-store and native Job/loopback integration."""
import ctypes as C
from ctypes import wintypes as W
import json,os,socket,subprocess,sys,tempfile,threading,time,unittest,uuid,shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import quarantine as q
from windows_store import WindowsStore
import peer_guard as peer
import domain_proxy as protocol
from quarantine_handler import LoopbackServer
HELPER=os.environ['G40_STORE_HELPER']
MARKER='SYNTHETIC-G40-DEVICE-ID'
RAW=('GET /fixture?device='+MARKER+' HTTP/1.1\r\nHost: level3.blizzard.com\r\nCookie: SYNTHETIC-SECRET\r\nX-Device: '+MARKER+'\r\n\r\n').encode()
K=peer.K
K.CreateJobObjectW.argtypes=[C.c_void_p,W.LPCWSTR];K.CreateJobObjectW.restype=W.HANDLE
K.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE];K.AssignProcessToJobObject.restype=W.BOOL
K.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD];K.SetInformationJobObject.restype=W.BOOL
class Limit(C.Structure):_fields_=[('a',C.c_int64),('b',C.c_int64),('flags',W.DWORD),('min',C.c_size_t),('max',C.c_size_t),('active',W.DWORD),('affinity',C.c_size_t),('priority',W.DWORD),('scheduling',W.DWORD)]
class IO(C.Structure):_fields_=[(x,C.c_uint64) for x in 'abcdef']
class Extended(C.Structure):_fields_=[('basic',Limit),('io',IO),('a',C.c_size_t),('b',C.c_size_t),('c',C.c_size_t),('d',C.c_size_t)]

def identity():
 h=K.OpenProcess(0x1000|0x100000,False,os.getpid())
 if not h:raise RuntimeError('controller_open_failed')
 try:
  created=W.FILETIME();other=[W.FILETIME() for _ in range(3)]
  if not K.GetProcessTimes(h,C.byref(created),*[C.byref(v) for v in other]):raise RuntimeError('controller_time_failed')
  image=C.create_unicode_buffer(32768);length=W.DWORD(len(image))
  if not K.QueryFullProcessImageNameW(h,0,image,C.byref(length)):raise RuntimeError('controller_image_failed')
  return {'pid':os.getpid(),'created':(created.dwHighDateTime<<32)|created.dwLowDateTime,'image':image.value}
 finally:K.CloseHandle(h)

def acl(path,add):
 args=['icacls.exe',str(path)]+(['/grant','*S-1-5-11:(R)'] if add else ['/remove:g','*S-1-5-11'])
 r=subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
 if r.returncode:raise RuntimeError('acl_fixture_failed')

class WindowsTests(unittest.TestCase):
 def setUp(self):
  self.session=Path(os.environ['ProgramData'])/'BNetOnlineG40'/uuid.uuid4().hex
  self.root=self.session/'quarantine';self.store=WindowsStore(self.root,HELPER);self.gate=q.QuarantineGate(self.store)
  self.children=[];self.handles=[]
  self.policy=self.session/'peers.json';self.lease=self.session/'lease.json'
  self.job_name='Global\\BNetOnlineG40_'+self.session.name
  self.job=K.CreateJobObjectW(None,self.job_name)
  self.assertTrue(self.job);self.handles.append(self.job)
  limits=Extended();limits.basic.flags=0x2000
  self.assertTrue(K.SetInformationJobObject(self.job,9,C.byref(limits),C.sizeof(limits)))
  self.policy_value={'expires_unix':time.time()+300,'job_name':self.job_name,'controller':identity()}
  self.write_policy();self.lease.write_text('{"phase":"active"}')
 def write_policy(self):self.policy.write_text(json.dumps(self.policy_value))
 def tearDown(self):
  for child in self.children:
   if child.poll() is None:child.kill()
   child.communicate(timeout=10)
  for h in self.handles:K.CloseHandle(h)
  if self.session.exists():shutil.rmtree(self.session)
 def capture(self):
  receipt=self.gate.inspect_http(RAW);self.assertTrue(receipt.private_stored)
  return receipt,self.store.read_for_local_review(receipt.capture_id)
 def talk(self,assigned=True,header_hook=None):
  # Only numeric loopback connection from the child, never DNS/content servers.
  code="import socket,sys;sys.stdin.buffer.read(1);s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),5);s.sendall("+repr(RAW)+");r=s.recv(4096);print(int(r.startswith(b'HTTP/1.1 403')),flush=True);sys.stdin.buffer.read(1);s.close()"
  with LoopbackServer(('127.0.0.1',0),self.gate,str(self.policy)) as server:
   server.timeout=8;worker=threading.Thread(target=server.handle_request)
   with patch.object(protocol,'connect',side_effect=AssertionError('upstream_dial_forbidden')) as upstream:
    context=patch.object(protocol,'header',side_effect=header_hook) if header_hook else patch.object(protocol,'header',wraps=protocol.header)
    with context:
     worker.start()
     child=subprocess.Popen([sys.executable,'-I','-c',code,str(server.server_address[1])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
     self.children.append(child)
     if assigned:self.assertTrue(K.AssignProcessToJobObject(self.job,W.HANDLE(int(child._handle))))
     child.stdin.write(b'x');child.stdin.flush()
     deadline=time.monotonic()+10
     while not server.receipts and time.monotonic()<deadline:time.sleep(.02)
     self.assertEqual(len(server.receipts),1)
     out,_=child.communicate(input=b'x',timeout=10);self.assertEqual(out.strip(),b'1')
     worker.join(10);self.assertFalse(worker.is_alive());upstream.assert_not_called()
   return server.receipts[0]
 def test_native_owned_job_captured_before_any_dial(self):
  receipt=self.talk();self.assertTrue(receipt['private_stored']);self.assertEqual(receipt['decision'],'blocked');self.assertEqual(receipt['upstream_attempts'],0)
  r=self.store.read_for_local_review(receipt['capture_id']);self.assertIn(MARKER,r['query']);self.assertNotIn('SYNTHETIC-SECRET',json.dumps(r));self.assertNotIn(MARKER,json.dumps(receipt))
 def test_outside_job_blocked_without_capture(self):
  r=self.talk(False);self.assertFalse(r['private_stored']);self.assertEqual(list(self.root.iterdir()),[])
 def test_expired_policy_blocked_without_capture(self):
  self.policy_value['expires_unix']=time.time()-1;self.write_policy()
  self.assertFalse(self.talk()['private_stored']);self.assertEqual(list(self.root.iterdir()),[])
 def test_controller_identity_mismatch_blocked(self):
  self.policy_value['controller']['created']+=1;self.write_policy()
  self.assertFalse(self.talk()['private_stored']);self.assertEqual(list(self.root.iterdir()),[])
 def test_closed_lease_blocked(self):
  self.lease.write_text('{"phase":"closed"}')
  self.assertFalse(self.talk()['private_stored']);self.assertEqual(list(self.root.iterdir()),[])
 def test_lease_revoked_after_admission_blocks_capture(self):
  original=protocol.header
  def revoke(sock):
   result=original(sock);self.lease.write_text('{"phase":"closed"}');return result
  self.assertFalse(self.talk(header_hook=revoke)['private_stored']);self.assertEqual(list(self.root.iterdir()),[])
 def test_storage_acl_drift_after_admission_blocks_capture(self):
  original=protocol.header
  def drift(sock):
   result=original(sock);acl(self.root,True);return result
  try:self.assertFalse(self.talk(header_hook=drift)['private_stored']);self.assertEqual(list(self.root.iterdir()),[])
  finally:acl(self.root,False)
 def test_private_write_and_read_roundtrip(self):
  receipt,r=self.capture();self.assertEqual(r['host'],'level3.blizzard.com');self.assertFalse(r['approval_granted']);self.assertEqual(r['review_status'],'pending')
 def test_directory_acl_drift_refused(self):
  acl(self.root,True)
  try:self.assertFalse(self.gate.inspect_http(RAW).private_stored)
  finally:acl(self.root,False)
 def test_file_acl_drift_refused(self):
  receipt,_=self.capture();file=self.root/(receipt.capture_id+'.json');acl(file,True)
  try:
   self.assertFalse(self.gate.inspect_http(RAW).private_stored)
   with self.assertRaises(q.Rejected):self.store.read_for_local_review(receipt.capture_id)
  finally:acl(file,False)
 def test_hardlinked_capture_refused(self):
  receipt,_=self.capture();link=self.session/'fixture-link'
  os.link(self.root/(receipt.capture_id+'.json'),link)
  try:
   self.assertFalse(self.gate.inspect_http(RAW).private_stored)
   with self.assertRaises(q.Rejected):self.store.read_for_local_review(receipt.capture_id)
  finally:link.unlink()
 def test_junction_root_refused(self):
  other=self.session/'other';other.mkdir();self.root.rmdir()
  r=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(self.root),str(other)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10);self.assertEqual(r.returncode,0)
  try:
   with self.assertRaises(q.Rejected):WindowsStore(self.root,HELPER)
   self.assertEqual(list(other.iterdir()),[])
  finally:os.rmdir(self.root)
 def test_quota_survives_reopening(self):
  for _ in range(q.MAX_RECORDS):self.assertTrue(self.gate.inspect_http(RAW).private_stored)
  fresh=WindowsStore(self.root,HELPER)
  self.assertFalse(q.QuarantineGate(fresh).inspect_http(RAW).private_stored);self.assertEqual(len(list(self.root.iterdir())),q.MAX_RECORDS)
 def test_concurrent_quota_and_no_overwrite(self):
  with ThreadPoolExecutor(max_workers=8) as pool:receipts=list(pool.map(self.gate.inspect_http,[RAW]*24))
  ids=[r.capture_id for r in receipts if r.private_stored]
  self.assertEqual(len(ids),q.MAX_RECORDS);self.assertEqual(len(set(ids)),q.MAX_RECORDS)
  self.assertTrue(all(r.decision=='blocked' for r in receipts))
 def test_read_path_traversal_refused(self):
  for ident in ('../x','x.json','',None):
   with self.assertRaises(q.Rejected):self.store.read_for_local_review(ident)
 def test_native_reverse_tuple_ipv4(self):
  with socket.socket() as server:
   server.bind(('127.0.0.1',0));server.listen()
   with socket.create_connection(server.getsockname()) as client:
    accepted,_=server.accept()
    with accepted:self.assertEqual(peer.owner(accepted),os.getpid())
 def test_native_reverse_tuple_ipv6(self):
  with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as server:
   server.bind(('::1',0));server.listen()
   with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as client:
    client.connect(server.getsockname());accepted,_=server.accept()
    with accepted:self.assertEqual(peer.owner(accepted),os.getpid())

if __name__=='__main__':unittest.main(verbosity=2)
