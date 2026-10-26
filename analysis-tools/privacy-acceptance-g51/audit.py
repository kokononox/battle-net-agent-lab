"""Offline privacy acceptance audit of existing components. No OS socket allowed.
Windows owner/Job admission is explicitly stubbed, NOT tested here. Legacy
forwarding functions run on in-memory socket-shaped objects; no real TLS.
"""
import ast,hashlib,importlib.util,json,socket,sys,tempfile,types
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[2];OUT=BASE/'reports/privacy-acceptance-g51'
def source(stage,relative):return (BASE/relative) if (BASE/relative).exists() else BASE.parent/stage/relative
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod);return mod
def sha(b):return hashlib.sha256(b).hexdigest()
class Permit:
 def revalidate(self):pass
 def close(self):pass
class FakeSocket:
 def __init__(self,data=b''):self.data=data;self.sent=bytearray()
 def recv(self,n):b=self.data[:n];self.data=self.data[n:];return b
 def sendall(self,data):self.sent.extend(data)
 def send(self,data):self.sent.extend(data);return len(data)
 def settimeout(self,*a):pass
 def close(self):pass
MARK=b'SYNTHETIC-NOT-A-REAL-USER-ID'
def http(method='GET',target='/fixed.bin',extras=b'',body=b''):
 return method.encode()+b' http://level3.blizzard.com'+target.encode()+b' HTTP/1.1\r\nHost: level3.blizzard.com\r\n'+extras+(b'Content-Length: '+str(len(body)).encode()+b'\r\n' if body else b'')+b'\r\n'+body
def main():
 OUT.mkdir(parents=True,exist_ok=True)
 brokerpath=source('g37','analysis-tools/download-broker-g37/broker.py');legacydir=source('g41','analysis-tools/quarantine-system-g41/domain_proxy.py').parent
 broker=load('g51_broker_under_test',brokerpath)
 native=types.ModuleType('peer_guard');native.admit=lambda *a:Permit()
 # Only bypass native admission for controlled in-memory handler tests.
 with patch.dict(sys.modules,{'peer_guard':native}):
  tls=load('tls_records',legacydir/'tls_records.py');proxy=load('domain_proxy',legacydir/'domain_proxy.py');quarantine=load('quarantine',legacydir/'quarantine.py');endpoint=load('g51_quarantine_handler',legacydir/'quarantine_handler.py')
 cases=[('post_body',http('POST',body=MARK)),('get_body',http(body=MARK)),('query_id',http(target='/fixed.bin?device='+MARK.decode())),('path_id',http(target='/'+MARK.decode()+'/fixed.bin')),('custom_header',http(extras=b'X-Device-Id: '+MARK+b'\r\n')),('cookie',http(extras=b'Cookie: device='+MARK+b'\r\n')),('authorization',http(extras=b'Authorization: Bearer '+MARK+b'\r\n'))]
 report={'schema':'privacy_acceptance_audit_g51_v1','mode':'offline_component_tests_only','os_socket_creation_forbidden':True,'external_network_requests':0,'native_windows_admission_stubbed':True,'windows_firewall_or_job_tested_in_g51':False,'real_tls_session_tested':False,'real_installer_or_payload_executed':False,'production_policy_changed':False,'cases':[]}
 with patch.object(socket,'socket',side_effect=AssertionError('os_network_forbidden')):
  # Exercise the actual existing legacy Handler, not a rewritten forwarding model.
  with tempfile.TemporaryDirectory() as temp:
   config={'peer_policy':'stub-only','log':str(Path(temp)/'unused.log')};server=types.SimpleNamespace(config=config)
   for label,raw in cases:
    client=FakeSocket(raw);up=FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    with patch.object(proxy,'admit',return_value=Permit()),patch.object(proxy,'connect',return_value=up) as dial,patch.object(proxy,'log'),patch.object(proxy,'metadata'):
     proxy.Handler(client,('127.0.0.1',12345),server)
    leaked=MARK in up.sent
    assert leaked and dial.call_count==1
    report['cases'].append({'component':'legacy_domain_proxy','case':label,'synthetic_marker_reached_mock_upstream':leaked,'upstream_is_in_memory_only':True,'privacy_requirement_met':False})
   # Relay transparency: synthetic opaque TLS-shaped bytes, NOT real encryption.
   opaque=b'\x17\x03\x03'+len(MARK).to_bytes(2,'big')+MARK;a=FakeSocket(opaque);b=FakeSocket();t=proxy.new_transfer()
   with patch.object(proxy.select,'select',side_effect=[([a],[],[]),([a],[],[])]):proxy.relay(a,b,Permit(),config,'level3.blizzard.com',t)
   assert bytes(b.sent)==opaque
   report['opaque_relay']={'unchanged_synthetic_record_forwarded':True,'real_encryption_or_handshake_tested':False,'meaning':'relay does not inspect application payload semantics; allowed SNI/host cannot establish privacy safety'}
   # Actual quarantine endpoint and gate, actual POSIX private store; native admission stubbed.
   qroot=Path(temp)/'private';qroot.mkdir(mode=0o700)
   with quarantine.PrivateStore(str(qroot)) as store:
    gate=quarantine.QuarantineGate(store);qserver=types.SimpleNamespace(peer_policy='stub-only',quarantine_gate=gate,receipts=[])
    for label,raw in cases:
     client=FakeSocket(raw)
     with patch.object(proxy,'admit',return_value=Permit()),patch.object(proxy,'connect',side_effect=AssertionError('quarantine_must_not_forward')) as dial:
      endpoint.QuarantineOnlyHandler(client,('127.0.0.1',12345),qserver)
     receipt=qserver.receipts[-1];assert receipt['decision']=='blocked' and receipt['upstream_attempts']==0 and dial.call_count==0 and bytes(client.sent).startswith(b'HTTP/1.1 403')
     assert MARK.decode() not in json.dumps(receipt)
     report['cases'].append({'component':'quarantine_only_endpoint','case':label,'decision':'blocked','upstream_calls':0,'public_receipt_contains_marker':False,'privacy_requirement_met_for_this_request':True,'download_allowed':False})
   payload=b'SYNTHETIC DOWNLOAD ONLY\n'
   policy={'schema':'offline_download_catalog_v2','resources':[{'resource_id':'fixture','host':'level3.blizzard.com','path':'/audit-fixture/file.bin','expected_bytes':len(payload),'sha256':sha(payload),'review':{'status':'approved','evidence_id':'synthetic_fixture_only'}}],'session':{'resource_ids':['fixture'],'max_requests':1,'max_total_bytes':len(payload)}}
   def enc(x):return json.dumps(x,separators=(',',':')).encode()
   cat=broker.Catalog.load(enc(policy),sha(enc(policy)));plan=cat.plan(enc({'resource_id':'fixture'}))
   fixed_wire=plan.request;assert MARK not in fixed_wire and fixed_wire.startswith(b'GET /audit-fixture/file.bin ') and fixed_wire.endswith(b'\r\n\r\n')
   fields=['url','path','query','headers','cookie','body','method','host','port','device_id','machine_guid','authorization','proxy','redirect','range']
   injected=[enc({'resource_id':'fixture',key:MARK.decode()}) for key in fields]+[raw for _,raw in cases]+[b'CONNECT level3.blizzard.com:443 HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n']
   def attempt(raw):
    transport=broker.InMemoryTransport({(plan.host,plan.request):broker.Reply(200,payload)});session=broker.OfflineBroker(cat,transport)
    try:session.download(raw)
    except broker.Denied:
     assert not transport.calls and session.snapshot().phase=='failed';return True
    raise AssertionError('injected_request_accepted')
   for raw in injected:assert attempt(raw)
   # Each of 1000 variants REALLY calls download; a corrected independent loop.
   checked=0
   for i in range(1000):assert attempt(enc({'resource_id':'fixture','x_'+str(i):MARK.decode()}));checked+=1
   assert checked==1000
   transport=broker.InMemoryTransport({(plan.host,plan.request):broker.Reply(200,payload)});session=broker.OfflineBroker(cat,transport);assert session.download(enc({'resource_id':'fixture'}))==payload and len(transport.calls)==1 and transport.calls[0].request==fixed_wire
   shipped=brokerpath.with_name('catalog.deny-all.json').read_bytes();empty=broker.Catalog.load(shipped,sha(shipped));denyt=broker.InMemoryTransport({})
   try:broker.OfflineBroker(empty,denyt).download(enc({'resource_id':'fixture'}))
   except broker.Denied:pass
   else:raise AssertionError('deny_all_failed')
   assert not denyt.calls
   # A trusted-but-bad catalog can bake an identifier into a syntactically valid static path.
   bad=json.loads(json.dumps(policy));bad['resources'][0]['path']='/audit-fixture/'+MARK.decode()+'/file.bin';badcat=broker.Catalog.load(enc(bad),sha(enc(bad)));badwire=badcat.plan(enc({'resource_id':'fixture'})).request;assert MARK in badwire
   report['fixed_broker']={'direct_injection_cases_executed_and_blocked':len(injected),'additional_unique_injections_executed_and_blocked':checked,'blocked_before_fixture_fetch':True,'approved_synthetic_download_succeeded':True,'client_wire_reconstructed_not_forwarded':True,'shipped_deny_all_fetch_calls':len(denyt.calls),'online_transport_available':False,'trusted_bad_catalog_can_embed_identifier':True,'content_hash_and_approved_label_are_not_privacy_review':True,'synthetic_success_is_not_real_install_success':True}
  # Reproduce the historical regression test's ACTUAL download-call count.
  testpath=brokerpath.with_name('test_broker.py')
  with patch.dict(sys.modules,{'broker':broker}):oldtest=load('g51_old_test_under_test',testpath)
  calls=[];original=broker.OfflineBroker.download
  def counted(self,raw):calls.append(1);return original(self,raw)
  case=oldtest.Tests('test_many_injected_requests_never_fetch')
  with patch.object(broker.OfflineBroker,'download',counted):case.setUp();case.test_many_injected_requests_never_fetch();case.doCleanups()
  assert len(calls)==1
  report['historical_test_correction']={'source':'G37 test_many_injected_requests_never_fetch','generated_variants':1000,'download_calls_actually_executed_in_original_test':len(calls),'cause':'assertRaises/download block lies outside for-loop','g51_independently_executed_unique_variants':checked,'prior_source_or_receipt_modified':False}
 report['catalog_sha256']=sha(brokerpath.with_name('catalog.deny-all.json').read_bytes());assert report['catalog_sha256']=='ee2b6f3e115f58ff21414168185024ffa9f574863333ab869cbb861c52c0c8c5'
 report['source_hashes']={str(p.relative_to(p.parents[2])):sha(p.read_bytes()) for p in [brokerpath,brokerpath.with_name('test_broker.py'),legacydir/'domain_proxy.py',legacydir/'quarantine_handler.py',legacydir/'quarantine.py',legacydir/'tls_records.py']}
 report['acceptance']={'user_goal_met':False,'release_as_privacy_safe_installer_route':False,'reason':'Legacy route forwards arbitrary allowed-host HTTP data and opaque TLS bytes; safe broker is offline only; quarantine blocks all downloads. No combined Windows manual-install route validated.','next_required_work':'Keep legacy forwarding out of privacy mode; integrate fixed-request online broker with Windows deny-all gate, then test manual-install compatibility and negative controls. No broad host exception or blind CONNECT fallback.'}
 (OUT/'acceptance-evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ['cases','source_hashes']}))
if __name__=='__main__':main()
