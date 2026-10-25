"""Offline independent checks against the acquired PE, never executes it."""
import hashlib,json,unittest
from pathlib import Path
from google.protobuf.descriptor_pb2 import FileDescriptorProto
BASE=Path(__file__).resolve().parents[2];R=BASE/'reports/bootstrap-static-g42';B=(BASE/'private/Battle.net-Setup.exe').read_bytes();E=json.loads((R/'static-evidence.json').read_text());A=json.loads((R/'acquisition.json').read_text())
class EvidenceChecks(unittest.TestCase):
 def test_acquisition_pin(self):
  self.assertEqual(len(B),A['bytes']);self.assertEqual(hashlib.sha256(B).hexdigest(),A['sha256']);self.assertEqual(A['sha256'],E['input_sha256']);self.assertEqual(A['sha256'],A['historical_pin_sha256'])
 def test_resources_are_real_bytes(self):
  self.assertEqual(len(E['resources']),51)
  for r in E['resources']:
   data=B[r['offset']:r['offset']+r['bytes']];self.assertEqual(hashlib.sha256(data).hexdigest(),r['sha256'])
   if 'json' in r:self.assertEqual(json.loads(data.decode('utf-8-sig')),r['json'])
  self.assertEqual(E['settings_resources'][0]['json']['ProductCode'],'bna')
 def test_endpoint_offsets(self):
  for r in E['endpoint_strings']+E['download_discovery_strings']:
   raw=r['text'].encode('ascii' if r['encoding']=='ascii' else 'utf-16le');self.assertEqual(B[r['offset']:r['offset']+len(raw)],raw);self.assertIs(r['runtime_approved'],False)
  self.assertTrue(any(r['text']=='https://telemetry-in.battle.net/data' for r in E['endpoint_strings']))
 def test_descriptors_decode_from_recorded_bytes(self):
  self.assertEqual(len(E['protobuf_descriptors']),7);names={}
  for r in E['protobuf_descriptors']:
   blob=B[r['offset']:r['offset']+r['bytes']];self.assertEqual(hashlib.sha256(blob).hexdigest(),r['sha256']);d=FileDescriptorProto();d.ParseFromString(blob);self.assertEqual(d.name,r['name'])
   for m in d.message_type:names[m.name]={f.name:f.number for f in m.field}
  self.assertEqual(names['ClientRunOnStartup']['client_id'],3);self.assertEqual(names['SessionGenerate']['uuid'],1);self.assertEqual(names['SessionUpdate']['uuid'],2)
 def test_windows_signature_report_matches_same_file(self):
  w=json.loads((R/'windows-signature.json').read_text())
  self.assertEqual(w['run_id'],'40242794593');self.assertEqual(w['source_commit'],'a76e635c31e7666fae17ab0c271774c01bf2295f')
  self.assertEqual(w['sha256'],A['sha256']);self.assertEqual(w['signature_status'],'Valid');self.assertIs(w['accepted'],True)
  self.assertIn('Blizzard Entertainment',w['signer_subject']);self.assertIs(w['installer_executed'],False)
 def test_fail_closed_claims(self):
  for r in (A,E):self.assertIs(r['installer_executed'],False);self.assertEqual(r['catalog_entries_approved'],0)
  self.assertIs(E['resource_urls_requested'],False);self.assertIs(E['complete_payload_manifest_recovered'],False)
  self.assertIs(E['embedded_certificates_are_not_trust_verification'],True)
if __name__=='__main__':unittest.main()
