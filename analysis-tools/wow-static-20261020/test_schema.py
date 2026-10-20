import unittest,tempfile,subprocess,sys,json
from pathlib import Path
from google.protobuf.descriptor_pb2 import FileDescriptorProto
SCRIPT=Path(__file__).with_name('extract_telemetry_schema.py')
class Test(unittest.TestCase):
 def fixture(self,package='Blizzard.Telemetry.Wow.Client'):
  f=FileDescriptorProto(name='Fixture.proto',package=package)
  msg=f.message_type.add(name='TestHardware');field=msg.field.add(name='motherboardBiosVersion',number=196,label=1,type=9)
  return f.SerializeToString()
 def runscan(self,data):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'input').write_bytes(data);subprocess.run([sys.executable,str(SCRIPT),str(p/'input'),str(p/'out')],check=True,capture_output=True);return json.loads((p/'out').read_text())
 def test_structural_field_not_only_string(self):
  r=self.runscan(b'PREFIX\0'+self.fixture()+b'\0TRAILER');self.assertEqual(r['message_count'],1);f=r['hardware_related_messages'][0]['hardware_related_fields'][0];self.assertEqual((f['name'],f['number'],f['type']),('motherboardBiosVersion',196,'TYPE_STRING'))
 def test_unrelated_package_excluded(self):self.assertEqual(self.runscan(self.fixture('unrelated.package'))['message_count'],0)
 def test_loose_string_not_a_descriptor(self):self.assertEqual(self.runscan(b'cpu_brand motherboardBiosVersion Fixture.proto')['message_count'],0)
 def test_duplicate_descriptor_deduplicated(self):self.assertEqual(self.runscan(self.fixture()+b'\0'+self.fixture()+b'\0')['message_count'],1)
 def test_truncated_descriptor_does_not_invent_message(self):self.assertEqual(self.runscan(self.fixture()[:10])['message_count'],0)
if __name__=='__main__':unittest.main()
