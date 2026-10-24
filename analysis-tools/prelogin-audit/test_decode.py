import base64
import hashlib
import json
import unittest
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from decode_startup import PACKAGE, analyze, extract_startup, parts, varint, wire


def vi(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def ld(n, value):
    return vi(n * 8 + 2) + vi(len(value)) + value


def fixture():
    d = descriptor_pb2.FileDescriptorProto(name='Startup.proto', package=PACKAGE)
    h = d.message_type.add(name='Hardware')
    for num, name, typ in [(2, 'cpu_num_cores', 5), (4, 'memory', 3), (10, 'cpu_brand', 9)]:
        h.field.add(name=name, number=num, type=typ, label=1)
    m = d.message_type.add(name='StartAgent')
    m.field.add(name='hardware', number=1011, type=11, type_name='.' + PACKAGE + '.Hardware', label=1)
    pool = descriptor_pool.DescriptorPool()
    pool.Add(d)
    cls = message_factory.GetMessageClass(pool.FindMessageTypeByName(PACKAGE + '.StartAgent'))
    msg = cls()
    msg.hardware.cpu_brand = 'PRIVATE FIXTURE CPU'
    msg.hardware.memory = 100
    msg.hardware.cpu_num_cores = 2
    agent = b'fixture prefix\0' + d.SerializeToString() + b'\0'
    payload = ld(2, PACKAGE.encode()) + ld(3, b'StartAgent') + ld(4, msg.SerializeToString())
    q = {'host': 'fixture.invalid', 'method': 'POST', 'target': '/data',
         'process_sha256': hashlib.sha256(agent).hexdigest(),
         'body_sample_base64': base64.b64encode(payload).decode(),
         'body_complete': True, 'body_sample_truncated': False,
         'headers': [['content-type', 'application/octet-stream']]}
    report = {'schema': 'bnet-process-birth-http-tls-1', 'requests': [q],
              'reference': {'cpu_model': 'PRIVATE FIXTURE CPU', 'total_physical_memory_bytes': 100, 'logical_processors': 2}}
    return agent, report


class DecoderTests(unittest.TestCase):
    def test_schema_backed_fields_and_no_values(self):
        agent, report = fixture()
        result = analyze(agent, report)
        decoded = result['decoded_startup_messages'][0]
        self.assertTrue(decoded['cpu_matches_vm_reference_after_trim'])
        self.assertFalse(decoded['unknown_payload_fields_present'])
        self.assertIn('hardware.cpu_brand', [x['path'] for x in decoded['fields_present']])
        self.assertNotIn('PRIVATE FIXTURE CPU', json.dumps(result))

    def test_hash_mismatch_refused(self):
        agent, report = fixture()
        report['requests'][0]['process_sha256'] = '0' * 64
        result = analyze(agent, report)
        self.assertFalse(result['decoded_startup_messages'])
        self.assertEqual(result['unresolved'][0]['reason'], 'agent_hash_mismatch')

    def test_truncated_body_not_decoded(self):
        agent, report = fixture()
        report['requests'][0]['body_sample_truncated'] = True
        self.assertFalse(analyze(agent, report)['decoded_startup_messages'])

    def test_unknown_wire_field_flagged(self):
        agent, report = fixture()
        q = report['requests'][0]
        fields = wire(base64.b64decode(q['body_sample_base64']))
        payload = next(v for n, w, v in fields if n == 4) + vi(2000 * 8) + b'\x01'
        q['body_sample_base64'] = base64.b64encode(ld(2, PACKAGE.encode()) + ld(3, b'StartAgent') + ld(4, payload)).decode()
        self.assertTrue(analyze(agent, report)['decoded_startup_messages'][0]['unknown_payload_fields_present'])

    def test_reject_missing_and_duplicate_descriptors(self):
        agent, _ = fixture()
        for bad in [b'not a descriptor', agent + agent]:
            with self.assertRaises(ValueError):
                extract_startup(bad)

    def test_wire_bounds(self):
        for bad in [b'\x00', b'\x0a\x02A', b'\x09A', b'\x0e', b'\x80' * 11]:
            with self.assertRaises(ValueError):
                wire(bad)
        with self.assertRaises(ValueError):
            varint(b'\xff' * 9 + b'\x02', 0)

    def test_mime_bounds(self):
        with self.assertRaises(ValueError):
            parts(b'incomplete', 'multipart/mixed; boundary=abc')
        body = b'--abc\r\nContent-Type: application/octet-stream\r\n\r\nhello\r\n--abc--\r\n'
        self.assertEqual(parts(body, 'multipart/mixed; boundary=abc'), [b'hello'])

    def test_reference_mismatch_not_hidden(self):
        agent, report = fixture()
        report['reference']['total_physical_memory_bytes'] = 99
        report['reference']['logical_processors'] = 1
        decoded = analyze(agent, report)['decoded_startup_messages'][0]
        self.assertFalse(decoded['memory_equals_reference_total_physical_bytes'])
        self.assertFalse(decoded['core_count_equals_reference_logical_processors'])


if __name__ == '__main__':
    unittest.main()
