"""Decode existing startup evidence with a Startup.proto descriptor from the EXACT Agent image.
Offline only. Requires google.protobuf. Output field presence, never machine values or raw payloads.
"""
import argparse
import base64
import email.parser
import email.policy
import hashlib
import json
import re
from pathlib import Path
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

PACKAGE = 'Blizzard.Telemetry.Distribution.Agent'


def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError('Truncated varint')
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            raise ValueError('Varint exceeds uint64')
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise ValueError('Varint overflow')


def wire(data):
    pos, result = 0, []
    while pos < len(data):
        tag, pos = varint(data, pos)
        number, kind = tag >> 3, tag & 7
        if not 1 <= number <= 536870911:
            raise ValueError('Invalid field number')
        if kind == 0:
            value, pos = varint(data, pos)
        elif kind in (1, 5):
            size = 8 if kind == 1 else 4
            value = data[pos:pos + size]
            pos += size
            if len(value) != size:
                raise ValueError('Truncated fixed field')
        elif kind == 2:
            size, pos = varint(data, pos)
            value = data[pos:pos + size]
            pos += size
            if len(value) != size:
                raise ValueError('Truncated length-delimited field')
        else:
            raise ValueError('Unsupported wire type')
        result.append((number, kind, value))
    return result


def descriptor_prefixes(data, start):
    pos, limit = start, min(len(data), start + 131072)
    while pos < limit:
        try:
            tag, pos = varint(data, pos)
            number, kind = tag >> 3, tag & 7
            if not 1 <= number <= 12:
                return
            if kind == 0:
                _, pos = varint(data, pos)
            elif kind in (1, 5):
                pos += 8 if kind == 1 else 4
            elif kind == 2:
                size, pos = varint(data, pos)
                pos += size
            else:
                return
            if pos > limit:
                return
            yield pos
        except ValueError:
            return


def extract_startup(data):
    candidates = []
    for match in re.finditer(rb'\x0a\x0dStartup\.proto', data):
        best = None
        for stop in descriptor_prefixes(data, match.start()):
            d = descriptor_pb2.FileDescriptorProto()
            try:
                d.ParseFromString(data[match.start():stop])
            except Exception:
                continue
            if d.name == 'Startup.proto' and d.package == PACKAGE and any(t.name == 'StartAgent' for t in d.message_type):
                best = (d, match.start(), stop)
        if best:
            candidates.append(best)
    if len(candidates) != 1:
        raise ValueError('Expected exactly one validated Startup.proto descriptor')
    d, start, stop = candidates[0]
    if d.dependency:
        raise ValueError('Descriptor dependencies require explicit resolution')
    pool = descriptor_pool.DescriptorPool()
    pool.Add(d)
    cls = message_factory.GetMessageClass(pool.FindMessageTypeByName(PACKAGE + '.StartAgent'))
    return d, cls, start, stop


def parts(body, content_type):
    if not content_type.lower().startswith('multipart/'):
        return [body]
    message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        ('Content-Type: ' + content_type + '\r\nMIME-Version: 1.0\r\n\r\n').encode('ascii') + body)
    if not message.is_multipart() or message.defects:
        raise ValueError('Invalid or incomplete multipart body')
    result = []
    for part in message.iter_parts():
        if part.is_multipart() or part.defects:
            raise ValueError('Nested or malformed MIME part')
        payload = part.get_payload(decode=True)
        if payload is None:
            raise ValueError('Missing MIME payload')
        result.append(payload)
    return result


def one_bytes(fields, number):
    values = [v for n, w, v in fields if n == number and w == 2]
    if len(values) != 1:
        raise ValueError('Expected one envelope field')
    return values[0]


def field_presence(message, prefix=''):
    result = []
    for field, value in message.ListFields():
        path = prefix + field.name
        if field.message_type:
            for i, child in enumerate(value if field.is_repeated else [value]):
                result += field_presence(child, path + (f'[{i}].' if field.is_repeated else '.'))
        else:
            result.append({'path': path, 'field_number': field.number,
                           'type': descriptor_pb2.FieldDescriptorProto.Type.Name(field.type), 'present': True})
    return result


def analyze(agent, report):
    if report.get('schema') != 'bnet-process-birth-http-tls-1':
        raise ValueError('Unsupported report schema')
    d, cls, start, stop = extract_startup(agent)
    digest = hashlib.sha256(agent).hexdigest()
    events, decoded, unresolved = [], [], []
    for index, request in enumerate(report['requests']):
        body = base64.b64decode(request['body_sample_base64'], validate=True)
        if not body:
            continue
        if not request['body_complete'] or request['body_sample_truncated']:
            unresolved.append({'request_index': index, 'reason': 'incomplete_body'})
            continue
        content_type = dict(request['headers']).get('content-type', '')
        for part_index, payload in enumerate(parts(body, content_type)):
            try:
                fields = wire(payload)
                namespace = one_bytes(fields, 2).decode('ascii')
                event = one_bytes(fields, 3).decode('ascii')
                if not re.fullmatch(r'Blizzard\.Telemetry\.[A-Za-z0-9_.]{1,160}', namespace) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,100}', event):
                    raise ValueError('Unsupported envelope labels')
                events.append({'request_index': index, 'part_index': part_index, 'event_type': namespace + '.' + event, 'payload_decoding': 'not_attempted'})
                if namespace != PACKAGE or event != 'StartAgent':
                    continue
                if request.get('process_sha256') != digest:
                    unresolved.append({'request_index': index, 'part_index': part_index, 'reason': 'agent_hash_mismatch'})
                    continue
                inner = one_bytes(fields, 4)
                message = cls.FromString(inner)
                known = field_presence(message)
                without_unknown = cls()
                without_unknown.CopyFrom(message)
                without_unknown.DiscardUnknownFields()
                has_unknown = without_unknown.ByteSize() != message.ByteSize()
                events[-1]['payload_decoding'] = 'schema_verified_with_unknown_fields' if has_unknown else 'schema_verified'
                # Independently locate the CPU using numbered wire paths; do not infer names from strings.
                hardware = one_bytes(wire(inner), 1011)
                cpu_bytes = one_bytes(wire(hardware), 10)
                if cpu_bytes.decode('utf-8') != message.hardware.cpu_brand:
                    raise ValueError('Wire and dynamic decoder disagree')
                ref = report.get('reference', {})
                decoded.append({'request_index': index, 'part_index': part_index, 'host': request['host'],
                                'method': request['method'], 'target_path': request['target'].split('?')[0],
                                'event_type': namespace + '.' + event, 'agent_hash_matches': True, 'unknown_payload_fields_present': has_unknown,
                                'cpu_matches_vm_reference_after_trim': bool(ref.get('cpu_model')) and message.hardware.cpu_brand.strip() == ref['cpu_model'],
                                'memory_equals_reference_total_physical_bytes': message.hardware.memory == ref.get('total_physical_memory_bytes'),
                                'core_count_equals_reference_logical_processors': message.hardware.cpu_num_cores == ref.get('logical_processors'),
                                'fields_present': known})
            except (ValueError, UnicodeError) as error:
                unresolved.append({'request_index': index, 'part_index': part_index, 'reason': type(error).__name__})
    return {'schema': 'prelogin-startup-schema-audit-1', 'run_id': report.get('run_id'),
            'source_commit': report.get('source_commit'), 'agent_sha256': digest,
            'descriptor': {'file': d.name, 'package': d.package, 'offset': start, 'bytes': stop - start,
                           'sha256': hashlib.sha256(agent[start:stop]).hexdigest()},
            'event_labels_observed': events, 'decoded_startup_messages': decoded, 'unresolved': unresolved,
            'limits': ['Envelope field numbers are an observed framing convention; only StartAgent payload fields have schema-backed names in this decoder.',
                       'Presence is in a previously captured pre-TLS outgoing body; server acceptance is not proven.',
                       'Memory and core values differ from OS reference fields; do not equate the units or semantics without further evidence.',
                       'Other event payloads, context identifiers, alternate encrypted channels and other versions remain unverified.',
                       'An available schema field is not a transmitted field; output lists only fields present in the captured message.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('agent', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.agent.stat().st_size > 64 * 1024 * 1024 or args.report.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Input exceeds supported size')
    report_bytes = args.report.read_bytes()
    result = analyze(args.agent.read_bytes(), json.loads(report_bytes))
    result['report_sha256'] = hashlib.sha256(report_bytes).hexdigest()
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Offline schema audit complete; no executable run and no raw field values exported.')


if __name__ == '__main__':
    main()
