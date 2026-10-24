"""Offline schema decoding and identifier-shape audit; does not execute the supplied image.
Requires decode_startup.py and google.protobuf. Never exports raw field or identifier values.
"""
import argparse
import base64
import collections
import hashlib
import json
import re
from pathlib import Path
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from decode_startup import descriptor_prefixes, wire, parts, one_bytes, field_presence

GUID = re.compile(rb'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}')


def extract_all(agent):
    found = {}
    for match in re.finditer(rb'\x0a([\x01-\x7f])([A-Za-z0-9_./-]+\.proto)', agent):
        if match[1][0] != len(match[2]):
            continue
        best = None
        for stop in descriptor_prefixes(agent, match.start()):
            d = descriptor_pb2.FileDescriptorProto()
            try:
                d.ParseFromString(agent[match.start():stop])
            except Exception:
                continue
            if d.name == match[2].decode('ascii') and d.package.startswith('Blizzard.Telemetry.') and d.message_type:
                best = (d, match.start(), stop)
        if best:
            d, start, stop = best
            if d.name in found:
                raise ValueError('Ambiguous duplicate descriptor filename')
            found[d.name] = best
    if not found:
        raise ValueError('No telemetry descriptors recovered')
    pool = descriptor_pool.DescriptorPool()
    pending, resolved = list(found), []
    while pending:
        remaining = []
        for name in pending:
            try:
                pool.Add(found[name][0])
                resolved.append(name)
            except Exception:
                remaining.append(name)
        if len(remaining) == len(pending):
            break
        pending = remaining
    manifest = []
    for name in resolved:
        d, start, stop = found[name]
        manifest.append({'file': name, 'package': d.package, 'offset': start,
                         'bytes': stop - start, 'sha256': hashlib.sha256(agent[start:stop]).hexdigest()})
    return pool, manifest, pending


def identifier_shapes(context, path='/1', depth=0):
    if depth > 8 or len(context) > 262144:
        return []
    try:
        fields = wire(context)
    except ValueError:
        return []
    out = []
    for number, kind, value in fields:
        if kind != 2:
            continue
        current = path + '/' + str(number)
        if GUID.fullmatch(value):
            # Raw bytes used for in-memory equality only, never returned in public analysis.
            out.append((current, value))
        elif value:
            out.extend(identifier_shapes(value, current, depth + 1))
    return out


def classify_presence(message, prefix=''):
    out = []
    for field, value in message.ListFields():
        path = prefix + field.name
        if field.message_type:
            for index, child in enumerate(value if field.is_repeated else [value]):
                out += classify_presence(child, path + (f'[{index}].' if field.is_repeated else '.'))
        else:
            item = {'path': path, 'field_number': field.number,
                    'type': descriptor_pb2.FieldDescriptorProto.Type.Name(field.type), 'present': True}
            if field.type in (9, 12):
                values = list(value) if field.is_repeated else [value]
                item['nonempty_value_present'] = any(bool(v) for v in values)
            out.append(item)
    return out


def analyze(agent, report):
    if report.get('schema') != 'bnet-process-birth-http-tls-1':
        raise ValueError('Unsupported report schema')
    pool, manifest, pending = extract_all(agent)
    digest = hashlib.sha256(agent).hexdigest()
    events, contexts, errors = [], collections.defaultdict(list), []
    for index, request in enumerate(report['requests']):
        body = base64.b64decode(request['body_sample_base64'], validate=True)
        if not body:
            continue
        if not request['body_complete'] or request['body_sample_truncated']:
            errors.append({'request_index': index, 'reason': 'incomplete_body'})
            continue
        for part_index, payload in enumerate(parts(body, dict(request['headers']).get('content-type', ''))):
            try:
                envelope = wire(payload)
                namespace = one_bytes(envelope, 2).decode('ascii')
                event_name = one_bytes(envelope, 3).decode('ascii')
                if not re.fullmatch(r'Blizzard\.Telemetry\.[A-Za-z0-9_.]{1,160}', namespace) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,100}', event_name):
                    raise ValueError('Unsupported event label')
                event = {'request_index': index, 'part_index': part_index, 'host': request['host'],
                         'event_type': namespace + '.' + event_name,
                         'payload_decoding': 'schema_unavailable', 'fields_present': []}
                events.append(event)
                # Identifier labels deliberately not inferred: these are wire-number locations.
                context_candidates = identifier_shapes(one_bytes(envelope, 1))
                for path, value in context_candidates:
                    contexts[path].append((value, request.get('process_sha256'), event['event_type']))
                context_values = {value for _, value in context_candidates}
                event['context_uuid_reused_at_payload_wire_paths'] = sorted({path for path, value in identifier_shapes(one_bytes(envelope, 4), path='/4') if value in context_values})
                try:
                    descriptor = pool.FindMessageTypeByName(event['event_type'])
                except KeyError:
                    continue
                if request.get('process_sha256') != digest:
                    event['payload_decoding'] = 'image_hash_mismatch'
                    continue
                cls = message_factory.GetMessageClass(descriptor)
                msg = cls.FromString(one_bytes(envelope, 4))
                copy = cls()
                copy.CopyFrom(msg)
                copy.DiscardUnknownFields()
                unknown = copy.ByteSize() != msg.ByteSize()
                event['payload_decoding'] = 'schema_verified_with_unknown_fields' if unknown else 'schema_verified'
                event['unknown_payload_fields_present'] = unknown
                event['fields_present'] = classify_presence(msg)
            except (ValueError, UnicodeError) as error:
                errors.append({'request_index': index, 'part_index': part_index, 'reason': type(error).__name__})
    slots = []
    for path, observations in sorted(contexts.items()):
        slots.append({'wire_path': path, 'shape': 'uuid_text', 'occurrences': len(observations),
                      'distinct_values_within_submitted_report': len({v for v, _, _ in observations}),
                      'distinct_process_images': len({p for _, p, _ in observations}),
                      'distinct_event_types': len({t for _, _, t in observations}),
                      'nil_uuid_occurrences': sum(all(c in b'0-' for c in v) for v, _, _ in observations),
                      'semantic_label': 'unverified', 'persistence_across_restarts': 'untested',
                      'hardware_derivation': 'unverified'})
    return {'schema': 'prelogin-all-events-audit-1', 'run_id': report.get('run_id'),
            'source_commit': report.get('source_commit'), 'agent_sha256': digest,
            'descriptor_manifest': manifest, 'unresolved_descriptor_dependencies': pending,
            'events': events, 'payload_status_counts': dict(collections.Counter(e['payload_decoding'] for e in events)),
            'context_identifier_shapes': slots, 'parse_errors': errors,
            'context_schema_decoded': False,
            'limitations': ['Only exact-image hash matches permit payload schema decoding.',
                            'Event and context framing is observed wire structure; context field names are NOT established.',
                            'UUID-shaped values may be session/correlation/install/host identifiers; their form and in-run equality do not prove which.',
                            'No inference of persistence, global uniqueness, hardware derivation, account linkage or game-file marking.',
                            'A schema-unavailable payload has NOT been checked for hidden system fields.',
                            'Previously captured pre-TLS inputs are not a new runtime/network-delivery experiment.',
                            'Other TLS implementations, protocols and processes remain outside established coverage.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('agent', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.agent.stat().st_size > 64 * 1024 * 1024 or args.report.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Input exceeds supported size')
    raw = args.report.read_bytes()
    result = analyze(args.agent.read_bytes(), json.loads(raw))
    result['report_sha256'] = hashlib.sha256(raw).hexdigest()
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('Offline event audit complete; no raw identifiers or field values exported.')


if __name__ == '__main__':
    main()
