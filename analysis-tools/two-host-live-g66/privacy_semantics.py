"""In-memory, bounded semantic observations. Never a privacy clearance.

No raw query, response, UA, identifier, digest of an identifier, PID or context
is serialized. Response matches are same-context evidence, not causality.
"""
import re
from collections import Counter

FIXED_WORDS = {'agent', 'blizzard', 'battle.net', 'battlenet', 'windows',
               'win32', 'win64', 'x86', 'x64', 'amd64'}
TOKEN = re.compile(r'[A-Za-z]+(?:\.[A-Za-z]+)+|[A-Za-z]+\d*|\d+(?:\.\d+)+|\d+|[^A-Za-z0-9]')
SEQ = re.compile(r'(?im)^\s*#?\s*seqn\s*=\s*([0-9]{1,20})\s*$')
MAX_BODY = 1024 * 1024


def ua_structure(value, public_tokens=()):
    """A shape, not a relaxed allow rule. Unknown pieces remain unknown."""
    public = set(public_tokens)
    out = []
    versions = []
    unknown = 0
    truncated = len(value) > 2048
    if not truncated:
        for token in TOKEN.findall(value):
            low = token.lower()
            if low in FIXED_WORDS:
                out.append({'kind': 'fixed_word', 'word': low})
            elif re.fullmatch(r'\d+(?:\.\d+)+', token):
                out.append({'kind': 'version_shape', 'public_exact': token in public})
                versions.append(token)
            elif token.isspace():
                out.append({'kind': 'whitespace'})
            elif len(token) == 1 and token in '/().;_:-':
                out.append({'kind': 'separator', 'symbol': token})
            else:
                unknown += 1
                out.append({'kind': 'unresolved_decimal' if token.isdecimal()
                            else 'unresolved_text', 'length': len(token)})
            if len(out) >= 128:
                truncated = True
                break
    # Exact fixed vocabulary grammar is diagnostic ONLY; a number looking like a
    # version might still encode data. Do not convert it into an allow decision.
    exact = bool(re.fullmatch(
        r'(?:Blizzard )?Agent(?:/| )[0-9]+(?:\.[0-9]+){1,5}', value))
    return {
        'present': bool(value), 'structure': out, 'truncated': truncated,
        'unresolved_token_count': unknown, 'exact_fixed_product_version_grammar': exact,
        'all_version_shapes_match_public_reference': bool(versions) and
            all(v in public for v in versions),
        'only_fixed_words_public_versions_and_separators_observed':
            bool(value) and not unknown and not truncated and bool(versions) and
            all(v in public for v in versions),
        'raw_value_exported': False, 'fingerprinting_absence_proven': False}


def table_sequences(body):
    """Accept only recognized public table text; do not scan arbitrary content."""
    try:
        text = body.decode('utf-8-sig')
    except UnicodeError:
        return set(), False
    lines = text.splitlines()
    headers = [line for line in lines if line and not line.startswith('#')]
    if not headers:
        return set(), False
    header = headers[0]
    if not (header.startswith('Product!STRING:0|Seqn!DEC:4|Flags!STRING:0')
            or header.startswith('Region!STRING:')
            or header.startswith('Name!STRING:')):
        return set(), False
    seqs = set(SEQ.findall(text))
    if header == 'Product!STRING:0|Seqn!DEC:4|Flags!STRING:0':
        for line in headers[1:]:
            fields = line.split('|')
            if len(fields) == 3 and re.fullmatch(r'[0-9]{1,20}', fields[1]):
                seqs.add(fields[1])
    return seqs, True


class ResponseRelation:
    """Reassembles framed identity HTTP/1 responses from successful TLS output.

    Rejects ambiguous framing, unsupported content encodings and oversized
    streams. A gap or rejected framing cannot become positive evidence.
    """
    def __init__(self, public=()):
        self.public = set(public)
        self.buffers = {}
        self.blocked = set()
        self.sequence_sets = {}
        self.queries = []
        self.counts = Counter()
        self.total = 0

    def note_query(self, key, value, route):
        if len(self.queries) >= 1000:
            self.counts['query_cap_hit'] += 1
            return
        self.queries.append((key, value, route))

    def _reject(self, key, reason):
        self.counts[reason] += 1
        self.buffers.pop(key, None)
        self.blocked.add(key)

    def feed(self, key, data):
        if key in self.blocked:
            return
        self.total += len(data)
        if self.total > 16 * MAX_BODY:
            self._reject(key, 'total_input_cap_hit')
            return
        buf = self.buffers.get(key, b'') + data
        if len(buf) > MAX_BODY + 65536:
            self._reject(key, 'stream_cap_hit')
            return
        while buf:
            cut = buf.find(b'\r\n\r\n')
            if cut < 0:
                if len(buf) > 65536:
                    self._reject(key, 'header_cap_hit')
                    return
                break
            lines = buf[:cut].decode('latin1').split('\r\n')
            if not re.fullmatch(r'HTTP/1\.[01] [0-9]{3}(?: .*)?', lines[0]):
                self._reject(key, 'invalid_or_midstream_response')
                return
            headers = {}
            for line in lines[1:]:
                if ':' not in line:
                    self._reject(key, 'invalid_header')
                    return
                k, v = line.split(':', 1)
                headers.setdefault(k.lower(), []).append(v.strip())
            status = int(lines[0].split(' ')[1])
            enc = headers.get('content-encoding', ['identity'])
            if enc != ['identity']:
                self._reject(key, 'unsupported_content_encoding')
                return
            cl = headers.get('content-length', [])
            te = headers.get('transfer-encoding', [])
            if len(cl) > 1 or (cl and te) or (te and te != ['chunked']):
                self._reject(key, 'ambiguous_framing')
                return
            start = cut + 4
            if 100 <= status < 200 or status in (204, 304):
                body, end = b'', start
            elif cl:
                if not re.fullmatch(r'[0-9]+', cl[0]) or int(cl[0]) > MAX_BODY:
                    self._reject(key, 'invalid_body_length')
                    return
                end = start + int(cl[0])
                if len(buf) < end:
                    break
                body = buf[start:end]
            elif te:
                pos, parts, size, end = start, [], 0, None
                while True:
                    eol = buf.find(b'\r\n', pos)
                    if eol < 0:
                        break
                    # Extensions and trailers deliberately unsupported.
                    if not re.fullmatch(rb'[0-9a-fA-F]{1,8}', buf[pos:eol]):
                        self._reject(key, 'unsupported_chunk_syntax')
                        return
                    n = int(buf[pos:eol], 16)
                    size += n
                    if size > MAX_BODY:
                        self._reject(key, 'body_cap_hit')
                        return
                    pos = eol + 2
                    if len(buf) < pos + n + 2:
                        break
                    if buf[pos+n:pos+n+2] != b'\r\n':
                        self._reject(key, 'invalid_chunk_boundary')
                        return
                    if not n:
                        end, body = pos + 2, b''.join(parts)
                        break
                    parts.append(buf[pos:pos+n])
                    pos += n + 2
                else:
                    raise AssertionError('unreachable')
                if end is None:
                    break
            else:
                self._reject(key, 'close_delimited_response_unsupported')
                return
            self.counts['complete_framed_responses'] += 1
            if status == 200:
                seqs, recognized = table_sequences(body)
                if recognized:
                    self.counts['recognized_200_table_responses'] += 1
                    self.sequence_sets.setdefault(key, set()).update(seqs)
            buf = buf[end:]
        self.buffers[key] = buf

    def report(self):
        rows = []
        for key, value, route in self.queries:
            same = value in self.sequence_sets.get(key, set())
            public = '@seq:' + value in self.public
            rows.append({
                'key': 'seqn', 'route_is_fixed_summary': route in ('/v1/summary', '/v2/summary'),
                'decimal': bool(re.fullmatch(r'[0-9]+', value)),
                'is_zero_sentinel_candidate_not_proven': value == '0',
                'matches_prepared_public_sequence_exact': public,
                'matches_sequence_in_complete_200_table_on_same_TLS_context': same,
                'context_had_rejected_response': key in self.blocked,
                'meaning': 'public_sequence_match_not_privacy_clearance' if public else
                    'same_context_response_sequence_match_not_causality' if same else
                    'unknown_requires_more_evidence',
                'raw_value_exported': False, 'fingerprinting_absence_proven': False})
        return {'rows': rows, 'response_observation_counts': dict(self.counts),
                'buffered_bytes': sum(map(len, self.buffers.values())),
                'matching_scope': 'same_TLS_context_not_request_response_pairing',
                'coverage_complete': False, 'raw_values_exported': False}