"""Bounded, read-only WoW patch audit. No game installation paths or writer.

Supports observed PA2/extended/16-byte keys and ZBSDIFF1 sign-magnitude.
Unknown variants fail closed. MD5 verifies TACT identity, not publisher signatures.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
import urllib.request
import zlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl
import cdn_catalog

BUILD = '334a36cf5f3c32a5f7a167405487fa14'
CDN = 'fcab7fec2ccc6b8158b56b6938ec4551'
VERSION = '12.1.5.70391'
VERSIONS = 'https://us.version.battle.net/v2/products/wow/versions'
CDNS = 'https://us.version.battle.net/v2/products/wow/cdns'
MAX_METADATA = 8 * 1024**2
MAX_PATCH = 4 * 1024**2
MAX_OUTPUT = 16 * 1024**2
MAX_CONTROL = 4 * 1024**2
MAX_TRANSFERS = 12 * 1024**2

class AuditError(ValueError):
    pass

def require(condition, code):
    if not condition:
        raise AuditError(code)

def key(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{32}', value), 'invalid_key')
    return value

def md5(b):
    return hashlib.md5(b).hexdigest()

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def table(b):
    require(len(b) <= 64 * 1024, 'table_size_limit')
    try:
        lines = [s for s in b.decode('utf-8-sig').splitlines() if s and not s.startswith('#')]
    except UnicodeError as e:
        raise AuditError('table_encoding') from e
    require(len(lines) >= 2, 'table_empty')
    cols = [s.split('!')[0] for s in lines[0].split('|')]
    require(len(cols) == len(set(cols)), 'table_duplicate_columns')
    rows = []
    for line in lines[1:]:
        row = line.split('|')
        require(len(row) == len(cols), 'table_row_width')
        rows.append(dict(zip(cols, row)))
    return rows

def one(rows, column, value):
    rows = [r for r in rows if r.get(column) == value]
    require(len(rows) == 1, 'ambiguous_table_selection')
    return rows[0]

def official_origin(row):
    require(row.get('Path') == 'tpr/wow', 'product_path_mismatch')
    origins = []
    for url in row.get('Servers', '').split():
        try:
            p = urlsplit(url)
            hints = parse_qsl(p.query, keep_blank_values=True, strict_parsing=True)
            valid_hints = (len(dict(hints)) == len(hints) and all(
                (k == 'maxhosts' and v.isascii() and v.isdigit() and 1 <= int(v) <= 64)
                or (k == 'fallback' and v in ('0', '1')) for k, v in hints))
            if (p.scheme == 'https' and p.hostname and not p.username and not p.password
                    and p.port in (None, 443) and p.path in ('', '/') and not p.fragment
                    and valid_hints and re.fullmatch('[a-zA-Z0-9.-]+', p.hostname)
                    and '.' in p.hostname and not p.hostname.replace('.', '').isdigit()
                    and not p.hostname.lower().endswith(('.local', '.localhost'))):
                origins.append('https://' + p.hostname.lower())
        except ValueError:
            continue
    require(len(set(origins)) == 1, 'expected_one_official_eu_https_origin')
    return origins[0]

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError('redirect_not_allowed')

class Fetcher:
    """Fresh workspace only; total body bytes capped; HTTP errors don't read bodies."""
    def __init__(self, root, budget=MAX_TRANSFERS):
        self.root = Path(root)
        require(self.root.is_dir() and not self.root.is_symlink(), 'fresh_directory_required')
        self.budget = budget
        self.total = 0
        self.receipts = []
        self.opener = urllib.request.build_opener(NoRedirect())
        self.allowed_origin = None

    def get(self, url, name, limit, expected_size=None):
        p = urlsplit(url)
        require(p.scheme == 'https' and not p.username and not p.password
                and p.port in (None, 443) and not p.query and not p.fragment, 'unsafe_url')
        require(url in (VERSIONS, CDNS) or (
            self.allowed_origin is not None and p.scheme + '://' + p.netloc == self.allowed_origin
            and p.path.startswith('/tpr/wow/')), 'unbound_origin')
        require(re.fullmatch('[a-zA-Z0-9_.-]+', name), 'unsafe_output_name')
        dest = self.root / name
        require(not dest.exists() and not dest.is_symlink(), 'refuse_overwrite')
        require(type(limit) is int and 0 < limit <= MAX_METADATA, 'fetch_limit')
        if expected_size is not None:
            require(type(expected_size) is int and 0 < expected_size <= limit, 'declared_size_limit')
        cap = min(limit, self.budget - self.total)
        require(cap > 0, 'transfer_budget_exhausted')
        req = urllib.request.Request(url, headers={'Accept-Encoding': 'identity', 'User-Agent': 'WoW-Patch-Audit/0.1'})
        with self.opener.open(req, timeout=30) as r:
            validate_response(r, url, cap, expected_size)
            length = r.headers.get('Content-Length')
            blocks, size = [], 0
            while True:
                b = r.read(min(65536, cap + 1 - size))
                if not b:
                    break
                self.total += len(b)
                size += len(b)
                require(size <= cap, 'body_size_limit')
                blocks.append(b)
            data = b''.join(blocks)
            require(length is None or size == int(length), 'truncated_response')
            require(expected_size is None or size == expected_size, 'object_size_mismatch')
        with dest.open('xb') as f:
            f.write(data)
        self.receipts.append({'url': url, 'file': name, 'body_bytes': size, 'sha256': sha256(data)})
        return data

def validate_response(r, url, cap, expected_size):
    require(r.status == 200 and r.geturl() == url, 'unexpected_response_status_or_url')
    require(not r.headers.get('Content-Range'), 'unexpected_range_response')
    require(r.headers.get('Content-Encoding', 'identity').lower() in ('', 'identity'), 'encoded_http_body')
    length = r.headers.get('Content-Length')
    if length is not None:
        require(bool(re.fullmatch('[0-9]+', length)) and int(length) <= cap, 'http_size_limit')
        require(expected_size is None or int(length) == expected_size, 'http_size_mismatch')

def config(b, expected):
    require(len(b) <= MAX_METADATA and md5(b) == key(expected), 'config_checksum_mismatch')
    result = {}
    try:
        text = b.decode('utf-8-sig')
    except UnicodeError as e:
        raise AuditError('config_encoding') from e
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        require('=' in line, 'config_line_invalid')
        name, value = line.split('=', 1)
        name = name.strip()
        require(re.fullmatch('[a-zA-Z0-9_-]{1,80}', name) and name not in result, 'config_field_invalid')
        result[name] = value.split()
    return result

def object_url(origin, kind, k, suffix=''):
    key(k)
    require(kind in ('config', 'data', 'patch') and suffix in ('', '.index'), 'object_kind_invalid')
    return f'{origin}/tpr/wow/{kind}/{k[:2]}/{k[2:4]}/{k}{suffix}'

def inflate(b, cap):
    require(type(cap) is int and cap >= 0, 'inflate_limit')
    try:
        dec = zlib.decompressobj()
        out = dec.decompress(b, cap + 1)
        require(len(out) <= cap and not dec.unconsumed_tail, 'decompression_limit')
        require(dec.eof and not dec.unused_data, 'zlib_truncated_or_trailing')
        return out
    except zlib.error as e:
        raise AuditError('zlib_invalid') from e

def blte(b, ekey, ckey, decoded_size):
    require(len(b) >= 12 and b[:4] == b'BLTE', 'blte_header')
    hs = int.from_bytes(b[4:8], 'big')
    count = int.from_bytes(b[9:12], 'big')
    require(b[8] == 15 and 0 < count <= 1024 and hs == 12 + count * 24 and hs <= len(b), 'blte_table')
    require(md5(b[:hs]) == key(ekey), 'blte_ekey_mismatch')
    require(0 < decoded_size <= MAX_METADATA, 'blte_decoded_limit')
    offset, out = hs, bytearray()
    for i in range(count):
        at = 12 + i * 24
        cs, ds = struct.unpack_from('>II', b, at)
        require(cs > 0 and ds > 0 and offset + cs <= len(b) and len(out) + ds <= decoded_size, 'blte_chunk_bounds')
        chunk = b[offset:offset + cs]
        require(hashlib.md5(chunk).digest() == b[at + 8:at + 24], 'blte_chunk_checksum')
        if chunk[:1] == b'N':
            data = chunk[1:]
        elif chunk[:1] == b'Z':
            data = inflate(chunk[1:], ds)
        else:
            raise AuditError('unsupported_blte_chunk_mode')
        require(len(data) == ds, 'blte_chunk_size')
        out.extend(data)
        offset += cs
    require(offset == len(b) and len(out) == decoded_size and md5(out) == key(ckey), 'blte_content_mismatch')
    return bytes(out), count

@dataclass(frozen=True)
class PatchOption:
    target_ckey: str
    target_size: int
    source_ekey: str
    source_size: int
    patch_key: str
    patch_size: int
    ordinal: int

def manifest(b, expected):
    """PA2 observed variant: hashes cover used records plus zero terminator.

    Padding is NOT included in block hashes, but must itself be zero. No tail
    or unknown flags accepted. This is deliberately not a universal PA parser.
    """
    require(len(b) >= 51 and len(b) <= MAX_METADATA, 'manifest_size')
    require(b[:6] == b'PA\x02\x10\x10\x10' and b[9] == 2, 'unsupported_manifest_variant')
    require(12 <= b[6] <= 24, 'manifest_block_bits')
    count = int.from_bytes(b[7:9], 'big')
    require(0 < count <= 1800, 'manifest_block_count')
    header = 51 + b[50]
    table_end = header + count * 36
    require(table_end < 65536 and table_end < len(b), 'manifest_table_bounds')
    require(md5(b[:table_end]) == key(expected), 'manifest_header_checksum')
    bs, previous, records, options, offsets = 1 << b[6], None, 0, [], []
    for i in range(count):
        t = header + i * 36
        offsets.append(int.from_bytes(b[t + 32:t + 36], 'big'))
    require(offsets == [table_end + i * bs for i in range(count)], 'manifest_block_geometry')
    for i, offset in enumerate(offsets):
        end = min(offset + bs, len(b))
        require(offset < end and (i == count - 1 or end == offsets[i + 1]), 'manifest_block_bounds')
        block = b[offset:end]
        p, last = 0, None
        while p < len(block) and block[p] != 0:
            n = block[p]
            require(1 <= n <= 16 and p + 22 + n * 42 <= len(block), 'manifest_record_bounds')
            ck = block[p + 1:p + 17]
            size = int.from_bytes(block[p + 17:p + 22], 'big')
            require(ck != bytes(16) and size > 0 and (previous is None or previous < ck), 'manifest_target_order')
            previous, last = ck, ck
            p += 22
            records += 1
            for _ in range(n):
                source = block[p:p + 16]
                oldsize = int.from_bytes(block[p + 16:p + 21], 'big')
                pk = block[p + 21:p + 37]
                ps = int.from_bytes(block[p + 37:p + 41], 'big')
                ordinal = block[p + 41]
                require(source != bytes(16) and pk != bytes(16) and oldsize > 0 and ps > 0, 'manifest_patch_invalid')
                options.append(PatchOption(ck.hex(), size, source.hex(), oldsize, pk.hex(), ps, ordinal))
                p += 42
        require(last is not None, 'manifest_empty_block')
        require(not any(block[p:]), 'manifest_nonzero_padding')
        used = p + (p < len(block))
        t = header + i * 36
        require(last == b[t:t + 16], 'manifest_last_key_mismatch')
        require(hashlib.md5(block[:used]).digest() == b[t + 16:t + 32], 'manifest_block_checksum')
    require(offsets[-1] + bs >= len(b), 'manifest_unhandled_tail')
    return options, {'header_checksum_verified': True, 'all_block_checksums_verified': True,
                     'blocks': count, 'targets': records, 'patch_options': len(options),
                     'ordinal_values_raw': sorted({o.ordinal for o in options}),
                     'hash_scope': 'header+table; each block used records + optional zero terminator; padding checked separately',
                     'encoding_ckey': b[10:26].hex(), 'encoding_ekey': b[26:42].hex()}

def offtin(b):
    require(len(b) == 8, 'integer_width')
    value = int.from_bytes(b, 'little')
    magnitude = value & ((1 << 63) - 1)
    return -magnitude if value >> 63 else magnitude

def parse_patch(b, patch_key, output_size, output_limit=MAX_OUTPUT):
    require(32 <= len(b) <= MAX_PATCH and b[:8] == b'ZBSDIFF1', 'patch_header')
    require(md5(b) == key(patch_key), 'patch_checksum')
    c, d, n = [offtin(b[p:p + 8]) for p in (8, 16, 24)]
    require(c > 0 and d > 0 and n == output_size and 0 <= n <= output_limit
            and 32 + c + d < len(b), 'patch_declared_bounds')
    control = inflate(b[32:32 + c], MAX_CONTROL)
    diff = inflate(b[32 + c:32 + c + d], n)
    extra = inflate(b[32 + c + d:], n)
    require(len(control) % 24 == 0, 'patch_control_width')
    triples, ds, es, ns, oldpos, negative = [], 0, 0, 0, 0, 0
    for p in range(0, len(control), 24):
        x, y, seek = [offtin(control[p + j:p + j + 8]) for j in (0, 8, 16)]
        require(x >= 0 and y >= 0 and ns + x + y <= n, 'patch_control_bounds')
        # Zero-output control entries may move the source pointer; iteration is bounded.
        triples.append((x, y, seek))
        ds += x
        es += y
        ns += x + y
        oldpos += x + seek
        negative += seek < 0
        require(abs(oldpos) < 1 << 63, 'patch_seek_overflow')
    require(ds == len(diff) and es == len(extra) and ns == n, 'patch_stream_accounting')
    return triples, diff, extra, {'format': 'ZBSDIFF1', 'output_bytes': n, 'control_triples': len(triples),
                                  'negative_seek_entries': negative, 'integers': 'little-endian sign-magnitude',
                                  'patch_hash_verified': True, 'stream_sizes_reconciled': True}

def apply_patch(old, patch, patch_key, output_size, expected_ckey, *, source_sha256):
    """Pure in-memory reconstruction; no EKey/decoded-CKey confusion.

    Caller MUST bind source bytes to prior verified provenance. SHA256 here
    binds fixture bytes only; it does not prove an arbitrary decoded file's EKey.
    No game installation I/O is exposed.
    """
    require(len(old) <= MAX_OUTPUT and sha256(old) == source_sha256, 'source_proof_mismatch')
    triples, diff, extra, info = parse_patch(patch, patch_key, output_size)
    result = bytearray(output_size)
    oldpos = newpos = dp = ep = 0
    for x, y, seek in triples:
        for j in range(x):
            at = oldpos + j
            result[newpos + j] = (diff[dp + j] + (old[at] if 0 <= at < len(old) else 0)) & 255
        newpos += x
        oldpos += x
        dp += x
        result[newpos:newpos + y] = extra[ep:ep + y]
        ep += y
        newpos += y
        oldpos += seek
    require(md5(result) == key(expected_ckey), 'output_ckey_mismatch')
    return bytes(result), info

def run(root):
    f = Fetcher(root)
    v = one(table(f.get(VERSIONS, 'versions.txt', 65536)), 'Region', 'eu')
    require((v.get('VersionsName'), v.get('BuildConfig'), v.get('CDNConfig')) == (VERSION, BUILD, CDN), 'pinned_target_changed')
    c = one(table(f.get(CDNS, 'cdns.txt', 65536)), 'Name', 'eu')
    origin = official_origin(c)
    f.allowed_origin = origin
    build = config(f.get(object_url(origin, 'config', BUILD), 'build.config', MAX_METADATA), BUILD)
    cdn = config(f.get(object_url(origin, 'config', CDN), 'cdn.config', MAX_METADATA), CDN)
    require(build.get('build-uid') == ['wow'] and build.get('build-name') == ['WOW-70391patch12.1.5_Retail'], 'build_identity')
    if 'builds' in cdn:
        require(BUILD in cdn['builds'], 'cdn_build_binding')
    require(len(build.get('patch', [])) == len(build.get('patch-size', [])) == 1, 'patch_binding_shape')
    mk = key(build['patch'][0])
    raw = f.get(object_url(origin, 'patch', mk), 'manifest.pa', MAX_METADATA, int(build['patch-size'][0]))
    options, maudit = manifest(raw, mk)
    require(len(build.get('patch-index', [])) == len(build.get('patch-index-size', [])) == 2, 'patch_index_binding_shape')
    ck, ek = build['patch-index']
    ds, es = map(int, build['patch-index-size'])
    rawindex = f.get(object_url(origin, 'data', ek), 'patch-index.blte', MAX_METADATA, es)
    _, chunks = blte(rawindex, ek, ck, ds)
    require(len(cdn.get('patch-file-index', [])) == len(cdn.get('patch-file-index-size', [])) == 1, 'loose_index_binding_shape')
    ik = key(cdn['patch-file-index'][0])
    index = f.get(object_url(origin, 'patch', ik, '.index'), 'patch-loose.index', MAX_METADATA, int(cdn['patch-file-index-size'][0]))
    wanted = {}
    for option in options:
        k = bytes.fromhex(option.patch_key)
        require(k not in wanted or wanted[k] == option.patch_size, 'conflicting_patch_sizes')
        wanted[k] = option.patch_size
    routes, iaudit = cdn_catalog.matches(index, ik, wanted, kind='loose')
    found = {r[0].hex() for r in routes}
    candidates = [o for o in options if o.patch_key in found and o.patch_size <= MAX_PATCH and o.target_size <= MAX_OUTPUT]
    require(candidates, 'no_small_advertised_patch')
    sample = min(candidates, key=lambda o: (o.patch_size, o.patch_key))
    data = f.get(object_url(origin, 'patch', sample.patch_key), 'sample.zbsdiff', MAX_PATCH, sample.patch_size)
    _, _, _, paudit = parse_patch(data, sample.patch_key, sample.target_size)
    report = {'schema': 1, 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
              'status': 'official_metadata_and_patch_verified_not_applied',
              'target': {'version': VERSION, 'build_config': BUILD, 'cdn_config': CDN, 'region': 'eu'},
              'manifest': maudit, 'patch_index': {'encoded_ekey_verified': True, 'decoded_ckey_verified': True,
                'all_chunk_hashes_verified': True, 'chunks': chunks, 'decoded_bytes': ds, 'semantic_parser_implemented': False},
              'loose_index': iaudit, 'advertised_matching_patch_options': len(candidates),
              'sample': {**asdict(sample), **paudit},
              'network_body_bytes': f.total, 'receipts': f.receipts,
              'source_game_files_read': False, 'game_files_modified': False, 'patch_applied': False,
              'source_for_retail_sample_available': False, 'source_ekey_is_not_a_decoded_ckey': True,
              'patch_ordinal_policy_proven': False, 'patch_savings_for_user_installation': None,
              'required_network_download_bytes': None, 'installation_ready': False,
              'limitations': ['Retail source not supplied or decoded; no reconstruction claimed for this sample.',
                             'Only observed PA2 variant supported; patch-index semantics and ordinal/chaining unresolved.',
                             'Classic reference-fixture reconstruction, if run separately, does not prove Retail CASC installation.',
                             'Body-byte count excludes TLS/HTTP overhead, previous runs and failed responses.',
                             'MD5 is TACT identity validation over HTTPS, not publisher-signature verification.']}
    (Path(root) / 'PATCH-AUDIT.json').write_text(json.dumps(report, indent=2) + '\n')
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New, non-existing audit directory; never a game/Lab path')
    args = parser.parse_args()
    root = Path(args.output)
    # Parents must exist; symlink parents and existing destinations are rejected.
    require(not root.exists() and not root.is_symlink() and root.parent.is_dir()
            and all(not p.is_symlink() for p in [root.parent, *root.parent.parents]), 'new_output_directory_required')
    root.mkdir()
    try:
        report = run(root)
        print(json.dumps({k: report[k] for k in ('status', 'network_body_bytes', 'patch_applied', 'installation_ready')}))
    except Exception as e:
        (root / 'AUDIT-FAILED.json').write_text(json.dumps({'status': 'failed', 'error_type': type(e).__name__,
                                                          'error': str(e)[:200], 'installation_ready': False}))
        raise

if __name__ == '__main__':
    main()
