"""Bounded offline Install layout candidate. NOT an installer or policy engine.

The interpretation below is a structural hypothesis for one pinned object.
Matching hashes establish object identity, not publisher signature, bit-order
semantics, vendor tag-selection policy or complete game content closure.
"""
from dataclasses import dataclass
import hashlib
import struct

EXPECTED_SIZE = 24078
EXPECTED_CKEY = 'd7c8cd9845e2b5d39821678f481324da'
EXPECTED_SHA256 = '1e9a735e4ec5ffe7fc10b9f39e347cf6f9745a89d15ba700a3982399644d92a6'
MAX_TAGS = 64
MAX_ENTRIES = 512

class LayoutError(ValueError):
    pass

def need(value, code):
    if not value:
        raise LayoutError(code)

@dataclass(frozen=True)
class Tag:
    name: str
    kind: int
    bitmap: bytes

@dataclass(frozen=True)
class Entry:
    name: str
    digest: bytes
    declared_size: int

@dataclass(frozen=True)
class Layout:
    version: int
    digest_bytes: int
    tags: tuple
    entries: tuple
    entry_section_offset: int
    consumed_bytes: int

class Cursor:
    def __init__(self, data):
        need(type(data) is bytes, 'bytes_required')
        need(len(data) <= EXPECTED_SIZE, 'input_limit')
        self.data, self.pos = data, 0

    def take(self, n):
        need(type(n) is int and n >= 0, 'invalid_length')
        need(n <= len(self.data) - self.pos, 'truncated')
        result = self.data[self.pos:self.pos+n]
        self.pos += n
        return result

    def string(self, maximum, ascii_only=False):
        # The bounded search never scans outside the current field budget.
        stop = self.data.find(b'\0', self.pos, min(len(self.data), self.pos+maximum+1))
        need(stop >= self.pos, 'unterminated_or_oversize_string')
        raw = self.take(stop-self.pos)
        self.take(1)
        need(bool(raw), 'empty_string')
        try:
            result = raw.decode('ascii' if ascii_only else 'utf-8', errors='strict')
        except UnicodeError:
            raise LayoutError('invalid_string_encoding') from None
        need(all(ord(c) >= 32 and ord(c) != 127 for c in result), 'control_character')
        return result

def parse_candidate(data):
    c = Cursor(data)
    magic, version, digest_bytes, ntags, nentries = struct.unpack('>2sBBHI', c.take(10))
    need(magic == b'IN', 'magic')
    need(version == 1, 'unsupported_version')
    need(digest_bytes == 16, 'unsupported_digest_width')
    need(ntags <= MAX_TAGS, 'tag_limit')
    need(nentries <= MAX_ENTRIES, 'entry_limit')
    width = (nentries+7)//8
    tags, seen = [], set()
    for _ in range(ntags):
        label = c.string(64, ascii_only=True)
        need(label not in seen, 'duplicate_tag')
        seen.add(label)
        kind = struct.unpack('>H', c.take(2))[0]
        bitmap = c.take(width)
        # Padding bits are preserved verbatim. Nonzero padding is NOT corruption.
        tags.append(Tag(label, kind, bitmap))
    entry_offset = c.pos
    entries = []
    for _ in range(nentries):
        name = c.string(4096)
        digest = c.take(digest_bytes)
        size = struct.unpack('>I', c.take(4))[0]
        # This is metadata, not an extraction target. Never resolve or write names.
        entries.append(Entry(name, digest, size))
    need(c.pos == len(data), 'trailing_bytes')
    return Layout(version, digest_bytes, tuple(tags), tuple(entries), entry_offset, c.pos)

def msb_candidate_members(bitmap, nentries):
    need(type(nentries) is int and 0 <= nentries <= MAX_ENTRIES, 'entry_limit')
    need(len(bitmap) == (nentries+7)//8, 'bitmap_length')
    return tuple(i for i in range(nentries) if bitmap[i//8] & (0x80 >> (i%8)))

def pinned_observation(data):
    # Exact identity is separate from and stronger than generic layout acceptance.
    need(type(data) is bytes and len(data) == EXPECTED_SIZE, 'pinned_size')
    need(hashlib.md5(data).hexdigest() == EXPECTED_CKEY, 'pinned_ckey')
    need(hashlib.sha256(data).hexdigest() == EXPECTED_SHA256, 'pinned_sha256')
    layout = parse_candidate(data)
    n = len(layout.entries)
    unused = (8-n%8)%8
    mask = (1 << unused)-1
    return {
        'format': 'pinned-install-structural-observation-1',
        'status': 'exact_identity_and_complete_candidate_layout_verified',
        'decoded_size': len(data), 'ckey': EXPECTED_CKEY, 'sha256': EXPECTED_SHA256,
        'header_first_10_bytes_hex': data[:10].hex(),
        'layout_candidate': {'magic': 'IN', 'version': layout.version,
            'digest_bytes': layout.digest_bytes, 'tag_count': len(layout.tags),
            'entry_count': n, 'bitmap_bytes_per_tag': (n+7)//8,
            'entry_section_offset': layout.entry_section_offset,
            'consumed_bytes': layout.consumed_bytes, 'trailing_bytes': 0,
            'entry_layout': 'NUL-terminated UTF-8 name, 16 raw digest bytes, big-endian uint32 declared size',
            'tag_layout': 'NUL-terminated ASCII label, big-endian uint16 kind, ceil(entry_count/8) raw bitmap bytes'},
        'raw_padding_observation': {'unused_bits_per_bitmap': unused,
            'nonzero_padding_tag_count': sum(bool(t.bitmap[-1] & mask) for t in layout.tags) if mask else 0,
            'padding_values': sorted({t.bitmap[-1] & mask for t in layout.tags}) if mask else [],
            'nonzero_padding_is_not_corruption': True},
        'tags': [{'label': t.name, 'kind': t.kind,
            'msb_first_candidate_member_count_NOT_vendor_selection': len(msb_candidate_members(t.bitmap,n))}
            for t in layout.tags],
        'observed_entry_properties': {
            'duplicate_exact_names': n-len({e.name for e in layout.entries}),
            'duplicate_raw_digests': n-len({e.digest for e in layout.entries}),
            'zero_declared_sizes': sum(e.declared_size == 0 for e in layout.entries),
            'interpretation_limit': 'Exact names/digests only; no path canonicalization, payload validation or extraction'},
        'bit_order_independently_proven': False,
        'schema_publisher_documentation_checked_this_run': False,
        'vendor_tag_selection_policy_proven': False,
        'actual_required_install_set_known': False,
        'fresh_local_content_verified': False,
        'publisher_signature_verified': False,
        'network_requests': 0, 'archive_payload_bytes_read': 0,
        'user_game_or_lab_accessed': False, 'game_or_lab_writes': False,
        'installation_ready': False, 'required_network_download_bytes': None}
