"""Version-pinned offline static checks; no target execution, network or raw IDs.
Checks reproduce anchors of a manually reviewed x86 data-flow argument, not a
formal proof of runtime reachability, storage persistence or complete coverage.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

SHA256 = 'b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5'


def analyze(image):
    if hashlib.sha256(image).hexdigest() != SHA256:
        raise ValueError('Unsupported Agent image: SHA-256 mismatch')
    pe = struct.unpack_from('<I', image, 0x3c)[0]
    if image[:2] != b'MZ' or image[pe:pe+4] != b'PE\0\0':
        raise ValueError('Invalid PE')
    machine, count = struct.unpack_from('<HH', image, pe+4)
    optsize = struct.unpack_from('<H', image, pe+20)[0]
    opt = pe+24
    if machine != 0x14c or struct.unpack_from('<H', image, opt)[0] != 0x10b:
        raise ValueError('Expected x86 PE32')
    base = struct.unpack_from('<I', image, opt+28)[0]
    sections = []
    for index in range(count):
        off = opt+optsize+40*index
        _, rva, size, raw = struct.unpack_from('<IIII', image, off+8)
        sections.append((base+rva, size, raw))

    def read(va, size):
        for start, length, raw in sections:
            if start <= va and va+size <= start+length:
                return image[raw+va-start:raw+va-start+size]
        raise ValueError('VA outside raw sections')

    checks = []

    def anchor(label, va, expected):
        if read(va, len(expected)) != expected:
            raise ValueError('Static anchor mismatch: '+label)
        checks.append({'label': label, 'va': hex(va), 'verified': True})

    def call(label, va, target):
        if read(va, 1) != b'\xe8' or va+5+struct.unpack('<i',read(va+1,4))[0] != target:
            raise ValueError('Relative call mismatch: '+label)
        checks.append({'label': label, 'va': hex(va), 'target': hex(target), 'verified': True})

    anchor('host_id diagnostic literal',0x9f71dc,b"CreateDefaultContext: Failed to create 'host_id'.\0")
    anchor('diagnostic xref',0x8b087a,b'\x68\xdc\x71\x9f\x00')
    call('default context fill',0x8b077a,0x8b0f01)
    anchor('diagnostic validates same nested string',0x8b07a7,b'\x8b\x40\x20')
    call('UUID wrapper',0x8ba2a3,0x8ba244)
    call('UUID bit-setting generator',0x8ba24d,0x8c8d80)
    anchor('Context field 4 object at +0x28',0x7d53e9,b'\xff\x73\x28\x6a\x04')
    call('Context field 4 serializer helper',0x7d53ee,0x81275e)
    anchor('nested string at +0x20',0x7d45c1,b'\x8b\x47\x20')
    anchor('nested field number 1',0x7d45d2,b'\x6a\x01')
    call('nested string serializer',0x7d45d4,0x48921b)
    anchor('provider vtable slot 0x1c',0x8b100b,b'\xff\x50\x1c')
    anchor('provider constructor vtable',0x8b97a6,b'\xc7\x06\x88\x82\x9f\x00')
    anchor('provider function pointer',0x9f82a4,struct.pack('<I',0x8c13b0))
    anchor('configuration source_id key',0x9f9958,b'source_id\0')
    anchor('source read virtual call',0x8c147d,b'\xff\xd3')
    call('UUID fallback generator',0x8c14b7,0x8ba288)
    anchor('source write virtual call',0x8c151b,b'\xff\xd3')
    anchor('ephemeral suffix literal',0x9f9964,b'-ephemeral\0')
    anchor('UUID version 4 bits',0x8c8d98,b'\x24\x0f\x0c\x40')
    anchor('UUID variant bits',0x8c8da2,b'\x24\x3f\x0c\x80')
    call('candidate host name helper',0x8b9ca1,0x8b9785)
    call('host name wrapper',0x8b9790,0x86cfed)
    anchor('GetComputerNameW import call',0x86d019,b'\xff\x15\x5c\xb5\x8f\x00')
    hint = struct.unpack('<I',read(0x8fb55c,4))[0]
    anchor('GetComputerNameW import name',base+hint+2,b'GetComputerNameW\0')
    return {'schema':'bnet-static-host-id-1','agent_sha256':SHA256,
            'method':'manual static data-flow review with pinned instruction anchors',
            'checks':checks,'wire_path':'/1/4/1',
            'mapped_agent_field':'host_id',
            'configuration_key_in_fallback':'source_id',
            'uuid_v4_fallback_present':True,
            'runtime_branch_selected':'not_established',
            'actual_storage_path':'not_established',
            'persistence_after_restart':'not_tested',
            'hardware_derivation':'not_established',
            'global_uniqueness':'not_established',
            'note':'Only the Agent field mapping is reviewed; Bootstrapper payload field names remain unavailable.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('agent',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args()
    if args.agent.stat().st_size > 64*1024*1024:
        raise ValueError('Input too large')
    args.output.write_text(json.dumps(analyze(args.agent.read_bytes()),indent=2)+'\n')
    print('Pinned static checks passed; no target execution or raw identifiers exported.')


if __name__ == '__main__':
    main()
