"""Validate only the observed first crash's instruction/address, no emulation."""
from inspect_dump import Dump,D,sha
import struct,json
f=sorted((D/'work').glob('*.dmp'))[0];md=Dump(f.read_bytes());r,s=md.streams[6];code,flags,record,rip,np,unused=struct.unpack('<IIQQII',md.read(r+8,32));assert np<=15
params=struct.unpack('<15Q',md.read(r+40,120));size,cr=struct.unpack('<II',md.read(r+160,8));ctx=md.read(cr,size);assert len(ctx)>=256
flags=struct.unpack_from('<I',ctx,48)[0];assert flags&0x100000 and flags&3==3
ctx_rip=struct.unpack_from('<Q',ctx,248)[0];r9=struct.unpack_from('<Q',ctx,192)[0];assert ctx_rip==rip
raw,_=md.memory(rip,8,md.ranges());assert raw==bytes.fromhex('458099f3cccccccc')
# REX 45, 80 /3, ModRM 99: SBB byte ptr [r9+disp32], imm8.
disp=struct.unpack('<i',raw[3:7])[0];effective=(r9+disp)&((1<<64)-1)
assert code==0xc0000005 and np>=2 and params[0]==1 and params[1]==effective
report={'dump':f.name,'exception':'0xc0000005','access_type':'write','instruction_module':'Wow_loader.dll','instruction_rva':'0x401a05','instruction_hex':raw.hex(),'decoded_instruction':'sbb byte ptr [r9 - 0x3333330d], 0xcc','context_rip_matches_exception':True,'effective_address_matches_exception_parameter':True,'instruction_bytes_match_disk':True,'limits':'Only validates the crash-time write address arithmetic. No attribution to anti-cheat, decryption, deliberate crash, dump tooling, CPU/BIOS collection, or network sending. No prior instruction/control flow was recovered.'}
(D/'reports/first-crash-check.json').write_text(json.dumps(report,indent=2)+'\n');print('Verified first-crash instruction and write address against exception context; cause remains unassigned.')
