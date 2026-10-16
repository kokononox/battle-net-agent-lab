"""Pinned Agent 9824 byte anchors and PE32 import/call receipts, never execution.
This is a bounded static audit, not a decompiler or a demonstrated activation API.
"""
import argparse,json,struct
from pathlib import Path
import agent_static_audit as old
import patch_audit as a
import source_binding as b

class PE:
    def __init__(self,raw):
        a.require(isinstance(raw,bytes) and 0x100<=len(raw)<=8*1024**2,'activation_pe_size')
        self.raw=raw
        a.require(raw[:2]==b'MZ','activation_dos')
        pe=int.from_bytes(raw[60:64],'little');a.require(0x40<=pe<=len(raw)-24,'activation_pe_offset')
        a.require(raw[pe:pe+4]==b'PE\0\0','activation_pe_signature')
        op=pe+24;opt=int.from_bytes(raw[pe+20:pe+22],'little');n=int.from_bytes(raw[pe+6:pe+8],'little')
        a.require(1<=n<=32 and opt>=112 and op+opt+n*40<=len(raw),'activation_pe_headers')
        a.require(int.from_bytes(raw[pe+4:pe+6],'little')==0x14c and int.from_bytes(raw[op:op+2],'little')==0x10b,'activation_pe32')
        self.base=int.from_bytes(raw[op+28:op+32],'little');self.sections=[]
        for i in range(n):
            at=op+opt+40*i;_,rva,size,offset=struct.unpack_from('<IIII',raw,at+8)
            a.require(offset+size<=len(raw),'activation_section_bounds');self.sections.append((self.base+rva,offset,size))
        self.import_rva,self.import_size=struct.unpack_from('<II',raw,op+104)
    def read(self,va,size):
        a.require(type(va)is int and type(size)is int and 0<=size<=65536,'activation_va_size')
        for base,offset,length in self.sections:
            if base<=va and va+size<=base+length:return self.raw[offset+va-base:offset+va-base+size]
        raise a.AuditError('activation_va_unbacked')
    def u32(self,va):return int.from_bytes(self.read(va,4),'little')
    def string(self,va):
        out=bytearray()
        for i in range(256):
            v=self.read(va+i,1)
            if v==b'\0':
                try:return bytes(out).decode('ascii')
                except UnicodeError:raise a.AuditError('activation_import_ascii') from None
            out.extend(v)
        raise a.AuditError('activation_import_string_limit')
    def imports(self):
        a.require(20<=self.import_size<=4096,'activation_import_directory_limit');out={};terminated=False
        for at in range(0,self.import_size-19,20):
            fields=struct.unpack('<5I',self.read(self.base+self.import_rva+at,20))
            if not any(fields):terminated=True;break
            lookup,_,_,name,iat=fields;dll=self.string(self.base+name)
            for i in range(4096):
                value=self.u32(self.base+(lookup or iat)+4*i)
                if value==0:break
                symbol='#'+str(value&65535) if value&0x80000000 else self.string(self.base+value+2)
                address=self.base+iat+4*i;a.require(address not in out,'activation_duplicate_iat');out[address]={'dll':dll,'name':symbol}
            else:raise a.AuditError('activation_import_thunk_limit')
        a.require(terminated,'activation_import_directory_unterminated');return out
    def relcall(self,va):
        raw=self.read(va,5);a.require(raw[0]==0xe8,'activation_relcall_opcode')
        return va+5+int.from_bytes(raw[1:],'little',signed=True)

ANCHORS={
'bind_mode5_dispatch':(0x71dd8e,'833805751e'),
'v4_constructor_protocol':(0x71de0e,'c785acfeffff04000000'),
'v4_constructor_header_size':(0x71de1e,'c785b0feffff50010000'),
'v4_constructor_payload_size':(0x71de3b,'c745b4b82a0000'),
'v4_constructor_payload_offset':(0x71de44,'c745b850010000'),
'v4_constructor_file_size':(0x71de4b,'b8102c0000'),
'v5_constructor_header_variants':(0x71def0,'be54010000b958020000'),
'v5_constructor_protocol':(0x71df0a,'6a055a'),
'v5_page_alignment':(0x71df5d,'8d86ff0f00002500f0ffff'),
'bind_mapped_pointer':(0x71e169,'0faef08b7718'),
'bind_protocol_lower':(0x71e18c,'39160f82b5000000'),
'bind_protocol_upper':(0x71e194,'39060f87ad000000'),
'bind_payload_size':(0x71e19c,'81be08010000b82a0000'),
'bind_payload_pointer':(0x71e212,'89378b860c01000003c6894704'),
'map_zero_offset_whole_file':(0x72e352,'535353536a01'),
'control_output_mapping_move':(0x72e42e,'8b8dd8feffff8841148d85b8feffff5083c118'),
'mapping_move_base_pointer':(0x86c798,'8b55088b02893a8906'),
'flush_success_gate':(0x71f227,'85f6743c'),
'rename_flags_zero':(0x8652b4,'6a005756'),
'rename_three_attempts':(0x71f31b,'83f9030f8256ffffff'),
'refresh_header_sequence_base':(0x71ea22,'8b0f6a1081c11001000083c60c5a'),
'refresh_header_sequence_copy':(0x71ea30,'8b068d760889018d490483ea0175f1'),
'index_filename_bswap':(0x71f0f4,'8b45140fc8'),
'index_filename_extension':(0x71f110,'a100e69b0083c41489460aa004e69b0088460e'),
}
CALLS={'construct_v4_mapping':(0x71de7c,0x72e265),'construct_v5_mapping':(0x71df9f,0x72e265),'map_file_wrapper':(0x72e366,0x86c8e5),'transfer_mapping':(0x72e441,0x86c784),'flush_table_sync':(0x71f21f,0x864dc2),'flush_table_rename':(0x71f2af,0x865253),'sequence_name_builder':(0x71f28c,0x71f0d3)}
IAT_CALLS={'flush_api':(0x864dca,0x8fb48c,'FlushFileBuffers'),'rename_api':(0x8652b8,0x8fb2dc,'MoveFileExW'),'create_mapping_api':(0x86c9f7,0x8fb2e4,'CreateFileMappingW'),'map_view_api':(0x86ca23,0x8fb2ec,'MapViewOfFile')}

def verify(pe):
    imports=pe.imports();anchors={};calls={};apis={}
    for name,(va,h) in ANCHORS.items():
        expected=bytes.fromhex(h);a.require(pe.read(va,len(expected))==expected,'activation_anchor_'+name);anchors[name]=hex(va)
    for name,(va,target) in CALLS.items():
        a.require(pe.relcall(va)==target,'activation_call_'+name);calls[name]={'call':hex(va),'target':hex(target)}
    for name,(va,iat,symbol) in IAT_CALLS.items():
        a.require(pe.read(va,6)==b'\xff\x15'+iat.to_bytes(4,'little'),'activation_iat_opcode_'+name)
        entry=imports.get(iat);a.require(entry is not None and entry['name']==symbol,'activation_iat_symbol_'+name)
        apis[name]={'call':hex(va),'iat':hex(iat),**entry}
    a.require(pe.read(0x9be600,5)==b'.idx\0','activation_index_extension')
    return {'anchors':anchors,'direct_calls':calls,'import_calls':apis}

def analyze(raw):
    a.require(isinstance(raw,bytes) and len(raw)<=8*1024**2,'activation_agent_size')
    a.require(a.sha256(raw)==old.AGENT_SHA256,'activation_pinned_agent_sha256')
    result=verify(PE(raw))
    return {'format':'agent-9824-activation-static-1','agent_sha256':old.AGENT_SHA256,'status':'bounded_static_paths_verified','binary_executed':False,'network_requests':0,'game_or_lab_written':False,'evidence':result,'activation_contract_complete':False,'installation_ready':False,'limitations':['Not a whole-program CFG or runtime trace','Actual user shmem not available in portable fixture','No .build.info writer or full-build closure proof','MoveFileExW(flags=0) in this helper is not power-loss atomicity proof']}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--agent',required=True,type=Path);args=p.parse_args();w=b.Watch();raw=w.read(args.agent,8*1024**2);result=analyze(raw);w.check();print(json.dumps(result,indent=2))
if __name__=='__main__':main()
