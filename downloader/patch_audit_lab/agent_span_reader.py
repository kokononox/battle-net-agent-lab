"""Bounded original header parser/address getters plus independent numbered-file adapter.

This is not Agent archive-open/read or BLTE execution. The five pure original
functions have no mocked call destinations. File I/O and payload verification
remain Python, with explicit expected keys and caller-supplied file mapping.
"""
import struct,subprocess
import agent_static_audit as identity
from pathlib import Path
import patch_audit as a
import source_binding as b
import synthetic_casc_format as fmt
MASK=(1<<64)-1

def inputs(header,address,available):
 a.require(type(header)is bytes and len(header)==30,'span_header_exact_width')
 a.require(type(address)is int and 0<=address<=MASK,'span_address_u64')
 a.require(type(available)is int and 0<=available<=0xffffffff,'span_available_u32')

def model(header,address,available=30):
 """Model the original parser, intentionally NOT the stricter reader policy."""
 inputs(header,address,available)
 low=address&0xffffffff;fold=bytearray(4)
 for i,v in enumerate(header):fold[(low+i)&3]^=v
 check=(fmt.TABLE[(low+30)&15]^((low+30)&0xffffffff))&0xffffffff
 valid=available>=30 and int.from_bytes(fold,'little')==check and int.from_bytes(header[22:26],'little')==fmt.hashlittle2(header[:22],0x3d6be971)[0] and header[20] in (0,1)
 if not valid:return {'valid':False,'record':bytes(40).hex(),'archive':0,'payload_offset':0}
 record=bytearray(40);record[:16]=header[:16][::-1];struct.pack_into('<QQ',record,16,address,int.from_bytes(header[16:20],'little'));record[32]=header[20]
 return {'valid':True,'record':bytes(record).hex(),'archive':address>>30,'payload_offset':(address&0x3fffffff)+30}

def oracle_identity(oracle):
 oracle=b.safe(Path(oracle),True);watch=b.Watch();receipt=b.json_object(watch.read(oracle.parent/'BUILD-RECEIPT.json',65536))
 a.require(receipt.get('format')=='agent-span-reader-build-1' and receipt.get('agent_sha256')==identity.AGENT_SHA256 and receipt.get('helpers')=={} and receipt.get('original_bytes_verified_in_elf') is True and receipt.get('no_rwx') is True and receipt.get('nx_stack') is True,'span_oracle_receipt')
 a.require(a.sha256(watch.read(oracle,2*1024**2))==receipt.get('binary_sha256'),'span_oracle_digest');watch.check();return oracle

def native(oracle,header,address,available=30):
 inputs(header,address,available);oracle=oracle_identity(oracle)
 data=struct.pack('<QI',address,available)+header+bytes(2)
 p=subprocess.run([str(oracle)],input=data,capture_output=True,timeout=5)
 a.require(p.returncode==0 and len(p.stdout)==60 and not p.stderr,'span_native_execution')
 valid=struct.unpack_from('<I',p.stdout)[0];a.require(valid in (0,1),'span_native_bool');archive,payload=struct.unpack_from('<QQ',p.stdout,44)
 return {'valid':bool(valid),'record':p.stdout[4:44].hex(),'archive':archive,'payload_offset':payload}

def compare(oracle,*args,**kw):
 expected=model(*args,**kw);observed=native(oracle,*args,**kw);a.require(expected==observed,'span_original_model_parity');return observed

def read_numbered(oracle,files,address,span,ekey,decoded_size,ckey):
 """Read only one explicit research archive, never scan or write.

Absolute V8 base is unpacked by a policy first for selecting a supplied file;
then the unchanged Agent getters must return that same archive and payload
position. Wrong headers/keys/lengths are rejected before BLTE decoding.
"""
 a.key(ekey);a.key(ckey)
 a.require(type(address)is int and 0<=address<1024*(1<<30),'span_reader_address_profile')
 a.require(type(span)is int and 30<span<=1024**2+30,'span_reader_size_profile')
 archive=address>>30;offset=address&0x3fffffff
 a.require(offset>=480 and offset+span<=1<<30,'span_reader_segment_bounds')
 a.require(type(files)is dict and archive in files,'span_reader_explicit_archive_required')
 path=Path(files[archive]);a.require(path.name==f'data.{archive:03d}','span_reader_numbered_filename')
 # No discovery, network, auto-fallback, mkdir or writes. Safe paths forbid links.
 watch=b.Watch();raw=watch.read(path,2*1024**2)
 a.require(offset+span<=len(raw),'span_reader_file_bounds')
 chunk=raw[offset:offset+span];parsed=compare(oracle,chunk[:30],address,span)
 a.require(parsed['valid'],'span_reader_original_header_rejected')
 rec=bytes.fromhex(parsed['record']);stored_address,stored_span=struct.unpack_from('<QQ',rec,16)
 a.require(rec[:16].hex()==ekey and stored_address==address and stored_span==span and rec[32]==0,'span_reader_key_size_flag')
 a.require(parsed['archive']==archive and parsed['payload_offset']==offset+30,'span_reader_original_address_mismatch')
 decoded,proof=fmt.read_span(chunk,ekey,decoded_size,ckey,archive,offset);watch.check()
 return {'format':'agent-span-read-bridge-1','archive':archive,'filename':path.name,'absolute_address':address,'header_offset':offset,'payload_offset':parsed['payload_offset'],'span':span,'encoded_bytes':len(chunk)-30,'decoded_bytes':len(decoded),'decoded_md5':a.md5(decoded),'encoded_sha256':a.sha256(chunk[30:]),'original_header_and_getters_executed':True,'file_io_implementation':'independent Python, not Agent','agent_archive_io_executed':False,'installation_ready':False}
