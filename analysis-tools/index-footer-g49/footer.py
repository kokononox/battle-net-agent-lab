"""Strict offline parser for the pinned 28-byte v1 archive-index footer only."""
import hashlib
class Rejected(ValueError):pass
def verify_footer(b,key,observed_total):
 if len(b)!=28:raise Rejected('footer_size')
 if hashlib.md5(b).hexdigest()!=key:raise Rejected('footer_filename_key')
 if hashlib.md5(b[8:20]+b'\0'*8).digest()[:8]!=b[20:]:raise Rejected('footer_checksum')
 version,f0,f1,bkb,ob,sb,kb,hb=b[8:16];n=int.from_bytes(b[16:20],'little')
 if (version,f0,f1,bkb,ob,sb,kb,hb)!=(1,0,0,4,4,4,16,8) or not 1<=n<=10000:raise Rejected('unsupported_footer_fields')
 block_bytes=bkb*1024;per_block=block_bytes//(ob+sb+kb);blocks=(n+per_block-1)//per_block;size=blocks*(block_bytes+kb+hb)+len(b)
 if size>131072 or size!=observed_total:raise Rejected('derived_layout_size_mismatch')
 return {'footer_key_md5_verified':True,'footer_checksum_verified':True,'record_count':n,'derived_blocks':blocks,'derived_index_bytes':size,'head_total_matches_derived_layout':True,'footer_sha256':hashlib.sha256(b).hexdigest(),'toc_hash_prefix':b[:8].hex(),'toc_content_verified':False,'block_content_verified':False,'publisher_signature_verified':False,'runtime_approved':False}
