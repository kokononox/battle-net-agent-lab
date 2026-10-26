"""Strict offline parser for observed normal/loose index v1, key16/hash8/block4KiB."""
import hashlib,math
class Rejected(ValueError):pass

def parse_index(b,expected_key,kind):
 if len(b)<28 or len(b)>131072 or kind not in ('archive_index','loose_file_index'):raise Rejected('index_bounds_or_kind')
 foot=b[-28:];toc_hash=foot[:8];version,f0,f1,bkb,ob,sb,kb,hb=foot[8:16];n=int.from_bytes(foot[16:20],'little')
 if (version,f0,f1,bkb,sb,kb,hb)!=(1,0,0,4,4,16,8) or ob!=(4 if kind=='archive_index' else 0) or not 1<=n<=10000:raise Rejected('unsupported_index_footer')
 if hashlib.md5(foot).hexdigest()!=expected_key:raise Rejected('index_key_footer_hash')
 if hashlib.md5(foot[8:20]+b'\0'*8).digest()[:8]!=foot[20:]:raise Rejected('footer_checksum')
 block_size=bkb*1024;entry_size=kb+sb+ob;per_block=block_size//entry_size;nb=(n+per_block-1)//per_block;toc_start=nb*block_size;toc_len=nb*(kb+hb)
 if len(b)!=toc_start+toc_len+28:raise Rejected('index_layout_size')
 toc=b[toc_start:toc_start+toc_len]
 if hashlib.md5(toc).digest()[:8]!=toc_hash:raise Rejected('toc_checksum')
 entries=[];pages=[];last_key=None
 for page in range(nb):
  block=b[page*block_size:(page+1)*block_size];expected_md5=toc[nb*kb+page*hb:nb*kb+(page+1)*hb]
  if hashlib.md5(block).digest()[:hb]!=expected_md5:raise Rejected('block_checksum')
  q=0;rows=[]
  while q+entry_size<=len(block) and any(block[q:q+kb]):
   key=block[q:q+kb];size=int.from_bytes(block[q+kb:q+kb+sb],'big');off=int.from_bytes(block[q+kb+sb:q+entry_size],'big') if ob else None;q+=entry_size
   if last_key is not None and key<=last_key:raise Rejected('index_key_order_or_duplicate')
   if size==0 or ob and off+size>2**32:raise Rejected('index_record_bounds')
   last_key=key;rows.append({'ekey':key.hex(),'encoded_bytes':size,'offset':off,'block':page})
  if not rows or any(block[q:]):raise Rejected('index_padding_or_empty_block')
  if bytes.fromhex(rows[-1]['ekey'])!=toc[page*kb:(page+1)*kb]:raise Rejected('toc_last_key')
  pages.append({'block':page,'records':len(rows),'md5_prefix':expected_md5.hex(),'verified':True});entries.extend(rows)
 if len(entries)!=n:raise Rejected('index_record_count')
 return {'index_key':expected_key,'kind':kind,'input_bytes':len(b),'input_sha256':hashlib.sha256(b).hexdigest(),'footer_key_verified':True,'footer_checksum_verified':True,'toc_checksum_verified':True,'blocks':pages,'entry_count':n,'offset_bytes':ob,'entries':entries,'runtime_approved':False}
