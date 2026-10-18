"""Pure bounded CDN .index reader; never a local .idx reader or downloader.
Qualified profile: 4KiB pages, EKey16, size4, hash8, footer28, offset0/4.
References: wowdev TACT CDN File Organization; CascLib CascStructs.h.
"""
from dataclasses import dataclass
import hashlib
from release_core import need,ck

def md5(b):return hashlib.md5(b).digest()
@dataclass(frozen=True)
class CdnEntry:
 ekey:str
 encoded_size:int
 offset:object
@dataclass(frozen=True)
class CdnIndex:
 index_key:str
 route_kind:str
 entries:tuple
 sha256:str
 page_count:int
 def lookup(self,ekey,encoded_size=None):
  ck(ekey)
  if encoded_size is not None:need(type(encoded_size)is int and encoded_size>0,'lookup_size_type')
  matches=tuple(x for x in self.entries if x.ekey==ekey)
  if encoded_size is not None:need(all(x.encoded_size==encoded_size for x in matches),'metadata_size_conflict_route_not_usable')
  return matches
 def summary(self):
  return {'format':'verified-cdn-index-1','index_key':self.index_key,'sha256':self.sha256,'route_kind':self.route_kind,'records':len(self.entries),'pages':self.page_count,'footer_name_md5_verified':True,'footer_checksum_verified':True,'toc_checksum_verified':True,'all_page_checksums_verified':True,'last_key_toc_verified':True,'sorted_entries_verified':True,'padding_and_element_count_verified':True,'publisher_signature_verified':False,'game_content_verified':False,'installation_ready':False,'apply_authorized':False}
def parse_cdn_index(raw,index_key,expected_size=None):
 ck(index_key);need(type(raw)is bytes and 28<len(raw)<=4*1024**2,'cdn_index_input_bounds')
 if expected_size is not None:need(type(expected_size)is int and len(raw)==expected_size,'cdn_index_pinned_size')
 f=raw[-28:];v,z0,z1,kib,off,size,key,h=f[8:16]
 need((v,z0,z1,kib,size,key,h)==(1,0,0,4,4,16,8) and off in (0,4),'unsupported_cdn_index_profile')
 need(md5(f).hex()==index_key,'cdn_index_footer_name_identity');need(md5(f[8:20]+bytes(8))[:8]==f[20:28],'cdn_index_footer_checksum')
 count=int.from_bytes(f[16:20],'little');need(0<count<=220000,'cdn_index_declared_count');unit=4120;need((len(raw)-28)%unit==0,'cdn_index_exact_geometry');pages=(len(raw)-28)//unit;need(0<pages<=1024,'cdn_index_page_budget');toc=raw[pages*4096:-28];need(md5(toc)[:8]==f[:8],'cdn_index_toc_checksum');entries=[];last=None;rowlen=20+off
 for page in range(pages):
  b=raw[page*4096:(page+1)*4096];need(md5(b)[:8]==toc[pages*16+page*8:pages*16+(page+1)*8],'cdn_index_page_checksum');pagekeys=[];pos=0
  while pos+rowlen<=4096:
   row=b[pos:pos+rowlen]
   if row[:16]==bytes(16):break
   e=row[:16];n=int.from_bytes(row[16:20],'big');o=int.from_bytes(row[20:],'big')if off else None
   need(n>0 and (last is None or last<=e),'cdn_index_entry_size_or_order');last=e;pagekeys.append(e);entries.append(CdnEntry(e.hex(),n,o));pos+=rowlen
  need(pagekeys and not any(b[pos:]),'cdn_index_nonzero_padding_or_empty_page');need(pagekeys[-1]==toc[page*16:(page+1)*16],'cdn_index_toc_last_key')
 need(len(entries)==count,'cdn_index_element_count')
 return CdnIndex(index_key,'loose'if off==0 else 'archive',tuple(entries),hashlib.sha256(raw).hexdigest(),pages)
