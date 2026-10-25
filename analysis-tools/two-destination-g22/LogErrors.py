"""Bounded enum/code extraction from installer logs, never raw lines or URLs."""
import hashlib,json,os,re,sys
from pathlib import Path
CODES={'0x80072f8f':'winhttp_secure_failure','0x80072f0d':'certificate_invalid_ca','0x80072f19':'certificate_revocation_check_failed','0x800b0109':'certificate_untrusted_root','0x800b010a':'certificate_chain_incomplete','0x800b0101':'certificate_expired_or_not_yet_valid','0x80092013':'revocation_server_offline','0x80090325':'security_untrusted_root','0x80090322':'security_wrong_principal','0x80090326':'security_illegal_message','0x80072ee2':'network_timeout','0x80072ee7':'name_not_resolved','0x80072efd':'cannot_connect','12175':'winhttp_secure_failure','12045':'certificate_invalid_ca','12057':'certificate_revocation_check_failed','12037':'certificate_date_invalid','12038':'certificate_name_invalid','12157':'secure_channel_error','12029':'cannot_connect','12002':'network_timeout','12007':'name_not_resolved'}
WORDS={'certificate':r'\bcert(?:ificate)?\b','tls':r'\btls\b','ssl':r'\bssl\b','error':r'\berror\b','failed':r'\bfailed\b','download':r'\bdownload(?:ing)?\b','timeout':r'\btime(?:d[ -]?out|out)\b','connection':r'\bconnect(?:ion|ing|ed)?\b','version':r'\bversion\b','proxy':r'\bproxy\b'}
def extract_codes(data):
 text=data.decode('utf-16' if data.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig',errors='replace')
 codes=set(re.findall(r'\bBLZ[A-Z0-9]{6,40}\b',text));codes.update(x.lower() for x in re.findall(r'(?i)\b0x[89][a-f0-9]{7}\b',text))
 for m in re.finditer(r'(?i)\b(?:error|winhttp|status|hresult|last_error)\s*[:=]?\s*([0-9]{5})\b',text):
  if m[1] in CODES:codes.add(m[1])
 ordered=sorted(codes)
 return {'codes':[{'code':c,'category':CODES.get(c,'blizzard_error_code' if c.startswith('BLZ') else 'unmapped_hresult')} for c in ordered[:32]],'codes_truncated':len(ordered)>32,'keyword_counts':{k:len(re.findall(pattern,text,re.I)) for k,pattern in WORDS.items()},'recognized_host_mentions':{h:text.lower().count(h) for h in ('level3.blizzard.com','us.version.battle.net')}}
def main():
 root=Path(sys.argv[1]);bases=[(root/'stage-temp','staged_temp'),(Path(os.environ['ProgramData'])/'Battle.net','programdata_battle_net'),(Path(os.environ['ProgramData'])/'Blizzard Entertainment','programdata_blizzard'),(Path(os.environ['LOCALAPPDATA'])/'Battle.net','localappdata_battle_net')]
 out=[];total=0;visited=0;limited=False
 for base,kind in bases:
  if not base.exists():continue
  for directory,folders,files in os.walk(base,followlinks=False):
   if len(Path(directory).relative_to(base).parts)>8:folders[:]=[];limited=True;continue
   folders[:]=[n for n in folders if not (Path(directory)/n).is_symlink() and not getattr((Path(directory)/n).lstat(),'st_file_attributes',0)&0x400]
   for name in files:
    visited+=1
    if visited>4096 or len(out)>=32:limited=True;break
    p=Path(directory)/name
    if p.suffix.lower() not in {'.log','.txt'}:continue
    try:
     st=p.lstat()
     if p.is_symlink() or getattr(st,'st_file_attributes',0)&0x400:continue
     if st.st_size>1048576 or total+st.st_size>8388608:limited=True;continue
     data=p.read_bytes();total+=len(data);row=extract_codes(data);row.update(root_category=kind,relative_path_sha256=hashlib.sha256(str(p.relative_to(base)).encode()).hexdigest(),bytes_read=len(data));out.append(row)
    except OSError:continue
   if limited and (visited>4096 or len(out)>=32):break
 (root/'installer-error-codes.json').write_text(json.dumps({'schema':'installer_error_codes_v1','scope':'matched_log_codes_not_causal_verdict','files':out,'bytes_read':total,'limited':limited}))
if __name__=='__main__':main()
