# WLab BIOS Path: add review bookmarks only; never patch bytes.
# @category WLab
import json
from java.io import File
f=askFile('Select WLab evidence.json','Open')
with open(f.getAbsolutePath(),'r') as stream: report=json.load(stream)
expected=report['input']['sha256'].lower()
actual=currentProgram.getExecutableSHA256()
if not actual or actual.lower()!=expected:
 raise RuntimeError('SHA-256 mismatch. Open the exact unmodified input image first.')
manager=currentProgram.getBookmarkManager();base=currentProgram.getImageBase();added=0;skipped=0
for hit in report['code_candidates']:
 addr=base.add(long(hit['site_rva']));expected_bytes=hit['bytes']
 try:
  raw=getBytes(addr,len(expected_bytes)//2)
  observed=''.join('%02x'%(int(x)&255) for x in raw)
  if observed!=expected_bytes:skipped+=1;continue
  note='CANDIDATE ONLY | '+hit['cfg_status']+' | '+'; '.join(hit['target_labels'])+' | No hardware read/population/send proof.'
  manager.setBookmark(addr,'Analysis','WLab BIOS Path',note);added+=1
 except Exception:skipped+=1
print('WLab: %d candidate bookmarks; %d skipped. No bytes patched.'%(added,skipped))
