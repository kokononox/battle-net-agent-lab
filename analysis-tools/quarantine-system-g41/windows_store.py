"""Windows private-store adapter. Private records travel only over stdin/stdout.
Helper executable, root and controller are trusted; never client-configurable.
"""
import json,os,re,subprocess
from pathlib import Path
from quarantine import Rejected,MAX_RECORD_BYTES
class WindowsStore:
 def __init__(self,root,helper):
  if os.name!='nt':raise Rejected('quarantine_unavailable')
  self._root=str(Path(root).absolute());self._helper=str(Path(helper).absolute())
  self._call('init')
 def _call(self,action,capture_id=None,record=None):
  args=[self._helper,action,self._root]
  if capture_id is not None:
   if type(capture_id) is not str or re.fullmatch('[0-9a-f]{32}',capture_id) is None:raise Rejected('capture_id_rejected')
   args.append(capture_id)
  data=b'' if record is None else json.dumps(record,ensure_ascii=True,separators=(',',':')).encode('ascii')
  if len(data)>MAX_RECORD_BYTES:raise Rejected('private_store_quota')
  env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','SYSTEMDRIVE','ALLUSERSPROFILE','PROGRAMDATA','TEMP','TMP'}}
  try:
   r=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,env=env,check=False)
   if len(r.stdout)>MAX_RECORD_BYTES+65536:raise ValueError()
   value=json.loads(r.stdout.decode('utf-8-sig'))
   if r.returncode or type(value) is not dict or value.get('ok') is not True:raise ValueError()
   return value
  except (OSError,ValueError,subprocess.SubprocessError):raise Rejected('quarantine_unavailable') from None
 def write(self,record):
  value=self._call('write',record=record);ident=value.get('capture_id')
  if type(ident) is not str or re.fullmatch('[0-9a-f]{32}',ident) is None:raise Rejected('quarantine_unavailable')
  return ident
 def read_for_local_review(self,ident):return self._call('read',capture_id=ident)['record']
