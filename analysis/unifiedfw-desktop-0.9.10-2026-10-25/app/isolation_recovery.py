"""GUI-independent status / explicitly consented scoped isolation recovery."""
from pathlib import Path
import json,os,sys,uuid
sys.path.insert(0,str(Path(__file__).resolve().parent))
from isolation_ops import native
from state import assert_local_tree

def run():
 if os.name!='nt':raise RuntimeError('Windows required')
 import ctypes
 choice=ctypes.windll.user32.MessageBoxW(None,'Yes: Isolation status (read-only).\nNo: Choose scoped isolation Restore.\nCancel: Exit.','Isolation recovery',3|48|512)
 if choice==2:return
 action='Status';payload={}
 if choice==7:
  if ctypes.windll.user32.MessageBoxW(None,'Remove isolation protection and restore only exact recorded original fields? Changed/foreign rules are not force overwritten. Keep protected journal.','Restore isolation',4|48|256)!=6:return
  action='Restore';payload={'confirmation':'RESTORE ISOLATION'}
 job=assert_local_tree(Path(__file__).resolve().parents[1]/'private-state/jobs'/uuid.uuid4().hex);job.mkdir(parents=True)
 result=native(action,payload,job);print(json.dumps(result,ensure_ascii=False,indent=2));print('Report:',job)
if __name__=='__main__':
 try:run()
 except Exception as e:print('ERROR:',e)
 input('Press Enter to close. Persistent journal is retained. ')
