"""Explicit status / journal recovery. No apply or self-test command exposed."""
from pathlib import Path
import sys
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'lab')]
from desktop_ops import native_result

def run():
 print('Unified Firewall Desktop — protected journal recovery')
 print('Run this window explicitly as Administrator. No automatic changes.')
 print('STATUS reads current state. RESTORE removes only exact unchanged journal-owned rules.')
 import ctypes,os
 if os.name!='nt':raise RuntimeError('Recovery requires Windows.')
 choice=ctypes.windll.user32.MessageBoxW(None,'Yes: Read status (no changes).\nNo: Choose rule recovery.\nCancel: Exit.','Protected firewall recovery',3|48|512)
 if choice==2:return
 if choice==6:result=native_result('status')
 elif choice==7:
  if ctypes.windll.user32.MessageBoxW(None,'Restore only unchanged journal-owned rules? Foreign rules and changed rules are not force-deleted.','Confirm firewall recovery',4|48|256)!=6:return
  result=native_result('restore')
 else:return
 import json
 print(json.dumps(result,ensure_ascii=False,indent=2))
 if not result['native_ok']:raise RuntimeError('Operation failed; inspect result and journal. Do not retry Apply.')
if __name__=='__main__':
 try:run()
 except Exception as e:print('ERROR:',e)
 input('Press Enter to close. Journal and reports are retained. ')
