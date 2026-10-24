"""Explicit status / journal recovery. No apply or self-test command exposed."""
from pathlib import Path
import sys
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'lab')]
from desktop_ops import native_result

def run():
 print('Unified Firewall Desktop — protected journal recovery')
 print('Run this window explicitly as Administrator. No automatic changes.')
 print('STATUS reads current state. RESTORE removes only exact unchanged journal-owned rules.')
 action=input('Type STATUS, RESTORE, or EXIT: ').strip()
 if action=='EXIT':return
 if action=='STATUS':result=native_result('status')
 elif action=='RESTORE':
  if input('Confirm by typing RESTORE: ')!='RESTORE':raise RuntimeError('Cancelled; no restore requested.')
  result=native_result('restore')
 else:raise RuntimeError('Unknown command; no operation requested.')
 import json
 print(json.dumps(result,ensure_ascii=False,indent=2))
 if not result['native_ok']:raise RuntimeError('Operation failed; inspect result and journal. Do not retry Apply.')
if __name__=='__main__':
 try:run()
 except Exception as e:print('ERROR:',e)
 input('Press Enter to close. Journal and reports are retained. ')
