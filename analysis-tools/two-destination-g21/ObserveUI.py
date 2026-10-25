import ctypes as C,json,os,sys,time
from ctypes import wintypes as W
from pathlib import Path
ROOT=Path(sys.argv[1]);BASE=Path(__file__).resolve().parents[2];sys.path.insert(0,str(BASE/'scripts'))
import ui_accessibility as uia,language_step,install_step
from ui_schedule import install_due
uia._HELPER=(ROOT/'NativeUI.exe',None)
rootpid=json.loads((ROOT/'launch-state.json').read_text())['root']['pid']
U=C.WinDLL('user32',use_last_error=True);CALLBACK=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
U.EnumWindows.argtypes=[CALLBACK,W.LPARAM];U.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)];U.IsWindowVisible.argtypes=[W.HWND];U.IsWindowVisible.restype=W.BOOL
r={'language_attempted':False,'language_status':'not_attempted','language_continue_returned':False,'outcome_uncertain':False,'install_action_requested':False,'ui_probe_errors':0,'language_probes':0,'ui_markers_seen':[],'install_status':'not_attempted','install_continue_returned':False,'install_probes':0}
seen=set();finished=False;install_finished=False;last=-10;last_install=-20;start=time.monotonic()
r['ui_samples']=[];r['install_probe_seconds']=[]
try:
 while time.monotonic()-start<165:
  targets=[]
  @CALLBACK
  def collect(hwnd,_):
   pid=W.DWORD();U.GetWindowThreadProcessId(hwnd,C.byref(pid))
   if pid.value==rootpid and U.IsWindowVisible(hwnd):targets.append({'pid':rootpid,'hwnd':int(hwnd)})
   return True
  U.EnumWindows(collect,0);targets=targets[:8]
  if targets:
   sample=uia.inspect(targets)
   now=int(time.monotonic()-start)
   if len(r['ui_samples'])<32 and (not r['ui_samples'] or now-r['ui_samples'][-1]['elapsed_seconds']>=5):
    r['ui_samples'].append({'elapsed_seconds':now,'status':sample['status'],'markers':sorted({m for e in sample['elements'] for m in e['markers']}),'controls':sorted({e['control_type'] for e in sample['elements']}),'labels':sorted({e['label'] for e in sample['elements'] if e['label'] not in {'not_read','unrecognized'}}),'truncated':sample['truncated']})
   if sample['status']=='ok':
    for e in sample['elements']:seen.update(e['markers'])
   else:r['ui_probe_errors']+=1
   if not finished and r['language_probes']<6 and time.monotonic()-start-last>=5:
    last=time.monotonic()-start;r['language_probes']+=1;v=language_step.run(targets,rootpid,ROOT/'Battle.net-Setup.exe',authorized=True)
    r['language_status']=v['status'];r['language_attempted']|=v['selection_attempted'] or v['continue_attempted'];r['language_continue_returned']|=v['continue_returned'];r['outcome_uncertain']|=v['outcome_uncertain']
    finished=v['selection_attempted'] or v['continue_attempted'] or v['outcome_uncertain'] or v['status'] not in {'page_not_language','no_targets'}
   if finished and r['language_continue_returned'] and not install_finished and install_due(time.monotonic()-start,last_install,r['install_probes']):
    last_install=time.monotonic()-start;r['install_probe_seconds'].append(int(last_install));r['install_probes']+=1;v=install_step.run(targets,rootpid,ROOT/'Battle.net-Setup.exe',authorized=True)
    r['install_status']=v['status'];r['install_action_requested']|=v['continue_attempted'];r['install_continue_returned']|=v['continue_returned'];r['outcome_uncertain']|=v['outcome_uncertain']
    install_finished=v['continue_attempted'] or v['outcome_uncertain'] or v['status'] not in {'page_mismatch','no_targets'}
   if 'login' in seen or 'login_page' in seen:
    r['login_page_observed']=True;break
  time.sleep(3)
except Exception:r['ui_probe_errors']+=1
r['ui_markers_seen']=sorted(seen);(ROOT/'ui-result.json').write_text(json.dumps(r));print(json.dumps(r))
