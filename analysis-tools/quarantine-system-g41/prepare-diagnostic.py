"""Actual Gate Prepare, stripped environment; no Apply/import calls."""
import base64,json,os,subprocess,sys,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from coordinator import clean_env
from common import ROOT,save
from windows_store import WindowsStore
results=[]
for label,extra in [('stripped',{}),('stripped_with_pathext',{'PATHEXT':'.COM;.EXE;.BAT;.CMD'})]:
 root=Path(os.environ['ProgramData'])/'BNetOnlineG41'/uuid.uuid4().hex
 WindowsStore(root/'quarantine',os.environ['G41_STORE_HELPER'])
 save(root/'config.json',{'root':str(root),'job_name':'Global\\BNetOnlineG41_'+root.name})
 ps=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
 env=clean_env();env.update(extra)
 p=subprocess.run([ps,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(ROOT/'Gate.ps1'),'-Action','Prepare','-Config',str(root/'config.json')],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=100)
 try:reply=json.loads(p.stdout.decode('utf-8-sig'))
 except Exception:reply={'error_code':'reply_invalid'}
 backup=root/'before.wfw'
 results.append({'environment':label,'exit_code':p.returncode,'reply':reply,'backup_exists':backup.exists(),'backup_length':backup.stat().st_size if backup.exists() else 0,'state_exists':(root/'gate-state.json').exists(),'stderr_nonempty':bool(p.stderr)})
r={'source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'results':results,'firewall_mutation_attempted':False}
print('G41_PREPARE_DIAGNOSTIC_B64='+base64.b64encode(json.dumps(r).encode()).decode())
