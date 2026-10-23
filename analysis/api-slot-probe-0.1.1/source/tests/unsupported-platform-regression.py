"""Linux diagnostic and no-retry check. No target process is opened."""
import json,subprocess,sys,tempfile,hashlib
from pathlib import Path
exe=Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory() as td:
 out=Path(td)/'report';out.mkdir()
 (out/'trust.json').write_text(json.dumps({'source':'PowerShell Get-AuthenticodeSignature + Get-FileHash','entries':[]}))
 r=subprocess.run([str(exe),'--read-once','123','456',str(out)],capture_output=True,text=True)
 assert r.returncode==1,(r.returncode,r.stderr)
 p=out/'analysis.json';j=json.loads(p.read_text())
 assert j['status']=='read_stopped' and 'Windows AMD64 required' in j['error'],j
 assert j['read_calls']==0 and j['memory_bytes_requested']==0
 before=hashlib.sha256(p.read_bytes()).hexdigest()
 r2=subprocess.run([str(exe),'--read-once','123','456',str(out)],capture_output=True,text=True)
 assert r2.returncode==1 and 'no retry' in r2.stderr,r2.stderr
 assert hashlib.sha256(p.read_bytes()).hexdigest()==before
 assert not list(out.glob('*.bin'))
 print(json.dumps({'platform':'Linux unsupported backend; no process opened','failure_analysis_written':True,'same_output_directory_reuse_rejected':True,'prior_analysis_not_overwritten':True,'memory_reads':0,'windows_runtime_tested':False}))
