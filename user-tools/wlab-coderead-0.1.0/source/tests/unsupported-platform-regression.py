"""No process is opened: exercise the Linux unsupported-backend diagnostic path."""
import json,subprocess,sys,tempfile,hashlib
from pathlib import Path
exe=Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory() as td:
 out=Path(td)/'report'
 r=subprocess.run([str(exe),'--read-once','123','456',str(out)],capture_output=True,text=True)
 assert r.returncode==1,(r.returncode,r.stderr)
 p=out/'analysis.json';j=json.loads(p.read_text());assert j['status']=='read_failed' and 'require Windows' in j['error'],j
 before=hashlib.sha256(p.read_bytes()).hexdigest()
 r2=subprocess.run([str(exe),'--read-once','123','456',str(out)],capture_output=True,text=True)
 assert r2.returncode==1 and 'already used' in r2.stderr,r2.stderr
 assert hashlib.sha256(p.read_bytes()).hexdigest()==before
 assert not list(out.glob('*.bin'))
 print(json.dumps({'platform':'Linux unsupported backend; no process opened','failure_analysis_written':True,'same_output_directory_reuse_rejected':True,'prior_analysis_not_overwritten':True,'binary_export_on_failure':False}))
