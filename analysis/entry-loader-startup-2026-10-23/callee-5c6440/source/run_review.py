"""Run static producers and separate verifiers; subprocesses are Python tools only."""
import argparse,subprocess,sys
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args();a.out_dir.mkdir(parents=True,exist_ok=True)
base=Path(__file__).resolve().parent
for name,out in [('analyze_dispatch.py','dispatch-proof.json'),('analyze_scenario.py','scenario-proof.json')]:
 subprocess.run([sys.executable,str(base/name),'--input',str(a.input),'--out',str(a.out_dir/out)],check=True)
for name,report,out in [('verify_dispatch.py','dispatch-proof.json','dispatch-verification.json'),('verify_review.py','scenario-proof.json','verification.json')]:
 subprocess.run([sys.executable,str(base/name),'--input',str(a.input),'--report',str(a.out_dir/report),'--out',str(a.out_dir/out)],check=True)
