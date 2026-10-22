"""Run a pinned offline helper review, then its independent verifier."""
import argparse,subprocess,sys
from pathlib import Path
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',required=True,type=Path);p.add_argument('--out-dir',required=True,type=Path);a=p.parse_args();src=Path(__file__).resolve().parent;a.out_dir.mkdir(parents=True,exist_ok=True)
 subprocess.run([sys.executable,str(src/'analyze_helper.py'),'--input',str(a.input),'--out-dir',str(a.out_dir)],check=True)
 subprocess.run([sys.executable,str(src/'verify_helper.py'),'--input',str(a.input),'--report',str(a.out_dir/'helper-proof.json'),'--out',str(a.out_dir/'verification.json')],check=True)
 print('Offline review completed; no input PE execution or binary modification.')
