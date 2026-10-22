"""Run the pinned, offline startup review and its independent verifier."""
import argparse, subprocess, sys
from pathlib import Path
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--input-dir',required=True,type=Path)
 p.add_argument('--out-dir',required=True,type=Path)
 a=p.parse_args();src=Path(__file__).resolve().parent
 a.out_dir.mkdir(parents=True,exist_ok=True)
 subprocess.run([sys.executable,str(src/'prove_startup.py'),'--input-dir',str(a.input_dir),'--out-dir',str(a.out_dir)],check=True)
 subprocess.run([sys.executable,str(src/'verify_startup.py'),'--input-dir',str(a.input_dir),'--report',str(a.out_dir/'startup-proof.json'),'--out',str(a.out_dir/'verification.json')],check=True)
 print('Static review and independent verification completed. No input PE was executed.')
