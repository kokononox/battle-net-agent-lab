"""Run static analysis and a separate verifier; never starts the input PE."""
import argparse,subprocess,sys
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args();a.out_dir.mkdir(parents=True,exist_ok=True)
base=Path(__file__).resolve().parent
subprocess.run([sys.executable,str(base/'analyze_adapter.py'),'--input',str(a.input),'--out-dir',str(a.out_dir)],check=True)
subprocess.run([sys.executable,str(base/'verify_adapter.py'),'--input',str(a.input),'--reports',str(a.out_dir),'--out',str(a.out_dir/'verification.json')],check=True)
