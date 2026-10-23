"""Run static producers and verifiers; no game process or input PE execution."""
import argparse,subprocess,sys
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('--input',required=True,type=Path);ap.add_argument('--out-dir',required=True,type=Path);a=ap.parse_args();a.out_dir.mkdir(parents=True,exist_ok=True);base=Path(__file__).resolve().parent
subprocess.run([sys.executable,str(base/'analyze_record.py'),'--input',str(a.input),'--out',str(a.out_dir/'provenance-proof.json')],check=True)
subprocess.run([sys.executable,str(base/'verify_record.py'),'--input',str(a.input),'--report',str(a.out_dir/'provenance-proof.json'),'--out',str(a.out_dir/'verification.json')],check=True)
