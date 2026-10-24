from pathlib import Path
import argparse,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import admit,atomic
from https_common import probe_https

def main():
 p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--output',required=True);a=p.parse_args()
 q,out=admit(a.request,a.output)
 if q['challenge']['role'] not in ('A','B'):raise ValueError('python_child_role')
 row=probe_https(q['url'],q['address'],q['challenge']);row['client_version']=sys.version;atomic(out,row)
if __name__=='__main__':main()
