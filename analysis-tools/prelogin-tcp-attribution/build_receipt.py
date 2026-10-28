"""Compiler diagnostics limited to fixed unit labels, numeric lines and error codes."""
import json,re,sys
from pathlib import Path

def validate(r):
 if type(r)is not dict or set(r)!={'schema','source_commit','run_id','units'}or r['schema']!='bnet-tcp-build-1':raise ValueError('schema')
 if type(r['source_commit'])is not str or not re.fullmatch('[0-9a-f]{40}',r['source_commit'])or type(r['run_id'])is not str or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 if type(r['units'])is not list or len(r['units'])>2 or len({v['unit']for v in r['units']})!=len(r['units']):raise ValueError('units')
 for u in r['units']:
  if set(u)!={'unit','compiled','exit_code','compiler_error_codes','source_error_lines'}or u['unit']not in {'tcp_fixture','tcp_meter'}or type(u['compiled'])is not bool or type(u['exit_code'])is not int:raise ValueError('unit')
  if type(u['compiler_error_codes'])is not list or len(u['compiler_error_codes'])>16 or any(type(c)is not str or not re.fullmatch(r'(?:C[0-9]{4}|D[0-9]{4}|LNK[0-9]{4})',c)for c in u['compiler_error_codes']):raise ValueError('code')
  if type(u['source_error_lines'])is not list or len(u['source_error_lines'])>16 or any(type(n)is not int or not 1<=n<=9999 for n in u['source_error_lines']):raise ValueError('lines')
  if u['compiled']and(u['exit_code']!=0 or u['compiler_error_codes']or u['source_error_lines']):raise ValueError('success')
 return r
if __name__=='__main__':
 r=validate(json.loads(Path(sys.argv[1]).read_text()))
 if len(sys.argv)>3 and(r['source_commit']!=sys.argv[3]or r['run_id']!=sys.argv[4]):raise ValueError('identity')
 p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
