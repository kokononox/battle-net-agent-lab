"""Explicitly authorized values from fresh lab VM; never user-PC or account data."""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import sys

def reference():
 import winreg
 cpu=None
 try:
  with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:cpu=winreg.QueryValueEx(key,'ProcessorNameString')[0].strip()[:160]
 except OSError:pass
 class Mem(ctypes.Structure):
  _fields_=[('length',ctypes.c_uint32),('load',ctypes.c_uint32),*[(n,ctypes.c_uint64) for n in ('total_physical','available_physical','total_page','available_page','total_virtual','available_virtual','extended')]]
 m=Mem();m.length=ctypes.sizeof(m);api=ctypes.WinDLL('kernel32').GlobalMemoryStatusEx;api.argtypes=[ctypes.POINTER(Mem)];api.restype=ctypes.c_int
 physical=int(m.total_physical) if api(ctypes.byref(m)) else None
 return {'cpu_model':cpu,'windows_build':sys.getwindowsversion().build,'total_physical_memory_bytes':physical,'logical_processors':int(os.environ.get('NUMBER_OF_PROCESSORS','0'))}

def validate(r):
 if type(r) is not dict or set(r)!=set('schema source_commit run_id scope reference samples limits'.split()):raise ValueError('schema')
 if r['schema']!='bnet-api-input-samples-1' or r['scope']!='test_vm_no_account_user_authorized_buffer_values':raise ValueError('scope')
 if not re.fullmatch('[a-f0-9]{40}',r['source_commit']) or not re.fullmatch('[0-9]{1,30}',r['run_id']):raise ValueError('identity')
 ref=r['reference']
 if type(ref) is not dict or set(ref)!=set('cpu_model windows_build total_physical_memory_bytes logical_processors'.split()):raise ValueError('reference')
 if ref['cpu_model'] is not None and (type(ref['cpu_model']) is not str or len(ref['cpu_model'])>160 or not all(32<=ord(x)<=126 for x in ref['cpu_model'])):raise ValueError('cpu_model')
 for k in ('windows_build','total_physical_memory_bytes','logical_processors'):
  if ref[k] is not None and (type(ref[k]) is not int or not 0<=ref[k]<=2**50):raise ValueError('numeric_reference')
 if type(r['samples']) is not list or len(r['samples'])>64:raise ValueError('samples')
 total=0
 for s in r['samples']:
  if type(s) is not dict or set(s)!=set('pid process_sha256 api context sequence declared_length sample_truncated headers_redacted sample_sha256 base64'.split()):raise ValueError('sample_schema')
  if s['api'] not in ('WinHttpSendRequest','WinHttpWriteData','HttpSendRequestA','HttpSendRequestW','InternetWriteFile','EncryptMessage','SSL_write','SSL_write_ex'):raise ValueError('api')
  if type(s['pid']) is not int or not 0<s['pid']<2**32 or not re.fullmatch('[a-f0-9]{64}',s['process_sha256']):raise ValueError('process')
  if s['context'] is not None and not re.fullmatch('ctx[0-9]{1,3}',s['context']):raise ValueError('context')
  for k in ('sequence','declared_length'):
   if type(s[k]) is not int or not 0<=s[k]<=67108864:raise ValueError('numeric_sample')
  for k in ('sample_truncated','headers_redacted'):
   if type(s[k]) is not bool:raise ValueError('flags')
  b=base64.b64decode(s['base64'],validate=True);total+=len(b)
  if len(b)>16384 or total>262144 or hashlib.sha256(b).hexdigest()!=s['sample_sha256']:raise ValueError('sample_size_or_hash')
 limits={'sample_bytes_limit':262144,'per_buffer_limit':16384,'server_receipt_proven':False,'user_pc_observed':False,'auth_cookie_headers_redacted':True}
 if r['limits']!=limits:raise ValueError('limits')
 return r
if __name__=='__main__':
 src,dst=map(Path,sys.argv[1:])
 if src.stat().st_size>1024*1024:raise SystemExit('report_size')
 r=validate(json.loads(src.read_text(encoding='utf-8')));dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
