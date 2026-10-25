"""Read-only signature observation; same native WinVerifyTrust/publisher protocol.
Never used to authorize the bootstrapper or UI actions (their original gates remain).
"""
import json,subprocess,sys
STATUSES={'accepted','trust_rejected','publisher_rejected','helper_failed','helper_timeout','output_limit','output_rejected','file_busy','file_changed','waiting_stability','invalid_size','native_error'}

def result(status,exit_code=None,trust_status=None):return dict(status=status,exit_code=exit_code,trust_status=trust_status)
def decode_response(code,raw):
 if type(code) is not int or not -2**31<=code<2**32:return result('output_rejected')
 code=code if code<2**31 else code-2**32
 if code:return result('helper_failed',code)
 if len(raw)>4096:return result('output_limit',0)
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate')
   d[k]=v
  return d
 try:
  r=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique)
  if type(r) is not dict or set(r)!={'trust_status','expected_blizzard_publisher'}:raise ValueError('schema')
  status=r['trust_status'];publisher=r['expected_blizzard_publisher']
  if type(status) is not int or not -2**31<=status<2**31 or type(publisher) is not bool or (status!=0 and publisher):raise ValueError('values')
  return result('accepted' if status==0 and publisher else 'publisher_rejected' if status==0 else 'trust_rejected',0,status)
 except (ValueError,TypeError,UnicodeError):return result('output_rejected',0)

def probe(path,env):
 if sys.platform!='win32':return result('native_error')
 import ui_accessibility as uia
 if uia._HELPER is None:return result('native_error')
 child=dict(env,BNET_LAB_VERIFY_PATH=str(path.resolve()))
 try:
  r=subprocess.run([str(uia._HELPER[0]),'signature'],env=child,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60,check=False)
  return decode_response(r.returncode,r.stdout)
 except subprocess.TimeoutExpired:return result('helper_timeout')
 except OSError:return result('native_error')
