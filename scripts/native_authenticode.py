"""Fail-closed Windows Authenticode policy + verified leaf publisher, without PowerShell."""
import json
from pathlib import Path
import subprocess
import ui_accessibility as uia

class NativeSignatureError(ValueError):
    pass

def read_native(path,env):
    clean_env=__import__('observe_agent').clean_environment(env)
    if uia._HELPER is None:uia._HELPER=uia.native_helper(clean_env)
    child_env=dict(clean_env,BNET_LAB_VERIFY_PATH=str(Path(path).resolve()))
    response=subprocess.run([str(uia._HELPER[0]),'signature'],env=child_env,
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60,check=False)
    if response.returncode or len(response.stdout)>4096:raise NativeSignatureError('native_signature_helper_failed')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('duplicate_key')
            result[k]=v
        return result
    def constant(_):raise ValueError('nonfinite')
    try:return json.loads(response.stdout.decode('utf-8-sig'),object_pairs_hook=unique,parse_constant=constant)
    except (ValueError,UnicodeError):raise NativeSignatureError('native_signature_output_rejected') from None

def verify(path,env):
    r=read_native(path,env)
    if type(r) is not dict or set(r)!={'trust_status','expected_blizzard_publisher'}:raise NativeSignatureError('native_signature_output_rejected')
    status=r['trust_status'];publisher=r['expected_blizzard_publisher']
    if type(status) is not int or not -2**31<=status<2**31 or type(publisher) is not bool:raise NativeSignatureError('native_signature_output_rejected')
    if status!=0 and publisher:raise NativeSignatureError('native_signature_output_rejected')
    return {'authenticode_valid':status==0,'expected_blizzard_publisher':publisher,
        'accepted_for_execution':status==0 and publisher,'winverifytrust_status':status}
