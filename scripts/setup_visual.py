"""Bounded visual of the exact signed no-input setup options page, not desktop."""
import base64
import json
import os
import struct
import subprocess
import ui_accessibility as uia

def blank(status='not_requested'):
    return dict(status=status,width=0,height=0,image_png_base64=None)

def validate(r):
    if type(r) is not dict or set(r)!=set(blank()) or r['status'] not in {'not_requested','refused','captured','helper_failed'}:raise ValueError('visual_schema')
    if any(type(r[k]) is not int for k in ('width','height')):raise ValueError('visual_size')
    if r['status']!='captured':
        if r!=blank(r['status']):raise ValueError('visual_empty')
        return r
    if not 100<=r['width']<=1024 or not 100<=r['height']<=768 or type(r['image_png_base64']) is not str or len(r['image_png_base64'])>87384:raise ValueError('visual_limit')
    try:data=base64.b64decode(r['image_png_base64'],validate=True)
    except ValueError:raise ValueError('visual_encoding') from None
    if not 24<=len(data)<=65536 or data[:8]!=b'\x89PNG\r\n\x1a\n' or data[12:16]!=b'IHDR':raise ValueError('visual_png')
    if struct.unpack('>II',data[16:24])!=(r['width'],r['height']):raise ValueError('visual_dimensions')
    return r

def capture(targets):
    if len(targets)!=1:return blank('refused')
    from observe_agent import clean_environment
    env=clean_environment(os.environ);target=targets[0]
    env['BNET_LAB_VISUAL_CONFIG']=json.dumps(target)
    try:
        if uia._HELPER is None:uia._HELPER=uia.native_helper(env)
        response=subprocess.run([str(uia._HELPER[0]),'setup-visual'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,check=False)
        if response.returncode or len(response.stdout)>95000:return blank('helper_failed')
        def unique(pairs):
            result={}
            for k,v in pairs:
                if k in result:raise ValueError('duplicate')
                result[k]=v
            return result
        return validate(json.loads(response.stdout.decode('utf-8-sig'),object_pairs_hook=unique))
    except (ValueError,TypeError,KeyError,OSError,subprocess.TimeoutExpired):return blank('helper_failed')
