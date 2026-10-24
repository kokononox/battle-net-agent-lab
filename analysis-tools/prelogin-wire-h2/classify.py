"""Decode StartAgent only with its actual process image; never export field values."""
import sys
import hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'prelogin-audit'))
from decode_startup import extract_startup,parts,wire,one_bytes,field_presence

class Classifier:
    def __init__(self,images,cpu):self.images=images;self.cpu=cpu;self.cache={}
    def __call__(self,request,sha):
        out={'hardware_payload_verified':False,'hardware_field_count':0,'cpu_reference_match':False}
        image=self.images.get(sha)
        if image is None or hashlib.sha256(image).hexdigest()!=sha:return out
        try:
            if sha not in self.cache:self.cache[sha]=extract_startup(image)[1]
            cls=self.cache[sha]
            for chunk in parts(request['body'],request['content_type']):
                envelope=wire(chunk)
                if one_bytes(envelope,2)!=b'Blizzard.Telemetry.Distribution.Agent' or one_bytes(envelope,3)!=b'StartAgent':continue
                payload=one_bytes(envelope,4);msg=cls();msg.ParseFromString(payload)
                before=msg.SerializeToString();msg.DiscardUnknownFields()
                if msg.SerializeToString()!=before:continue
                fields=field_presence(msg);hw=[x for x in fields if x['path'].startswith('hardware.')]
                out['hardware_payload_verified']=len(hw)>0
                out['hardware_field_count']=len(hw)
                if self.cpu and msg.HasField('hardware') and msg.hardware.HasField('cpu_brand'):
                    out['cpu_reference_match']=msg.hardware.cpu_brand.strip()==self.cpu.strip()
        except Exception:pass
        return out
