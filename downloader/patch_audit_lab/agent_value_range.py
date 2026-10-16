"""Pure Agent range validator parity; no complete object-readpath claim."""
import struct,subprocess
import patch_audit as a
import source_binding as b
MASK=(1<<64)-1

def inputs(start,length,base,extent):
 a.require(all(type(x)is int and 0<=x<=MASK for x in (start,length,base,extent)),'value_u64_bounds')

def model(start,length,base,extent):
 inputs(start,length,base,extent)
 if start>extent:return {'valid':False,'length':0}
 output=extent-start if length==MASK else length
 return {'valid':((start+output)&MASK)<=extent,'length':output}

def strict_policy(start,length,base,extent):
 """Our nonwrapping bounds are stricter than the isolated Agent primitive."""
 inputs(start,length,base,extent)
 if start>extent:return False
 size=extent-start if length==MASK else length
 return start+size<=extent and base+start+size<=MASK

def native(oracle,start,length,base,extent):
 inputs(start,length,base,extent);p=subprocess.run([str(b.safe(oracle,True))],input=struct.pack('<4Q',start,length,base,extent),capture_output=True,timeout=5)
 a.require(p.returncode==0 and len(p.stdout)==12 and not p.stderr,'value_native_execution');valid,length=struct.unpack('<IQ',p.stdout);a.require(valid in (0,1),'value_native_bool');return {'valid':bool(valid),'length':length}

def compare(oracle,*values):
 expected=model(*values);observed=native(oracle,*values);a.require(expected==observed,'value_native_model_parity');return observed
