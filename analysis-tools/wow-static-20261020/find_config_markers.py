"""Find exact config-related byte markers and absolute pointer refs; never execute input.
Usage: python find_config_markers.py Wow.exe output.json
Requires pefile. Markers do not prove live CVars or an opt-out effect.
"""
import sys,re,json,hashlib,struct
from pathlib import Path
import pefile
b=Path(sys.argv[1]).read_bytes();pe=pefile.PE(data=b,fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase
names=['engineSurvey','engineSurveyPatch','Engine Survey Patch','Engine Survey Index','telemetryWowPackage','telemetryWowlabsPackage','shop2ClientErrorTelemetryAllowed','shop2TelemetryAllowed','optOutIngameSurveys','Whether we are opted out of receiving surveys.']
rows=[]
for name in names:
 hits=[]
 for m in re.finditer(re.escape(name.encode()+b'\0'),b):
  if m.start()>0 and b[m.start()-1]!=0:continue
  rva=pe.get_rva_from_offset(m.start());n=sum(1 for _ in re.finditer(re.escape(struct.pack('<Q',base+rva)),b))
  hits.append({'file_offset':hex(m.start()),'rva':hex(rva),'absolute_va_pointer_byte_matches':n})
 rows.append({'marker':name,'hits':hits})
out={'schema':'wow-config-marker-inventory-1','sha256':hashlib.sha256(b).hexdigest(),'markers':rows,'live_cvar_registration_proven':False,'actual_defaults_or_effect_proven':False,'notes':['Exact case-sensitive marker scan only','No RIP or indirect/dynamic reference coverage','Zero pointer matches does not prove marker unused','No game/config mutation or runtime execution']}
Path(sys.argv[2]).write_text(json.dumps(out,indent=2)+'\n')
print('markers',len(rows),'hits',sum(len(x['hits']) for x in rows))
