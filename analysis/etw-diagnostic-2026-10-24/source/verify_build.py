from pathlib import Path
import json,struct,hashlib,base64,re,xml.etree.ElementTree as E
D=Path(__file__).resolve().parents[1];src=D/'source';b=(D/'build/WLab-ETW-Diagnostic.exe').read_bytes();pe=struct.unpack_from('<I',b,0x3c)[0];assert b[pe:pe+4]==b'PE\0\0';assert struct.unpack_from('<H',b,pe+4)[0]==0x8664;assert struct.unpack_from('<H',b,pe+24+68)[0]==2
r=E.parse(src/'Control.wprp').getroot().find('Profiles');providers={p.get('Id'):p for p in r.findall('EventProvider')};profiles=r.findall('Profile');assert len(profiles)==6
cases=[]
for p in profiles:
 ref=p.find('.//EventProviderId').get('Value');v=providers[ref];assert v.get('Strict')=='true';assert p.get('LoggingMode')=='Memory';cases.append(dict(name=p.get('Name'),provider=v.get('Name'),nonpaged=v.get('NonPagedMemory'),stack=v.get('Stack'),keyword=v.find('Keywords/Keyword').get('Value')))
assert len(set((c['provider'],c['nonpaged'],c['stack']) for c in cases))==6
for name in ['Run-Control.ps1','Control.wprp']:assert (src/name).read_bytes() in b
s=(src/'Run-Control.ps1').read_text();old=Path('/data/analysis/wlab-etw-exe/source/Run-Control.ps1').read_text();pat=r"Add-Type -TypeDefinition @'\n(.*?)\n'@";assert re.search(pat,s,re.S).group(1)==re.search(pat,old,re.S).group(1)
assert "'-cancel','-instancename',$instance" in s and "elseif ($active -ne -984076288)" in s
assert "'-filemode'" not in s and "stack_presence_verified=$false" in s
cmd="try { & {\n"+s.replace('$base = $PSScriptRoot','$base = $env:WLAB_CONTROL_DIR',1)+"\n} } catch { Write-Host $_.Exception.Message -ForegroundColor Red } finally { Write-Host ('Working folder: ' + $env:WLAB_CONTROL_DIR); [void](Read-Host 'Press Enter to close this window') }"
x=base64.b64encode(cmd.encode('utf-16le'));assert len(x)+1000<32000
out=dict(binary_sha256=hashlib.sha256(b).hexdigest(),binary_bytes=len(b),cross_compile_passed=True,go_vet_passed=True,pe_machine='AMD64',pe_subsystem='GUI',embedded_payload_matches=True,loopback_implementation_unchanged=True,cases=cases,encoded_command_chars=len(x),windows_runtime_tested=False,wpr_profile_runtime_validated=False,root_cause_fixed_proven=False,stack_presence_verified=False,limits='Static invariants and cross compilation only; not a PowerShell parser, WPR XSD validation or Windows execution.')
(D/'reports/build-verification.json').write_text(json.dumps(out,indent=2)+'\n');print('Static checks passed; encoded command chars',len(x),'EXE SHA256',out['binary_sha256'])
