"""Static package checks only; does not parse PowerShell/C# or run Windows WPR."""
from pathlib import Path
import json,hashlib,xml.etree.ElementTree as ET
D=Path(__file__).resolve().parents[1];P=D/'package';r=ET.parse(P/'Control.wprp').getroot();profiles=r.find('Profiles');events={e.get('Id'):e for e in profiles.findall('EventProvider')}
assert len(events)==2
assert events['WLabAFD'].get('Name').lower()=='e53c6823-7bb8-44bb-90dc-3f86090d48a6'
assert events['WLabAFD'].find('Keywords/Keyword').get('Value')=='0x4'
assert events['WLabSockets'].find('Keywords/Keyword').get('Value')=='0x1'
assert all(e.get('Stack')=='true' and e.get('Strict')=='true' for e in events.values())
prof=profiles.find('Profile');assert prof.get('LoggingMode')=='Memory'
assert {e.get('Value') for e in prof.findall('.//EventProviderId')}==set(events)
c=profiles.find('EventCollector');assert int(c.find('Buffers').get('Value'))*int(c.find('BufferSize').get('Value'))*1024==4194304
s=(P/'Run-Control.ps1').read_text()
assert "'-filemode'" not in s and "'-cancel','-instancename',$instance" in s
assert "'-stop',$etl,'-skipPdbGen','-instancename',$instance" in s
assert "@('-start',($profile+'!WLabControl.Verbose'),'-recordtempto',$temp,'-instancename',$instance)" in s
assert 'IPAddress.Loopback' in s and '64,128,256' in s and sum([64,128,256])==448
assert "stack_presence_verified=$false" in s and '64MB' in s
report=dict(scope='XML well-formedness, reference and source-string invariants only; not WPR XSD validation, PowerShell/C# compilation, runtime or ETL validation.',checks_passed=True,windows_execution_tested=False,powershell_syntax_parser_used=False,requested_event_buffer_bytes=4194304,expected_loopback_verified_bytes=448,stack_presence_verified=False,files=[dict(name=p.name,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(P.iterdir()) if p.is_file()])
(D/'reports/package-static-checks.json').write_text(json.dumps(report,indent=2)+'\n');print('Static invariants passed. Windows execution/stack capture NOT tested.')
