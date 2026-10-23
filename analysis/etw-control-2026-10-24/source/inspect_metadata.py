"""Parse uploaded metadata as data only. Deduplicate root/nested copies by hash."""
from pathlib import Path
import sys,zipfile,hashlib,json,re,xml.etree.ElementTree as ET
src=Path(sys.argv[1]);dest=Path(sys.argv[2]);ns={'e':'http://schemas.microsoft.com/win/2004/08/events'}
with zipfile.ZipFile(src) as z:
 files={i.filename:z.read(i) for i in z.infolist() if not i.is_dir()}
 for name,b in files.items():
  assert '..' not in Path(name).parts
  assert len(b)<10_000_000
  if '/' in name:assert b==files[Path(name).name]
 rows=[]
 for name in ['Microsoft-Windows-Winsock-AFD','Microsoft-Windows-Winsock-Sockets','Microsoft-Windows-TCPIP']:
  b=files[name+'-events.txt'];txt=b.decode('utf-8-sig');root=ET.fromstring(txt)
  tasks={t.get('value'):t.get('name') for t in root.findall('./e:tasks/e:task',ns)}
  events=[dict(e.attrib,task_name=tasks.get(e.get('task')),typed_template_present=e.get('template') is not None or bool(e.findall('./e:template',ns))) for e in root.findall('./e:events/e:event',ns)]
  assert len(events)==len(re.findall(r'<event\s+value=',txt))
  selected=events if name.endswith('-Sockets') else [e for e in events if e['value'] in ['1','4','18','1000','1003','1017','1018']]
  rows.append(dict(provider=name,guid=root.get('guid'),event_count=len(events),selected_events=selected,full_export_has_typed_templates=any(e['typed_template_present'] for e in events),metadata_sha256=hashlib.sha256(b).hexdigest()))
 out=dict(input_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),archive_file_entries=len(files),unique_files=sum('/' not in n for n in files),duplicates_byte_identical=True,duplicate_policy='Only root copies parsed; nested copies verified byte-identical. No input executable or script executed.',providers=rows,wpr_reported_version='10.0.26100 CoreSystem',os_build_user_reported='26200',version_difference_not_itself_an_error=True)
 dest.write_text(json.dumps(out,indent=2)+'\n')
 print('XML event counts independently agree with lexical counts; 7 duplicate copies identical.')
