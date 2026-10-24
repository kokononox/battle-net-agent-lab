"""Read only the standard Windows hosts file. Entries are configuration, not process activity."""
import hashlib,ipaddress,os,re,time
from pathlib import Path
IS_WINDOWS=os.name=='nt'
MAX_BYTES=8*1024*1024
MAX_DOMAINS=5000
SYSTEM_NAMES={'localhost','localhost.localdomain','ip6-localhost','ip6-loopback','broadcasthost'}

def domain_name(value):
 try:name=value.rstrip('.').encode('idna').decode('ascii').lower()
 except (UnicodeError,ValueError):return None
 if len(name)>253 or not name or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in name.split('.')):return None
 try:ipaddress.ip_address(name);return None
 except ValueError:return name

def parse_hosts(data):
 if not isinstance(data,bytes) or len(data)>MAX_BYTES:raise ValueError('hosts_file_too_large')
 if data.startswith((b'\xff\xfe',b'\xfe\xff')):text=data.decode('utf-16');encoding='utf-16'
 else:
  try:text=data.decode('utf-8-sig');encoding='utf-8'
  except UnicodeError:text=data.decode('cp1252');encoding='cp1252'
 records={};invalid=0;truncated=False;comments=0
 for line_no,raw in enumerate(text.splitlines(),1):
  line=raw.split('#',1)[0].strip()
  if not line:
   if raw.strip().startswith('#'):comments+=1
   continue
  parts=line.split()
  if len(parts)<2:invalid+=1;continue
  try:address=ipaddress.ip_address(parts[0])
  except ValueError:invalid+=1;continue
  target=str(address);local=address.is_loopback or address.is_unspecified
  for alias in parts[1:]:
   name=domain_name(alias)
   if name is None:invalid+=1;continue
   if name not in records:
    if len(records)>=MAX_DOMAINS:truncated=True;continue
    records[name]=dict(domain=name,addresses=[],local_addresses=[],other_addresses=[],lines=[])
   row=records[name]
   if target not in row['addresses']:row['addresses'].append(target)
   which='local_addresses' if local else 'other_addresses'
   if target not in row[which]:row[which].append(target)
   if line_no not in row['lines']:row['lines'].append(line_no)
 rows=[]
 for name,row in sorted(records.items()):
  kind='system_local' if name in SYSTEM_NAMES else ('mixed_mapping' if row['local_addresses'] and row['other_addresses'] else ('local_sink_mapping' if row['local_addresses'] else 'other_mapping'))
  rows.append({**row,'mapping_kind':kind,'game_attempt_verified':False,'blocking_verified':False})
 return dict(schema='wow-blacklist-hosts-view-1',entries=rows,encoding=encoding,invalid_items=invalid,comment_lines=comments,truncated=truncated,domain_limit=MAX_DOMAINS,local_sink_domains=sum(x['mapping_kind']=='local_sink_mapping' for x in rows),mixed_domains=sum(x['mapping_kind']=='mixed_mapping' for x in rows),sha256=hashlib.sha256(data).hexdigest(),checked_utc_epoch=time.time(),read_only=True,game_attempt_verified=False,blocking_verified=False)

def read_windows_hosts():
 if not IS_WINDOWS:raise ValueError('hosts_view_requires_Windows')
 root=os.environ.get('SystemRoot')
 if not root:raise ValueError('hosts_windows_root_unavailable')
 path=Path(root)/'System32/drivers/etc/hosts'
 with path.open('rb') as handle:data=handle.read(MAX_BYTES+1)
 return parse_hosts(data)
