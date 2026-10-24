"""Pure range preview. No DNS, firewall or file mutations."""
import ipaddress,re

def build_range(payload,validate_target,format_entries):
 mode=payload.get('mode');value=payload.get('value','');last=payload.get('last','');port=payload.get('port');proto=payload.get('protocol')
 if mode not in ('pattern','between','cidr') or not isinstance(value,str) or len(value)>200 or not isinstance(last,str) or len(last)>200:raise ValueError('invalid_range_input')
 if type(port) is not int or not 1<=port<=65535 or proto not in ('TCP','UDP'):raise ValueError('invalid_port_protocol')
 value=value.strip()
 if mode=='pattern':
  parts=value.lower().split('.')
  if not 1<=len(parts)<=4 or any(not re.fullmatch(r'(0|[1-9][0-9]{0,2}|\*|x)',x) for x in parts):raise ValueError('invalid_pattern')
  parts+=['*']*(4-len(parts));fixed=[];wild=False
  for x in parts:
   if x in ('*','x'):wild=True
   elif wild or int(x)>255:raise ValueError('wildcards_must_be_trailing')
   else:fixed.append(x)
  network=ipaddress.ip_network('.'.join(fixed+['0']*(4-len(fixed)))+'/'+str(8*len(fixed)))
  nets=[network];first=network.network_address;end=network.broadcast_address
 elif mode=='cidr':
  network=ipaddress.ip_network(value.strip('[]'),strict=False);nets=[network];first=network.network_address;end=network.broadcast_address
 else:
  first=ipaddress.ip_address(value.strip('[]'));end=ipaddress.ip_address(last.strip().strip('[]'))
  if first.version!=end.version or int(first)>int(end):raise ValueError('invalid_range_order_or_family')
  nets=list(ipaddress.summarize_address_range(first,end))
 if len(nets)>100:raise ValueError('too_many_range_rules')
 try:entries=[dict(ip=validate_target(str(n)),port=port,protocol=proto) for n in nets]
 except ValueError:raise ValueError('range_must_be_public_without_special_use_overlap')
 return dict(entries=entries,text=format_entries(entries),first_ip=str(first),last_ip=str(end),address_count=str(int(end)-int(first)+1),rule_count=len(entries),scope='selected_Wow_executable_port_protocol_only',applied=False)
