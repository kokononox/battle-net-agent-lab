"""Pure range preview. No DNS, firewall or file mutations."""
import ipaddress,re

def build_range(payload,validate_target,format_entries):
 mode=payload.get('mode');value=payload.get('value','');last=payload.get('last','');port=payload.get('port');proto=payload.get('protocol')
 if mode not in ('pattern','between','cidr','targets') or not isinstance(value,str) or len(value)>(12000 if mode=='targets' else 200) or not isinstance(last,str) or len(last)>200:raise ValueError('invalid_range_input')
 if type(port) is not int or not 1<=port<=65535 or proto not in ('TCP','UDP'):raise ValueError('invalid_port_protocol')
 port_end=payload.get('port_end',port);budget=payload.get('row_budget',256);program_count=payload.get('program_count',1)
 if type(port_end) is not int or not port<=port_end<=65535:raise ValueError('invalid_port_range_order_or_end')
 if type(budget) is not int or not 0<=budget<=256 or type(program_count) is not int or not 1<=program_count<=32:raise ValueError('invalid_range_budget_or_program_count')
 value=value.strip()
 if mode=='targets':
  items=value.splitlines()
  if not items or len(items)>256:raise ValueError('observed_IP_list_limit_256')
  targets=sorted(set(ipaddress.ip_address(x.strip()) for x in items if x.strip()),key=lambda ip:(ip.version,int(ip)))
  if not targets:raise ValueError('empty_IP_list')
  nets=targets;first=targets[0];end=targets[-1]
 elif mode=='pattern':
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
 if len(nets)>100 and mode!='targets':raise ValueError('too_many_range_rules')
 port_count=port_end-port+1;row_count=len(nets)*port_count
 if row_count>budget:raise ValueError(f'port_range_expansion_exceeds_remaining_draft_limit: needs={row_count}, remaining={budget}, total_cap=256; no_partial_expansion')
 if row_count*program_count>1024:raise ValueError('port_range_exceeds_native_1024_rules; narrow_range_or_EXEs')
 try:entries=[dict(ip=validate_target(str(n)),port=number,protocol=proto) for n in nets for number in range(port,port_end+1)]
 except ValueError:raise ValueError('range_must_be_public_without_special_use_overlap')
 return dict(entries=entries,text=format_entries(entries),first_ip=str(first),last_ip=str(end),address_count=str(len(nets) if mode=='targets' else int(end)-int(first)+1),destination_set_not_contiguous=(mode=='targets'),ip_rule_count=len(nets),port_first=port,port_last=port_end,port_count=port_count,rule_count=len(entries),native_rule_upper_bound=len(entries)*program_count,port_range_representation='explicit_single_port_entries_no_native_engine_change',row_budget=budget,scope='selected_Wow_executable_port_protocol_only',applied=False)
