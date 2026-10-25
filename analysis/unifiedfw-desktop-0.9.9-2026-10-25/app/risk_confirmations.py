"""Additional desktop consent restored from legacy blacklist; no rule or precedence changes."""
from policy import interval,PolicyError,port_matches,port_span
RANGE_TEXT='I ACCEPT NETWORK RANGE RISK'
LOGIN_TEXT='I ACCEPT LOGIN DISRUPTION RISK'
def risks(config):
 enabled={p['id'] for p in config['programs'] if p['enabled']};ranges=[];critical=[];known=interval('37.244.29.11')
 for entry in config['blacklist']:
  if not enabled.intersection(entry['program_ids']):continue
  dest=interval(entry['target'])
  if dest.low!=dest.high or port_span(entry['port'])[0]!=port_span(entry['port'])[1]:ranges.append(dict(entry_id=entry['id'],target=entry['target'],port=entry['port'],address_count=str(dest.high-dest.low+1)))
  if entry['protocol']=='TCP' and port_matches(entry['port'],3724) and dest.overlaps(known):critical.append(entry['id'])
 return dict(network_ranges=ranges,known_login_endpoint_entry_ids=critical,range_confirmation=RANGE_TEXT if ranges else None,login_confirmation=LOGIN_TEXT if critical else None,known_endpoint_list_is_not_exhaustive=True)
def require(config,payload):
 r=risks(config)
 if r['network_ranges'] and payload.get('range_confirmation')!=RANGE_TEXT:raise PolicyError('network_range_requires_extra_confirmation')
 if r['known_login_endpoint_entry_ids'] and payload.get('login_confirmation')!=LOGIN_TEXT:raise PolicyError('known_login_endpoint_requires_extra_confirmation')
