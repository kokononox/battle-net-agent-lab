"""Global SSTP allow-only policy. No native calls. Blacklist is exempted only inside VPN."""
from policy import validate,whitelist_spec,cidrs,interval,digest,PolicyError,whitelist_matches,port_span

def make_policy(state):
 c=state['config'];validate(c)
 if c['mode']!='full_isolation':raise PolicyError('select_and_save_full_isolation_first')
 specs=[dict(remote_addresses=cidrs([interval(w['target'])]),protocol=w['protocol'],remote_port='Any' if w['protocol']=='Any' else str(w['port'])+(('-'+str(w['port_end'])) if w['port_end']!=w['port'] else '')) for w in map(whitelist_spec,c['whitelist'])]
 if not specs:raise PolicyError('isolation_whitelist_empty')
 if sum(len(s['remote_addresses']) for s in specs)>8192:raise PolicyError('isolation_address_limit')
 overlaps=[]
 for e in c['blacklist']:
  for value in c['whitelist']:
   w=whitelist_spec(value)
   if interval(w['target']).overlaps(interval(e['target'])) and (w['protocol']=='Any' or w['protocol']==e['protocol'] and w['port']<=port_span(e['port'])[1] and port_span(e['port'])[0]<=w['port_end']):
    overlaps.append(dict(entry_id=e['id'],program_ids=e['program_ids'],target=e['target'],protocol=e['protocol'],port=e['port'],whitelist=value,resolution='whitelist_wins_only_for_overlap_inside_VPN; other_destinations_blocked_by_default'))
 return dict(schema='unified-isolation-policy-1',owner=state['owner'],generation=c['generation'],config_digest=digest(c),whitelist=specs,overlaps=overlaps,outside_tunnel='default_outbound_block_with_explicit_control_plane_exceptions',foreign_allow_rules='explicit_review_back_up_disable_local_outbound_Allow_only',foreign_block_rules='preserved; may still block allowed traffic',no_leak_certified=False)
