"""Explicit DNS cache-only operation. Never edits hosts, firewall or DNS configuration."""
from hosts_reset import require_admin,flush_dns
CONSENT='FLUSH WINDOWS DNS CACHE'
def handle(store,action,payload,job):
 if action!='hosts_reset_dns_flush':raise ValueError('unknown_dns_cache_action')
 if payload.get('confirmation')!=CONSENT:raise ValueError('dns_cache_click_confirmation_required')
 require_admin()
 result=flush_dns()
 # The reused function's failure code mentions a preceding hosts reset; none occurs here.
 if not result.get('succeeded') and result.get('error')=='dns_flush_failed_hosts_already_verified':
  result={**result,'error':'dns_cache_flush_failed_no_hosts_write_requested'}
 return dict(dns_cache_flush=result,hosts_changed=False,firewall_changed=False,dns_server_settings_changed=False,trace_sessions_changed=False)
