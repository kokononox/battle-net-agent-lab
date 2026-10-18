"""Fixed denylist experiment profiles. NOT an allowlist or privacy firewall."""
from pathlib import Path
import queue
import socket
import threading
import ipaddress
from hosts_guard import HostsGuard, safe_path, target_entry, combined_resolution

BAT3_FIXED=(
    'telemetry-in.battle.net','breaking-news.support.blizzard.com',
    'rum.battle.net','www.google-analytics.com','analytics.google.com',
    'www.googletagmanager.com','cm.g.doubleclick.net','inn-pa.googleapis.com',
    'fcmatch.google.com','eu.shop.battle.net','bnetstorefront.akamaized.net',
    'catalog.blzstatic.com','blz-contentstack-images.akamaized.net',
    'navbar.blizzard.com','content-ui.battle.net','images.blz-contentstack.com',
    'www.youtube.com','www.youtube-nocookie.com','fcmatch.youtube.com','i.ytimg.com',
)
EXTRAS=('oauth.battle.net','distribution.version.battle.net','us.version.battle.net',
        'level3.ssl.blizzard.com','level3.blizzard.com')
PROFILES={
    '01':{'label':'telemetry_only_reference','domains':('telemetry-in.battle.net',)},
    '02':{'label':'bat3_corrected_baseline','domains':BAT3_FIXED},
    **{f'{i:02}':{'label':'bat3_plus_one_extra','domains':BAT3_FIXED+(extra,)}
       for i,extra in enumerate(EXTRAS,3)},
}
ALL_TARGETS=tuple(dict.fromkeys(d for p in PROFILES.values() for d in p['domains']))

def domains_for(profile):
    if profile not in PROFILES:raise ValueError('unknown_fixed_profile')
    return PROFILES[profile]['domains']

def probe_domains(domains,timeout=8):
    if not set(domains)<=set(ALL_TARGETS):raise ValueError('unknown_probe_target')
    # All calls are OS DNS/resolver checks, not HTTP or game-server requests.
    q=queue.Queue()
    def work(domain):
        try:
            ips={ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(domain,443,type=socket.SOCK_STREAM)}
            state='loopback_only' if ips and all(i.is_loopback for i in ips) else 'public_only' if ips and all(i.is_global for i in ips) else 'other_or_failed'
        except Exception:state='other_or_failed'
        q.put((domain,state))
    for domain in domains:threading.Thread(target=work,args=(domain,),daemon=True).start()
    import time
    end=time.monotonic()+timeout;result={}
    while len(result)<len(domains):
        try:domain,state=q.get(timeout=max(0,end-time.monotonic()))
        except queue.Empty:break
        result[domain]=state
    return {d:result.get(d,'timeout') for d in domains}

class ProfileGuard(HostsGuard):
    def __init__(self,hosts,journal,profile,flush_fn=None,probe_fn=probe_domains):
        kw={} if flush_fn is None else {'flush_fn':flush_fn}
        super().__init__(hosts,journal,**kw)
        # Fixed profile only; never accept caller-supplied domains or shell text.
        self.targets=domains_for(profile);self.probe=probe_fn
    def check_resolution(self):
        self.resolutions=self.probe(self.targets)
        if set(self.resolutions)!=set(self.targets):raise ValueError('profile_resolution_keys')
        return combined_resolution(self.resolutions)
    def apply(self):
        safe_path(self.hosts)
        if self.hosts.stat().st_size>1048576:raise ValueError('hosts_size_limit')
        original=self.hosts.read_bytes()
        # Refuse existing entries from ANY profile, including the old malformed
        # :443 line, rather than silently cleaning someone else's configuration.
        legacy=ALL_TARGETS+('breaking-news.support.blizzard.com:443',)
        if target_entry(original,legacy):raise ValueError('existing_profile_entry_refused_no_changes')
        return super().apply()