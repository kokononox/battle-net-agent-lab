"""Pre-registered six-case pilot. No arbitrary domains or process-wide blocks."""
POLICIES={
 'r1':('control-1',None),
 'r2':('control-2',None),
 'r3':('telemetry-hosts-1','telemetry-in.battle.net'),
 'r4':('telemetry-hosts-2','telemetry-in.battle.net'),
 'r5':('level3-hosts','level3.blizzard.com'),
 'r6':('us-version-hosts','us.version.battle.net'),
}
DOMAINS={domain for label,domain in POLICIES.values() if domain}
def hosts_blank(replica):
 domain=POLICIES.get(replica,('',None))[1]
 return dict(domain=domain,scope='exact-hosts-os-resolver-only' if domain else 'none',backup_created=False,override_written=False,resolver_verified=False,verification_checks=0,verification_failures=0,flush_exit_code=None,restore_flush_exit_code=None,restore_attempted=False,restored=False,calibration=None)
