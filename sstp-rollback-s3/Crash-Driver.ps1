[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SessionId)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REPOSITORY -ne 'kokononox/battle-net-agent-lab') { throw 's3_ci_only_driver' }
. (Join-Path $PSScriptRoot 'Core.ps1')
$j=ReadJournal $PSScriptRoot $SessionId
$lock=AcquireSessionLock $PSScriptRoot
# Intentionally NO finally/rollback: Environment.Exit simulates loss of the apply driver.
$deadline=[DateTimeOffset]::Parse($j.prepared_utc).AddSeconds(30)
foreach ($p in $j.rules) {
    if ([DateTimeOffset]::UtcNow -gt $deadline) { throw 's3_apply_window_expired' }
    $rule=GetFixtureRule $p.name
    if ((FixtureIdentity $rule) -cne $p.identity_sha256 -or [string]$rule.Enabled -cne $p.before) { throw 's3_fixture_changed_before_apply' }
    Set-NetFirewallRule -Name $p.name -PolicyStore PersistentStore -Enabled False -ErrorAction Stop
}
if ($j.scenario -eq 'partial_conflict') {
    $p=$j.profiles[0]
    Set-NetFirewallProfile -Name $p.name -PolicyStore PersistentStore -DefaultOutboundAction Block -ErrorAction Stop
    # Fixture B deliberately changed by the simulated other administrator; the rollback must refuse it.
    Set-NetFirewallRule -Name $j.rules[1].name -PolicyStore PersistentStore -Description ('foreign-change-'+$SessionId) -ErrorAction Stop
} else {
    foreach ($p in $j.profiles) {
        if ([DateTimeOffset]::UtcNow -gt $deadline) { throw 's3_apply_window_expired' }
        Set-NetFirewallProfile -Name $p.name -PolicyStore PersistentStore -DefaultOutboundAction Block -ErrorAction Stop
    }
}
WriteNewJson (Join-Path $PSScriptRoot 'driver-applied.json') ([ordered]@{scenario=$j.scenario;profiles=(ProfileSnapshot);a_enabled=[string](GetFixtureRule $j.rules[0].name).Enabled;b_enabled=[string](GetFixtureRule $j.rules[1].name).Enabled})
[Environment]::Exit(73)
