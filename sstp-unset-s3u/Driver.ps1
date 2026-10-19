[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SessionId)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REPOSITORY -ne 'kokononox/battle-net-agent-lab') { throw 's3u_ci_only_driver' }
. (Join-Path $PSScriptRoot 'Core.ps1')
$j=ReadUnsetJournal $PSScriptRoot $SessionId;$lock=AcquireSessionLock $PSScriptRoot
if ([DateTimeOffset]::UtcNow -gt [DateTimeOffset]::Parse($j.prepared_utc).AddSeconds(30)) { throw 's3u_apply_window_expired' }
foreach ($p in $j.profiles) { if ((GetProfileValue $p.name) -cne 'NotConfigured') { throw 's3u_baseline_changed' } }
Set-NetFirewallProfile -Name Domain,Private,Public -PolicyStore PersistentStore -DefaultOutboundAction Block -ErrorAction Stop
$rows=ReadRegistryProfiles
WriteNewJson (Join-Path $PSScriptRoot 'applied.json') ([ordered]@{profiles=(ProfileSnapshot);registry_sha256=(RegistryDigest $rows);outbound_registry_sha256=(OutboundRegistryDigest $rows);registry_outbound_value_count=(OutboundPresenceCount $rows)})
# Exit without finally or cleanup. Only the previously armed SYSTEM timer should restore the defaults.
[Environment]::Exit(73)
