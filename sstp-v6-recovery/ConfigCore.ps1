# Configuration and read-only compatibility planning. NO firewall mutation entry point.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

function AssertConfigPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'tool_config_path' }
    $full = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetExtension($full) -ine '.json') { throw 'tool_config_extension' }
    $cursor = $full
    while ($cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'tool_config_link' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -ceq $cursor) { break }; $cursor = $parent
    }
    return $full
}
function ReadAllowlistConfig([string]$Path) {
    $full = AssertConfigPath $Path
    $f = New-Object IO.FileInfo($full)
    if (-not $f.Exists -or $f.Length -gt 65536) { throw 'tool_config_missing_or_large' }
    $text = [IO.File]::ReadAllText($full)
    return (PolicyConfig (ConvertFrom-Json -InputObject $text -ErrorAction Stop))
}
function EditAllowlistFile([string]$Path,[ValidateSet('Init','Add','Remove')][string]$Operation,[string]$Address='') {
    $full = AssertConfigPath $Path
    $dir = [IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($dir)) { throw 'tool_config_directory_missing' }
    $lockPath = $full + '.lock'
    $null = AssertConfigPath ($lockPath + '.json') # Includes existing ancestor/link checks.
    if ([IO.File]::Exists($lockPath) -and (([IO.File]::GetAttributes($lockPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'tool_config_link' }
    $lock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $temp = $null
    try {
        $null = AssertConfigPath $full
        if ($Operation -ceq 'Init') {
            if ([IO.File]::Exists($full)) { throw 'tool_config_already_exists' }
            $config = PolicyConfig ([pscustomobject]@{schema='sstp-allowlist-config-1';domains=@('level3.blizzard.com');ip_addresses=@()})
        } else { $config = EditPolicyConfig (ReadAllowlistConfig $full) $Operation $Address }
        $json = ConvertTo-Json -InputObject $config -Depth 5
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
        if ($bytes.Length -gt 65536) { throw 'tool_config_large' }
        $temp = Join-Path $dir ('.sstp-config-' + [guid]::NewGuid().ToString('N') + '.tmp')
        $stream = [IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ($Operation -ceq 'Init') { [IO.File]::Move($temp,$full) }
        else { [IO.File]::Replace($temp,$full,[System.Management.Automation.Language.NullString]::Value) }
        $temp = $null
        return (ReadAllowlistConfig $full)
    } finally {
        if ($temp -and [IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
        $lock.Dispose()
        # Retain the empty lock FILE; no process holds it after return.
    }
}
function NewCompatibilityPlan($Config,$Profiles,$Rules) {
    $c = PolicyConfig $Config
    $profileSet = @($Profiles); $ruleSet = @($Rules); $seen = @{}; $names = @{}
    if ($profileSet.Count -ne 3) { throw 'tool_profile_coverage' }
    $profileBlockers = @()
    foreach ($p in $profileSet) {
        if ($p.name -cnotin @('Domain','Private','Public') -or $seen.ContainsKey($p.name)) { throw 'tool_profile_identity' }
        $seen[$p.name] = $true
        if ($p.enabled -cnotin @('True','False') -or $p.default_outbound -cnotin @('Allow','Block','NotConfigured')) { throw 'tool_profile_value' }
        if ($p.enabled -cne 'True') { $profileBlockers += ,'firewall_profile_disabled' }
        if ($p.default_outbound -cne 'Block') { $profileBlockers += ,'effective_default_not_block' }
    }
    $legacy = @(); $otherAllows = @(); $blocks = @()
    foreach ($r in $ruleSet) {
        if ([string]::IsNullOrWhiteSpace($r.name) -or $names.ContainsKey($r.name)) { throw 'tool_rule_identity' }
        $names[$r.name] = $true
        if ($r.source_type -cnotin @('Local','GroupPolicy','Dynamic','Generated','Hardcoded') -or $r.action -cnotin @('Allow','Block','AllowBypass')) { throw 'tool_rule_value' }
        if ($r.action -ceq 'Block') { $blocks += ,$r.name; continue }
        if ($r.group -ceq 'SSTP Kill Switch' -and $r.source_type -ceq 'Local') { $legacy += ,$r.name }
        else { $otherAllows += ,$r.name }
    }
    return [pscustomobject][ordered]@{
        schema='sstp-allowlist-compatibility-1'; mode='read_only'; config=$c
        profile_blockers=@($profileBlockers | Sort-Object -Unique)
        legacy_group_candidates=@($legacy | Sort-Object); other_outbound_allow_candidates=@($otherAllows | Sort-Object)
        existing_outbound_blocks_to_review=@($blocks | Sort-Object)
        legacy_group_is_ownership_proof=$false; existing_rules_are_not_automatically_adopted=$true
        dns_queried=$false; network_changed=$false; vpn_connection_managed=$false
        resident_component_created=$false; apply_available=$false; ready_for_user_apply=$false
        unresolved=@('guarded_apply_and_exact_restore','effective_allow_and_block_review','vpn_path_binding','sstp_bootstrap_and_dns','disconnect_and_boot_validation')
        domain_semantics='explicit_ip_snapshot_required_not_hostname_identity'
    }
}
function ReadCompatibilityPlan([string]$ConfigPath) {
    # All NetSecurity calls are GET operations. Never execute/import the old kill-switch.
    $config = ReadAllowlistConfig $ConfigPath
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{name=[string]$_.Name;enabled=[string]$_.Enabled;default_outbound=[string]$_.DefaultOutboundAction}
    })
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop |
        Where-Object { [string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' } | ForEach-Object {
            [pscustomobject]@{name=[string]$_.Name;group=[string]$_.Group;action=[string]$_.Action;source_type=[string]$_.PolicyStoreSourceType}
        })
    return (NewCompatibilityPlan $config $profiles $rules)
}
