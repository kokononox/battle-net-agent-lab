Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function AssertPrivateDirectory([string]$Path) {
    $item=Get-Item -LiteralPath $Path
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'private_directory_invalid' }
    $acl=Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw 'private_acl_not_protected' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'untrusted_private_acl' }
    }
}
function CreatePrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'private_directory_exists' }
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity=New-Object Security.Principal.SecurityIdentifier($sid)
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    [void][IO.Directory]::CreateDirectory($Path,$acl)
    AssertPrivateDirectory $Path
}
function S3Hash([string]$Text) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
function WriteNewJson([string]$Path,$Value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 12))
    $fs=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $fs.Write($bytes,0,$bytes.Length);$fs.Flush($true) } finally { $fs.Dispose() }
}
function AcquireSessionLock([string]$Folder) {
    $limit=[DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $limit) {
        try { return (New-Object IO.FileStream((Join-Path $Folder 'session.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)) }
        catch [IO.IOException] { Start-Sleep -Milliseconds 250 }
    };throw 's3_session_lock_timeout'
}
function GetProfileValue([string]$Name) {
    $p=@(Get-NetFirewallProfile -Name $Name -PolicyStore PersistentStore -ErrorAction Stop)
    if ($p.Count -ne 1) { throw 's3_profile_not_unique' };return [string]$p[0].DefaultOutboundAction
}
function ProfileSnapshot {
    return @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop | Sort-Object Name | ForEach-Object { [ordered]@{name=[string]$_.Name;outbound=[string]$_.DefaultOutboundAction} })
}
function EffectiveProfileSnapshot {
    return (@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Sort-Object Name | ForEach-Object { [ordered]@{name=[string]$_.Name;enabled=[string]$_.Enabled;inbound=[string]$_.DefaultInboundAction;outbound=[string]$_.DefaultOutboundAction} }) | ConvertTo-Json -Compress)
}
function ReadRegistryProfiles {
    # READ ONLY: never opens a registry key for writing. Values stay private to the CI session.
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $paths=@('SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile','SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile','SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile','SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile','SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile','SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile','SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile')
    $rows=New-Object Collections.ArrayList
    try {
        foreach ($path in $paths) {
            $key=$base.OpenSubKey($path,$false)
            try {
                if ($null -eq $key) { [void]$rows.Add([ordered]@{path=$path;exists=$false;values=@()});continue }
                $values=@()
                $names=@($key.GetValueNames() | Sort-Object)
                if ($names.Count -gt 512) { throw 's3u_registry_value_cap' }
                foreach ($name in $names) {
                    $value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $json=ConvertTo-Json -InputObject $value -Compress -Depth 4
                    if ($json.Length -gt 65536) { throw 's3u_registry_value_size' }
                    $values+=,[ordered]@{name=$name;kind=[string]$key.GetValueKind($name);data=$json}
                }
                [void]$rows.Add([ordered]@{path=$path;exists=$true;values=$values})
            } finally { if ($null -ne $key) { $key.Dispose() } }
        }
    } finally { $base.Dispose() }
    return @($rows.ToArray())
}
function RegistryDigest($Rows) { return (S3Hash (ConvertTo-Json -InputObject @($Rows) -Depth 10 -Compress)) }
function OutboundRegistryDigest($Rows) {
    $selected=@($Rows | ForEach-Object { [ordered]@{path=$_.path;outbound=@($_.values | Where-Object { $_.name -ceq 'DefaultOutboundAction' })} })
    return (S3Hash (ConvertTo-Json -InputObject $selected -Depth 10 -Compress))
}
function OutboundPresenceCount($Rows) {
    return @($Rows | ForEach-Object { $_.values } | Where-Object { $_.name -ceq 'DefaultOutboundAction' }).Count
}
function RulePropertyDigest {
    $rows=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Sort-Object Name | ForEach-Object {
        [ordered]@{name=[string]$_.Name;enabled=[string]$_.Enabled;action=[string]$_.Action;direction=[string]$_.Direction;profile=[string]$_.Profile;group=[string]$_.Group;description=[string]$_.Description;display_name=[string]$_.DisplayName}
    })
    return (S3Hash (ConvertTo-Json -InputObject $rows -Depth 6 -Compress))
}
function ReadComEffective {
    $fw=New-Object -ComObject HNetCfg.FwPolicy2
    try {
        return [ordered]@{domain=[int]$fw.DefaultOutboundAction(1);private=[int]$fw.DefaultOutboundAction(2);public=[int]$fw.DefaultOutboundAction(4)}
    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($fw) }
}
function UnsetDecision([string]$Value) {
    if ($Value -ceq 'Block') { return 'restore_notconfigured' }
    if ($Value -ceq 'NotConfigured') { return 'already_notconfigured' }
    return 'conflict'
}
function AssertUnsetJournal($J,[string]$Id) {
    if ($Id -cnotmatch '^[a-f0-9]{32}$' -or $J.schema -cne 's3u-ci-journal-1' -or $J.session_id -cne $Id -or $J.purpose -cne 'experimental_unset_roundtrip_ci_only') { throw 's3u_journal_identity' }
    if (@($J.profiles).Count -ne 3 -or (@($J.profiles | ForEach-Object { $_.name } | Sort-Object) -join ',') -cne 'Domain,Private,Public') { throw 's3u_journal_profiles' }
    foreach ($p in $J.profiles) { if ($p.before -cne 'NotConfigured' -or $p.applied -cne 'Block') { throw 's3u_journal_values' } }
    $at=[DateTimeOffset]::Parse($J.prepared_utc)
    if ($at -lt [DateTimeOffset]::UtcNow.AddMinutes(-10) -or $at -gt [DateTimeOffset]::UtcNow.AddMinutes(1)) { throw 's3u_journal_stale' }
}
function ReadUnsetJournal([string]$Folder,[string]$Id) {
    AssertPrivateDirectory $Folder
    if ((Split-Path $Folder -Leaf) -cne ('RetailIsolation-S3U-'+$Id)) { throw 's3u_folder_identity' }
    $path=Join-Path $Folder 'journal.json';$item=Get-Item -LiteralPath $path
    if ($item.Length -gt 65536 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 's3u_journal_file' }
    $j=[IO.File]::ReadAllText($path) | ConvertFrom-Json;AssertUnsetJournal $j $Id;return $j
}
function RestoreUnsetExperiment([string]$Folder,[string]$Id) {
    $j=ReadUnsetJournal $Folder $Id;$lock=AcquireSessionLock $Folder
    try {
        $rows=@();$writes=0
        foreach ($p in $j.profiles) {
            $decision=UnsetDecision (GetProfileValue $p.name)
            if ($decision -eq 'restore_notconfigured') {
                # Experimental provider qualification on an ephemeral CI host, NOT a supported user Apply path.
                Set-NetFirewallProfile -Name $p.name -PolicyStore PersistentStore -DefaultOutboundAction NotConfigured -ErrorAction Stop
                $writes++
                if ((GetProfileValue $p.name) -cne 'NotConfigured') { throw 's3u_provider_restore_readback_failed' }
            }
            $rows+=,[ordered]@{name=$p.name;decision=$decision}
        }
        return [ordered]@{schema='s3u-timer-receipt-1';ran_as_system=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');restore_write_calls=$writes;conflicts=@($rows | Where-Object { $_.decision -eq 'conflict' }).Count;rows=$rows}
    } finally { $lock.Dispose() }
}
