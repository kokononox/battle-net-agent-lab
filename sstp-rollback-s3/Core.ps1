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
function S3Field($Object,[string]$Name) {
    $p=$Object.PSObject.Properties[$Name]
    if ($null -eq $p) { throw 's3_required_property_missing' };return $p.Value
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
function GetFixtureRule([string]$Name) {
    $rules=@(Get-NetFirewallRule -Name $Name -PolicyStore PersistentStore -ErrorAction Stop)
    if ($rules.Count -ne 1) { throw 's3_fixture_rule_not_unique' };return $rules[0]
}
function FixtureIdentity($Rule) {
    # S3 fixtures only, not a general fingerprint for arbitrary user policy.
    $af=$Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $pf=$Rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $ap=$Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $sf=$Rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    $ifilt=$Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
    $it=$Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
    $v=[ordered]@{}
    foreach ($k in @('Name','DisplayName','Description','Group','Direction','Action','Profile','EdgeTraversalPolicy','PolicyStoreSourceType')) { $v[$k]=[string](S3Field $Rule $k) }
    foreach ($entry in @(@('Address',$af,@('LocalAddress','RemoteAddress')),@('Port',$pf,@('Protocol','LocalPort','RemotePort')),@('App',$ap,@('Program','Package')),@('Service',$sf,@('Service')),@('Interface',$ifilt,@('InterfaceAlias')),@('InterfaceType',$it,@('InterfaceType')))) {
        foreach ($k in $entry[2]) { $v[($entry[0]+$k)]=@((S3Field $entry[1] $k) | ForEach-Object { [string]$_ } | Sort-Object) }
    }
    return (S3Hash ($v | ConvertTo-Json -Depth 8 -Compress))
}
function RollbackDecision([string]$Current,[string]$Before,[string]$Applied,[bool]$IdentityMatches) {
    if (-not $IdentityMatches) { return 'conflict_identity' }
    if ($Current -ceq $Before) { return 'already_before' }
    if ($Current -ceq $Applied) { return 'restore' }
    return 'conflict_value'
}
function AssertJournal($J,[string]$Id) {
    if ($Id -cnotmatch '^[a-f0-9]{32}$' -or $J.schema -cne 's3-ci-journal-1' -or $J.session_id -cne $Id -or $J.purpose -cne 'github_hosted_ci_fixtures_only') { throw 's3_journal_identity' }
    if ($J.scenario -notin @('full','partial_conflict') -or @($J.profiles).Count -ne 3 -or @($J.rules).Count -ne 2) { throw 's3_journal_shape' }
    if ((@($J.profiles | ForEach-Object { $_.name } | Sort-Object) -join ',') -cne 'Domain,Private,Public') { throw 's3_journal_profiles' }
    foreach ($p in $J.profiles) { if ($p.before -notin @('Allow','Block') -or $p.applied -cne 'Block') { throw 's3_journal_profile_value' } }
    $expected=@(('RetailIsolation-S3-'+$Id+'-A'),('RetailIsolation-S3-'+$Id+'-B'))
    if ((@($J.rules | ForEach-Object { $_.name } | Sort-Object) -join ',') -cne (($expected | Sort-Object) -join ',')) { throw 's3_journal_rule_names' }
    foreach ($p in $J.rules) { if ($p.before -cne 'True' -or $p.applied -cne 'False' -or $p.identity_sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 's3_journal_rule_value' } }
    $at=[DateTimeOffset]::Parse([string]$J.prepared_utc)
    if ($at -lt [DateTimeOffset]::UtcNow.AddMinutes(-10) -or $at -gt [DateTimeOffset]::UtcNow.AddMinutes(1)) { throw 's3_journal_time' }
}
function ReadJournal([string]$Folder,[string]$Id) {
    AssertPrivateDirectory $Folder
    if ((Split-Path $Folder -Leaf) -cne ('RetailIsolation-S3-'+$Id)) { throw 's3_private_folder_mismatch' }
    $path=Join-Path $Folder 'journal.json';$item=Get-Item -LiteralPath $path
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 65536) { throw 's3_journal_file_invalid' }
    $j=[IO.File]::ReadAllText($path) | ConvertFrom-Json;AssertJournal $j $Id;return $j
}
function InvokeS3Rollback([string]$Folder,[string]$Id) {
    $j=ReadJournal $Folder $Id;$lock=AcquireSessionLock $Folder
    try {
        $items=New-Object Collections.ArrayList
        # Restore connectivity-related defaults before fixture rules; only the planned properties are touched.
        foreach ($p in $j.profiles) {
            $current=GetProfileValue $p.name;$decision=RollbackDecision $current $p.before $p.applied $true
            if ($decision -eq 'restore') {
                Set-NetFirewallProfile -Name $p.name -PolicyStore PersistentStore -DefaultOutboundAction $p.before -ErrorAction Stop
                if ((GetProfileValue $p.name) -cne $p.before) { throw 's3_profile_restore_not_verified' }
            }
            [void]$items.Add([ordered]@{kind='profile';key=$p.name;decision=$decision})
        }
        foreach ($p in $j.rules) {
            $rule=GetFixtureRule $p.name;$same=((FixtureIdentity $rule) -ceq $p.identity_sha256)
            $decision=RollbackDecision ([string]$rule.Enabled) $p.before $p.applied $same
            if ($decision -eq 'restore') {
                Set-NetFirewallRule -Name $p.name -PolicyStore PersistentStore -Enabled True -ErrorAction Stop
                if ([string](GetFixtureRule $p.name).Enabled -cne $p.before) { throw 's3_rule_restore_not_verified' }
            }
            [void]$items.Add([ordered]@{kind='fixture_rule';key=($p.name.Substring($p.name.Length-1));decision=$decision})
        }
        return [ordered]@{schema='s3-ci-rollback-receipt-1';ran_as_system=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18');items=@($items.ToArray());conflicts=@($items | Where-Object { $_.decision -like 'conflict_*' }).Count;firewall_import_used=$false}
    } finally { $lock.Dispose() }
}
