[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SessionId)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
# This worker NEVER imports firewall policy or changes networking. It only writes a receipt.
if ($SessionId -cnotmatch '^[a-f0-9]{32}$') { throw 'invalid_session' }
if ((Split-Path $PSScriptRoot -Leaf) -cne ('RetailIsolation-S2-'+$SessionId)) { throw 'private_folder_mismatch' }
$dir=Get-Item -LiteralPath $PSScriptRoot
if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'private_folder_is_reparse_point' }
$acl=Get-Acl -LiteralPath $PSScriptRoot
if (-not $acl.AreAccessRulesProtected) { throw 'private_acl_not_protected' }
foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'untrusted_private_acl' }
}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne 'S-1-5-18') { throw 'probe_not_system' }
$r=[ordered]@{schema='s2-system-probe-1';session_id=$SessionId;ran_as_system=$true;ended_utc=[DateTime]::UtcNow.ToString('o');network_settings_changed=$false;firewall_import_attempted=$false}
$path=Join-Path $PSScriptRoot 'system-probe.json'
$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($r | ConvertTo-Json))
$stream=New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
