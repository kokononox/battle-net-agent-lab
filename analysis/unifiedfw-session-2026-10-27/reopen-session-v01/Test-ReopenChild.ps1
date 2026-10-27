param([string]$PackageRoot,[string]$FixtureRoot)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$m=Import-Module (Join-Path $PackageRoot 'Ufw.SessionJournal.psm1') -Force -PassThru
$reader=@(& $m {& $script:Core {Get-Module Ufw.ProfileReader}})[0]
& $reader {
 function script:Assert-UfwReadPlatform {}
 function script:Get-NetFirewallProfile {param($PolicyStore,$ErrorAction)foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;DefaultOutboundAction='Block';Enabled='True';AllowLocalFirewallRules=$(if($PolicyStore -ceq 'PersistentStore'){'NotConfigured'}else{'True'});DisabledInterfaceAliases=@()}}}
}
$r=& $m {
 param($entry,$root). $entry;$script:ChildFixtureRoot=$root
 function Get-UfwReopenNativeRoot {return $script:ChildFixtureRoot}
 Invoke-UfwReadOnlyReopen
} (Join-Path $PackageRoot 'ReopenEntry.ps1') $FixtureRoot
$r|ConvertTo-Json -Depth 24 -Compress
if(-not $r.completed){exit 1}
