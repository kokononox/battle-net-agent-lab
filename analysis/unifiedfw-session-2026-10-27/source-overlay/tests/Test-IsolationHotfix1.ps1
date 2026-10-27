param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1')
. (Join-Path $Root 'app/isolation-core.ps1')
. (Join-Path $Root 'app/isolation-native.ps1')
$script:checks=0
function Assert($b,$m){$script:checks++;if(-not $b){throw $m}}
function Rejected($Action,$Code){
 $caught=$false;try{& $Action|Out-Null}catch{$caught=$_.Exception.Message -ceq $Code}
 Assert $caught $Code
}
$script:excluded=@('NotConfigured');$script:badStore='';$script:badName='Public'
$script:missing=$false;$script:duplicate=$false;$script:noActive=$false;$script:typedNullActive=$false
function Get-NetFirewallProfile{
 param($PolicyStore,$ErrorAction)
 if($script:noActive -and $PolicyStore -ceq 'ActiveStore'){return @()}
 foreach($n in @('Domain','Private','Public')){
  $p=[pscustomobject]@{Name=$n;Enabled='True';DefaultOutboundAction='Block';AllowLocalFirewallRules='True';DisabledInterfaceAliases=@('NotConfigured')}
  if($n -ceq $script:badName -and $PolicyStore -ceq $script:badStore){
   if($script:missing){$p.PSObject.Properties.Remove('DisabledInterfaceAliases')}else{$p.DisabledInterfaceAliases=$script:excluded}
  }
  if($script:typedNullActive -and $PolicyStore -ceq 'ActiveStore'){
   $p.DisabledInterfaceAliases=$null
   $p|Add-Member -NotePropertyName CimInstanceProperties -NotePropertyValue @{DisabledInterfaceAliases=[pscustomobject]@{CimType='StringArray';Value=$null}}
  }
  $p
  if($script:duplicate -and $PolicyStore -ceq 'ActiveStore' -and $n -ceq $script:badName){$p}
 }
}
foreach($n in @('Domain','Private','Public')){
 $p=IsoProfileRead $n
 Assert ($p.name -ceq $n -and $p.default_outbound -ceq 'Block') 'normal profile admitted'
 Assert (@($p.PSObject.Properties).Count -eq 4) 'journal shape unchanged'
}
foreach($store in @('PersistentStore','ActiveStore')){
 foreach($n in @('Domain','Private','Public')){
  $script:badStore=$store;$script:badName=$n
  foreach($excluded in @('Ethernet','Synthetic SSTP','*')){
   $script:excluded=@($excluded)
   Rejected {IsoProfileRead $script:badName} 'iso_firewall_interface_exclusion_detected'
  }
  $script:missing=$true
  Rejected {IsoProfileRead $script:badName} 'iso_interface_exclusions_unreadable'
  $script:missing=$false;$script:excluded=@()
  Assert ((IsoProfileRead $n).name -ceq $n) 'empty exclusion set admitted'
  $script:excluded=@('NotConfigured','Ethernet')
  Rejected {IsoProfileRead $script:badName} 'iso_firewall_interface_exclusion_detected'
 }
}
$script:badStore='';$script:noActive=$true
Rejected {IsoProfileRead 'Public'} 'iso_profile_identity'
$script:noActive=$false;$script:badName='Public';$script:duplicate=$true
Rejected {IsoProfileRead 'Public'} 'iso_profile_identity'
$script:duplicate=$false
Rejected {IsoAssertNoExcludedInterfaces ([pscustomobject]@{DisabledInterfaceAliases=$null})} 'iso_interface_exclusions_unreadable'
# Match the native CIM typed-null representation without calling Windows APIs.
$typedEmpty=[pscustomobject]@{DisabledInterfaceAliases=$null;CimInstanceProperties=@{DisabledInterfaceAliases=[pscustomobject]@{CimType='StringArray';Value=$null}}}
IsoAssertNoExcludedInterfaces $typedEmpty;Assert $true 'typed CIM null is an empty exclusion list'
$wrongType=[pscustomobject]@{DisabledInterfaceAliases=$null;CimInstanceProperties=@{DisabledInterfaceAliases=[pscustomobject]@{CimType='String';Value=$null}}}
Rejected {IsoAssertNoExcludedInterfaces $wrongType} 'iso_interface_exclusions_unreadable'
$missingMeta=[pscustomobject]@{DisabledInterfaceAliases=$null;CimInstanceProperties=@{}}
Rejected {IsoAssertNoExcludedInterfaces $missingMeta} 'iso_interface_exclusions_unreadable'
$inconsistent=[pscustomobject]@{DisabledInterfaceAliases=$null;CimInstanceProperties=@{DisabledInterfaceAliases=[pscustomobject]@{CimType='StringArray';Value=@('Ethernet')}}}
Rejected {IsoAssertNoExcludedInterfaces $inconsistent} 'iso_interface_exclusions_unreadable'
$realExclusion=[pscustomobject]@{DisabledInterfaceAliases=@('Ethernet');CimInstanceProperties=$typedEmpty.CimInstanceProperties}
Rejected {IsoAssertNoExcludedInterfaces $realExclusion} 'iso_firewall_interface_exclusion_detected'
$notConfigured=[pscustomobject]@{DisabledInterfaceAliases=@('NotConfigured')}
IsoAssertNoExcludedInterfaces $notConfigured;Assert $true 'NotConfigured still accepted'
$script:typedNullActive=$true
foreach($profileName in @('Domain','Private','Public')){
 Assert ((IsoProfileRead $profileName).name -ceq $profileName) 'Persistent NotConfigured plus effective typed-null admitted'
}
$script:typedNullActive=$false
# Parse, but never execute, the worker entrypoint (no admin/firewall/task calls).
# Exercise its exact Restore statement block with fake operations and summary.
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'app/isolation-worker.ps1'),[ref]$tokens,[ref]$parseErrors)
Assert ($parseErrors.Count -eq 0) 'worker parses'
$ifs=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.IfStatementAst]},$true))
$clauses=@(foreach($i in $ifs){foreach($c in $i.Clauses){if($c.Item1.Extent.Text -ceq '$Mode -ceq ''Restore'' -and $null -ne $s'){$c.Item2}}})
Assert ($clauses.Count -eq 1) 'exact Restore branch extracted'
$restoreBlock=[scriptblock]::Create($clauses[0].Extent.Text.Trim().Substring(1,$clauses[0].Extent.Text.Trim().Length-2))
$script:events=@();$script:failRestore=$false;$script:failStop=$false
function IsoNativeOps{@{}}
function Restore-IsoSession{
 param($Session,$Ops)
 $script:events+=,'restore'
 if($script:failRestore){throw 'fixture_preflight_drift'}
 $Session.phase='restored';return $Session
}
function IsoTaskStop{
 param($Session)
 Assert ($Session.phase -ceq 'restored') 'task must outlive successful Restore'
 $script:events+=,'stop'
 if($script:failStop){throw 'fixture_stop_failed'}
}
function IsoSummary{param($Session)[pscustomobject]@{phase=$Session.phase}}
$Request=Join-Path ([IO.Path]::GetTempPath()) ('iso-hf1-'+[guid]::NewGuid().ToString('N')+'.json')
try{
 [IO.File]::WriteAllText($Request,'{"confirmation":"RESTORE ISOLATION"}')
 $s=[pscustomobject]@{phase='armed'};$result=$null;$started=$false
 . $restoreBlock
 Assert (($script:events -join ',') -ceq 'restore,stop') 'restore before task removal'
 Assert ($result.ok -and $s.phase -ceq 'restored') 'successful Restore result'
 $script:events=@();$script:failRestore=$true;$s=[pscustomobject]@{phase='armed'}
 Rejected {. $restoreBlock} 'fixture_preflight_drift'
 Assert (($script:events -join ',') -ceq 'restore') 'preflight failure never stops task'
 Assert ($s.phase -ceq 'armed') 'preflight failure preserves armed phase'
 $script:events=@();$script:failRestore=$false;$script:failStop=$true;$s=[pscustomobject]@{phase='armed'}
 Rejected {. $restoreBlock} 'fixture_stop_failed'
 Assert ($s.phase -ceq 'restored') 'task cleanup error does not undo completed Restore'
}finally{Remove-Item -LiteralPath $Request -Force}
$result=@{suite='isolation-hotfix-1-model';assertions=$script:checks;passed=$true;Windows_API_executed=$false;Windows_TaskScheduler_executed=$false;packet_leak_tested=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/isolation-hotfix-1-tests.json'),(ConvertTo-Json $result))
$result|ConvertTo-Json -Compress