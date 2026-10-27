param([string]$Root=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'lab/session-core.ps1');. (Join-Path $Root 'lab/native.ps1');. (Join-Path $Root 'app/isolation-core.ps1');. (Join-Path $Root 'app/isolation-native.ps1')
$script:checks=0
function Assert($b,$m){$script:checks++;if(-not $b){throw $m}}
function Reject($b,$code){$caught=$false;try{& $b|Out-Null}catch{$caught=$_.Exception.Message -ceq $code};Assert $caught ('expected '+$code)}
function Rule($Name,$Enabled='True',$Source='Local'){
 # Adapted Name/Enabled/Action differ from native raw CIM representation.
 $values=[ordered]@{InstanceID=$Name;Enabled=$(if($Enabled -ceq 'True'){'1'}else{'2'});Direction='2';Action='2';PolicyStoreSourceType=$Source}
 [pscustomobject]@{Name=$Name;Enabled=$Enabled;Direction='Outbound';Action='Allow';PolicyStoreSourceType=$Source;CimInstanceProperties=@(foreach($key in $values.Keys){[pscustomobject]@{Name=$key;Value=$values[$key]}})}
}
function FilterFixture($Name){[pscustomobject]@{InstanceID=$Name;CimInstanceProperties=@([pscustomobject]@{Name='InstanceID';Value=$Name},[pscustomobject]@{Name='Values';Value=@('fixture-value')})}}
function Reset-Inventory([int]$Count=4){
 $script:persistent=@(foreach($n in 1..$Count){if($Count -gt 0){Rule ('rule-'+$n)}})
 $script:active=@($script:persistent);$script:filters=@(foreach($r in $script:persistent){FilterFixture $r.Name})
 $script:calls=@{PersistentStore=0;ActiveStore=0};foreach($cmd in $script:UParts.Values){$script:calls[$cmd]=0}
}
function Get-NetFirewallRule{param($PolicyStore,$ErrorAction)$script:calls[$PolicyStore]++;if($PolicyStore -ceq 'PersistentStore'){$script:persistent}else{$script:active}}
foreach($cmd in $script:UParts.Values){
 $body=@'
[CmdletBinding()]param([string]$PolicyStore,[Parameter(ValueFromPipeline=$true)]$InputObject)
process{
 $script:calls['__CMD__']++
 if($PSBoundParameters.ContainsKey('PolicyStore')){if($PolicyStore -cne 'PersistentStore'){throw 'unexpected_filter_store'};return $script:filters}
 else{return @($script:filters|Where-Object{$_.InstanceID -ceq $InputObject.Name})}
}
'@.Replace('__CMD__',$cmd)
 Set-Item ('Function:'+$cmd) ([scriptblock]::Create($body))
}
$empty=[pscustomobject]@{entries=@()}
Reset-Inventory 0;$a=IsoPrepareForeignAllows $empty;Assert ($a.Count -eq 0) 'empty array preserved'
Reset-Inventory 6;$legacy=IsoForeignAllows $empty
# Reset the call counters without changing data, then use real new preparation helper.
foreach($k in @($script:calls.Keys)){$script:calls[$k]=0}
$grouped=IsoPrepareForeignAllows $empty
Assert (UEqual $legacy $grouped) 'all selected before-images identical to original reader'
Assert ($grouped.Count -eq 6) 'all foreign not just a sample'
Assert ($script:calls.PersistentStore -eq 1 -and $script:calls.ActiveStore -eq 1) 'single inventory per store'
foreach($cmd in $script:UParts.Values){Assert ($script:calls[$cmd] -eq 1) ('one batch per filter '+$cmd)}
Assert ($null -eq $grouped[0].image.rule.PSObject.Properties['Name']) 'adapted name not invented in raw image'
Reset-Inventory 3;$script:active=@();$a=IsoPrepareForeignAllows $empty;Assert ($a.Count -eq 3) 'persistent not currently effective still included'
$own=[pscustomobject]@{entries=@([pscustomobject]@{name='rule-1';removed=$false})};$a=IsoPrepareForeignAllows $own
Assert ($a.Count -eq 2 -and @($a|Where-Object{$_.name -ceq 'rule-1'}).Count -eq 0) 'current owned exact excluded'
$own.entries[0].removed=$true;$a=IsoPrepareForeignAllows $own;Assert ($a.Count -eq 3) 'removed entries not adopted'
Reset-Inventory 2;$script:active+=,(Rule 'gpo' 'True' 'GroupPolicy');Reject {IsoPrepareForeignAllows $empty} 'iso_nonlocal_allow_cannot_quarantine_review_GPO'
Reset-Inventory 2;$script:active=@();$script:persistent[0]=Rule 'rule-1' 'True' 'GroupPolicy';Reject {IsoPrepareForeignAllows $empty} 'iso_nonlocal_allow_cannot_quarantine_review_GPO'
Reset-Inventory 2;$script:active+=,(Rule 'effective-only');Reject {IsoPrepareForeignAllows $empty} 'iso_effective_allow_not_mutable_locally'
Reset-Inventory 2;$script:persistent[0]=Rule 'rule-1' 'False';Reject {IsoPrepareForeignAllows $empty} 'iso_effective_allow_not_mutable_locally'
Reset-Inventory 2;$script:filters=@($script:filters|Where-Object{$_.InstanceID -cne 'rule-1'});Reject {IsoPrepareForeignAllows $empty} 'filter_coverage'
Reset-Inventory 2;$script:filters+=,$script:filters[0];Reject {IsoPrepareForeignAllows $empty} 'iso_bulk_duplicate_identity'
Reset-Inventory 2;$script:persistent+=,$script:persistent[0];Reject {IsoPrepareForeignAllows $empty} 'iso_bulk_duplicate_identity'
Reset-Inventory 2;$script:persistent[0].CimInstanceProperties|Where-Object{$_.Name -ceq 'Enabled'}|ForEach-Object{$_.Value='2'}
Reject {IsoPrepareForeignAllows $empty} 'iso_effective_allow_not_mutable_locally'
Reset-Inventory 0;$script:persistent=@((Rule 'Case'),(Rule 'case'));$script:active=@();$script:filters=@((FilterFixture 'Case'),(FilterFixture 'case'))
Reject {IsoPrepareForeignAllows $empty} 'iso_duplicate_active_allow'
# Snapshot lifetime is one preparation call: fresh collection data next time.
Reset-Inventory 2;$a=IsoPrepareForeignAllows $empty;$script:filters[0].CimInstanceProperties[1].Value=@('changed');$b=IsoPrepareForeignAllows $empty
Assert (-not (UEqual $a[0].image $b[0].image)) 'no stale cache across preparations'
# Original mutation-side fresh read rejects a plan whose filter changed since Prepare.
$session=[pscustomobject]@{foreign=@()};$script:writes=0;$ops=IsoNativeOps
$ops.Save={param($s)$script:writes++};$ops.Disable={param($n)$script:writes++}
Reject {IsoQuarantine $session $a $ops} 'iso_foreign_drift_before_disable'
Assert ($script:writes -eq 0) 'no checkpoint or firewall write when fresh pre-mutation read detects drift'
# Rule limit checked without admitting any wider image on overflow.
Reset-Inventory 2049;Reject {IsoPrepareForeignAllows $empty} 'iso_foreign_allow_limit'
# Verify actual compiler dispatch, while isolating network detection and profile adapters only.
Reset-Inventory 2
function IsoAssertNoOtherEngine{param($s)@{}}
function IsoProfileRead{param($n)[pscustomobject]@{name=$n;enabled='True';default_outbound='Allow';allow_local_rules='True'}}
# Security-filter command already mocked; fixture has no .OverrideBlockRules. Override only this collection for compiler bypass scan.
$script:originalSecurity=(Get-Command Get-NetFirewallSecurityFilter).ScriptBlock
function Get-NetFirewallSecurityFilter{
 [CmdletBinding()]param([string]$PolicyStore,[Parameter(ValueFromPipeline=$true)]$InputObject)
 process{if($PolicyStore -ceq 'ActiveStore'){return @()};$script:calls['Get-NetFirewallSecurityFilter']++;return $script:filters}
}
$policy=[pscustomobject]@{schema='unified-isolation-policy-1';owner=('a'*32);connection='direct';whitelist=@([pscustomobject]@{remote_addresses=@('192.0.2.10');protocol='TCP';remote_port='443'})}
$p=IsoPrepare $policy $null;Assert ($p.foreign.Count -eq 2) 'actual Prepare uses bulk helper'
Assert ($p.rules.Count -eq 1 -and -not $p.no_leak_certified) 'policy scope and no-leak flag unchanged'
# No new snapshot route in the existing mutation adapter / live verifier.
foreach($name in @('IsoNativeOps','IsoVerify','IsoForeignAllows')){
 $body=(Get-Command $name).ScriptBlock.ToString()
 Assert ($body -notmatch 'Read-IsoBulkSnapshot|Get-IsoBulkImage|IsoPrepareForeignAllows') ('fresh live path unchanged '+$name)
}
$result=@{suite='prepare-only-bulk-integration';passed=$true;assertions=$script:checks;mocked_planning_collection_calls=9;windows_API_executed=$false;timing_benchmark_performed=$false;mutation_side_fresh_read_tested=$true}
$result|ConvertTo-Json|Set-Content (Join-Path $Root 'evidence/prepare-bulk-tests.json');$result|ConvertTo-Json -Compress
