param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1');. (Join-Path $Root 'lab/native.ps1');. '/data/hf121-readonly-parity/HF121-READONLY-PARITY/Bulk.ReadOnly.ps1'
$script:checks=0;function Assert($b,$m){$script:checks++;if(-not $b){throw $m}}
function Reject($b,$code){$caught=$false;try{& $b|Out-Null}catch{$caught=$_.Exception.Message -ceq $code};Assert $caught ('expected '+$code)}
function CimFixture($Values){
 $x=[pscustomobject]$Values;$properties=@(foreach($k in $Values.Keys){[pscustomobject]@{Name=$k;Value=$Values[$k]}})
 $x|Add-Member NoteProperty CimInstanceProperties $properties;return $x
}
$script:ruleRows=@();$script:filterRows=@();$script:calls=@{};$script:stores=@()
foreach($name in @('owned','name[*]?','Case','case')){
 $script:ruleRows+=,(CimFixture ([ordered]@{Name=$name;Enabled='2';PolicyStoreSourceType='Local'}))
 $script:filterRows+=,(CimFixture ([ordered]@{InstanceID=$name;Values=@('fixture','two');Nullable=$null}))
}
function Get-NetFirewallRule{param($PolicyStore,$ErrorAction)$script:calls.rules=1+$script:calls.rules;$script:stores+=,$PolicyStore;return $script:ruleRows}
$script:calls.rules=0
foreach($cmd in $script:UParts.Values){
 $script:calls[$cmd]=0
 $body="param(`$PolicyStore,`$ErrorAction) begin {`$script:calls['$cmd']++;`$script:stores+=,`$PolicyStore} end {return `$script:filterRows}"
 Set-Item ('Function:'+$cmd) ([scriptblock]::Create($body))
}
$snapshot=Read-IsoBulkSnapshot
Assert ($snapshot.rules.Count -eq 4) 'ordinal exact names retain case distinction'
foreach($name in @('owned','name[*]?','Case','case')){
 $image=Get-IsoBulkImage $snapshot $name
 $expected=[ordered]@{rule=(URaw @($script:ruleRows|Where-Object{$_.Name -ceq $name})[0])}
 foreach($part in $script:UParts.Keys){$expected[$part]=URaw @($script:filterRows|Where-Object{$_.InstanceID -ceq $name})[0]}
 Assert (UEqual $image ([pscustomobject]$expected)) ('raw parity '+$name)
}
Assert ($null -eq (Get-IsoBulkImage $snapshot 'absent')) 'no guessed match'
Assert ($null -eq (Get-IsoBulkImage $snapshot 'NAME[*]?')) 'ordinal matching'
Assert ($script:calls.rules -eq 1) 'one rule enumeration'
foreach($cmd in $script:UParts.Values){Assert ($script:calls[$cmd] -eq 1) ('one collection read '+$cmd)}
Assert ($script:stores.Count -eq 8 -and @($script:stores|Where-Object{$_ -cne 'PersistentStore'}).Count -eq 0) 'same explicit store for all reads'
Assert (-not $snapshot.atomic -and -not $snapshot.mutation_qualified) 'no atomic claim'
$snapshot.parts.port.Remove('owned')|Out-Null;Reject {Get-IsoBulkImage $snapshot 'owned'} 'filter_coverage'
$script:ruleRows+=,$script:ruleRows[0];Reject {Read-IsoBulkSnapshot} 'iso_bulk_duplicate_identity';$script:ruleRows=@($script:ruleRows|Select-Object -First 4)
$script:filterRows+=,$script:filterRows[0];Reject {Read-IsoBulkSnapshot} 'iso_bulk_duplicate_identity';$script:filterRows=@($script:filterRows|Select-Object -First 4)
Reject {IsoBulkIndex @([pscustomobject]@{Other='x'}) 'Name'} 'iso_bulk_missing_identity'
Reject {Read-IsoBulkSnapshot 'UntrustedStore'} 'iso_bulk_store'
$snapshot=Read-IsoBulkSnapshot 'ActiveStore';Assert ($snapshot.store -ceq 'ActiveStore') 'active store supported by mock'
$snapshot.rules['owned']=CimFixture ([ordered]@{Name='owned';PolicyStoreSourceType='GroupPolicy'})
Reject {Get-IsoBulkImage $snapshot 'owned'} 'not_local_rule'
# Changes to collections are not hidden by a reusable global cache.
$script:ruleRows=@();$new=Read-IsoBulkSnapshot;Assert ($new.rules.Count -eq 0) 'fresh invocation has fresh rules'
$result=@{suite='hf12-bulk-read-prototype';passed=$true;assertions=$script:checks;mocked_collection_calls_per_snapshot=8;Windows_API_executed=$false;timing_benchmark_performed=$false;integrated_into_controller=$false}
$result|ConvertTo-Json -Compress|Set-Content '/data/hf121-readonly-parity/bulk-regression.json';$result|ConvertTo-Json -Compress
