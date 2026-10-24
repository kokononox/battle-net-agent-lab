param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'experimental/Transaction.ps1')
$fixture=ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $Root 'evidence/compiled-mock-fixture.json')))
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('unified-mock-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $scratch
$script:checks=0
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw ('test_failed: '+$Name)};$script:checks++}
$script:resources=Join-Path $scratch 'resources.json'
function ReadMockState {ConvertFrom-Json ([IO.File]::ReadAllText($script:resources))}
function WriteMockState($s){[IO.File]::WriteAllText($script:resources,(TxJson $s))}
function ReadMockRule($key){$s=ReadMockState;return $s.PSObject.Properties[$key].Value}
function CasMockRule($key,$expected,$target){$s=ReadMockState;if(-not (TxEqual $s.PSObject.Properties[$key].Value $expected)){throw 'mock_conflict'};$s.PSObject.Properties[$key].Value=TxClone $target;WriteMockState $s}
$read={param($key) ReadMockRule $key};$write={param($key,$expected,$target) CasMockRule $key $expected $target}
function BuildOps($Rules){
 $desired=@{};foreach($r in $Rules){$desired[$r.name]=[pscustomobject][ordered]@{exists=$true;image=$r}}
 $ops=@();$state=ReadMockState
 foreach($p in $state.PSObject.Properties){
  if($p.Name -ceq 'foreign-block'){continue}
  $after=[pscustomobject][ordered]@{exists=$false;image=$null};if($desired.ContainsKey($p.Name)){$after=$desired[$p.Name]}
  if(-not (TxEqual $p.Value $after)){$ops+=,[pscustomobject][ordered]@{key=$p.Name;before=$p.Value;after=$after}}
 }
 return ,$ops
}
function PresentCount([string]$Component){return @((ReadMockState).PSObject.Properties|Where-Object{$_.Name -cne 'foreign-block' -and $_.Value.exists -and $_.Value.image.component -ceq $Component}).Count}
try{
 $initial=[ordered]@{'foreign-block'=[pscustomobject]@{exists=$true;image=[pscustomobject]@{Name='untouched-foreign-block';Action='Block'}}}
 foreach($r in $fixture.initial.rules){$initial[$r.name]=[pscustomobject][ordered]@{exists=$false;image=$null}}
 WriteMockState ([pscustomobject]$initial);$foreign=TxClone (ReadMockRule 'foreign-block')
 $tx1=Join-Path $scratch 'tx1';$null=New-Item -ItemType Directory $tx1
 NewMockableTransaction $tx1 (BuildOps $fixture.initial.rules);InvokeMockableTransaction $tx1 $read $write
 Check ((PresentCount 'blacklist') -eq 2) 'both-exes-applied-to-mock'
 Check ((PresentCount 'whitelist') -eq 2) 'global-vpn-whitelist-preserved'
 $tx2=Join-Path $scratch 'tx2';$null=New-Item -ItemType Directory $tx2
 $ops=BuildOps $fixture.one_program_removed.rules
 Check ($ops.Count -eq 1) 'removing-one-exe-affects-one-rule'
 NewMockableTransaction $tx2 $ops;InvokeMockableTransaction $tx2 $read $write
 Check ((PresentCount 'blacklist') -eq 1) 'other-exe-rule-remains'
 Check ((PresentCount 'whitelist') -eq 2) 'remove-program-does-not-remove-whitelist'
 $null=RestoreMockableTransaction $tx2 $read $write
 Check ((PresentCount 'blacklist') -eq 2) 'undo-config-change-restores-only-own-before-image'
 $tx3=Join-Path $scratch 'tx3';$null=New-Item -ItemType Directory $tx3
 $ops=BuildOps $fixture.blacklist_removed.rules;Check ($ops.Count -eq 2) 'remove-blacklist-component-only'
 NewMockableTransaction $tx3 $ops;InvokeMockableTransaction $tx3 $read $write
 Check ((PresentCount 'blacklist') -eq 0) 'blacklist-component-removed'
 Check ((PresentCount 'whitelist') -eq 2) 'whitelist-not-removed-with-blacklist'
 Check (TxEqual (ReadMockRule 'foreign-block') $foreign) 'foreign-rule-not-touched'
 $null=RestoreMockableTransaction $tx1 $read $write
 Check ((PresentCount 'whitelist') -eq 0 -and (PresentCount 'blacklist') -eq 0) 'original-session-restore-to-exact-empty-owned-state'
 Check (TxEqual (ReadMockRule 'foreign-block') $foreign) 'foreign-rule-survives-full-restore'
 $result=[pscustomobject]@{suite='compiled-policy-to-mock-transaction';passed=$true;assertions=$script:checks;backend='local JSON mock only';windows_apply_tested=$false;windows_restore_tested=$false}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence/policy-transaction-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
}finally{Remove-Item -LiteralPath $scratch -Recurse -Force}
