param([string]$OutputDirectory=(Join-Path $PSScriptRoot '../evidence'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../src/Transaction.ps1')
$work=Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) ('mock-runs-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $work
$script:Checks=0;$script:Cases=New-Object Collections.ArrayList
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw ('test_failed: '+$Name)};$script:Checks++}
function Reject([scriptblock]$Body,[string]$Name){$threw=$false;try{& $Body|Out-Null}catch{$threw=$true};Check $threw $Name}
function MockSave($State){
 $tmp=Join-Path $script:MockRoot ('mock-'+[guid]::NewGuid().ToString('N')+'.tmp');$file=Join-Path $script:MockRoot 'mock-resources.json'
 $bytes=[Text.Encoding]::UTF8.GetBytes((TxJson $State));$f=[IO.File]::Open($tmp,'CreateNew','Write','None')
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 if([IO.File]::Exists($file)){[IO.File]::Replace($tmp,$file,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$file)}
}
function MockLoad {ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $script:MockRoot 'mock-resources.json')))}
function MockRead([string]$Key){$s=MockLoad;return $s.PSObject.Properties[$Key].Value}
function MockCAS([string]$Key,$Expected,$Target){
 $s=MockLoad;$current=$s.PSObject.Properties[$Key].Value
 if(-not (TxEqual $current $Expected)){throw 'mock_cas_conflict'}
 $s.PSObject.Properties[$Key].Value=TxClone $Target;MockSave $s
}
$read={param($key) MockRead $key};$write={param($key,$expected,$target) MockCAS $key $expected $target}
$initial=[pscustomobject][ordered]@{
 'profile/Domain'=[pscustomobject][ordered]@{Name='Domain';DefaultOutboundAction='NotConfigured';Enabled='True'}
 'profile/Private'=[pscustomobject][ordered]@{Name='Private';DefaultOutboundAction='NotConfigured';Enabled='True'}
 'profile/Public'=[pscustomobject][ordered]@{Name='Public';DefaultOutboundAction='NotConfigured';Enabled='True'}
 'rule/allow-a'=[pscustomobject][ordered]@{Name='allow-a';Enabled='True';Action='Allow';RemoteAddress=@('Any');Program='C:\app-a.exe'}
 'rule/allow-b'=[pscustomobject][ordered]@{Name='allow-b';Enabled='True';Action='Allow';RemoteAddress=@('8.8.8.8');Program='Any'}
 'rule/owned-block'=[pscustomobject][ordered]@{exists=$false;image=$null}
 'rule/foreign-block'=[pscustomobject][ordered]@{Name='foreign-block';Enabled='True';Action='Block';Program='C:\other.exe'}
}
$ops=@()
foreach($key in @('profile/Domain','profile/Private','profile/Public','rule/allow-a','rule/allow-b','rule/owned-block')){
 $before=TxClone $initial.PSObject.Properties[$key].Value;$after=TxClone $before
 if($key.StartsWith('profile/')){$after.DefaultOutboundAction='Block'}
 elseif($key -ceq 'rule/owned-block'){$after.exists=$true;$after.image=[pscustomobject][ordered]@{Name='owned-block';Enabled='True';Action='Block';RemoteAddress=@('8.8.8.0/24')}}
 else{$after.Enabled='False'}
 $ops+=,[pscustomobject][ordered]@{key=$key;before=$before;after=$after}
}
function Setup([string]$Name){
 $script:MockRoot=Join-Path $work $Name;$null=New-Item -ItemType Directory -Path $script:MockRoot
 MockSave (TxClone $initial)
}
function ExpectOriginal([string]$Name){
 Check (TxEqual (MockLoad) $initial) $Name
 # Persisted file read, not the engine's in-memory state.
 foreach($key in @('profile/Domain','profile/Private','profile/Public')){Check ((MockRead $key).DefaultOutboundAction -ceq 'NotConfigured') ($Name+'-exact-default')}
 Check (TxEqual (MockRead 'rule/foreign-block') $initial.'rule/foreign-block') ($Name+'-unrelated-block')
}
Setup 'normal';$script:Events=New-Object Collections.ArrayList
$recordHook={param($name) $null=$script:Events.Add($name)}
NewMockableTransaction $script:MockRoot $ops $recordHook
InvokeMockableTransaction $script:MockRoot $read $write $recordHook
$applyEvents=@($script:Events.ToArray());Check ((TxRead $script:MockRoot).phase -ceq 'applied') 'normal-applied'
Reject {InvokeMockableTransaction $script:MockRoot $read $write} 'reapply-rejected'
$script:Events.Clear();$null=RestoreMockableTransaction $script:MockRoot $read $write $recordHook
$restoreEvents=@($script:Events.ToArray());ExpectOriginal 'normal-restored'
$null=RestoreMockableTransaction $script:MockRoot $read $write;ExpectOriginal 'idempotent-restore'
# Fault injection simulates abrupt loss of control after every exposed persistence
# and mock-mutation boundary. Finally releases test locks; this is NOT an OS kill.
for($cut=1;$cut -le $applyEvents.Count;$cut++){
 Setup ('apply-cut-'+$cut);$script:Seen=0;$script:Cut=$cut
 $hook={param($name) $script:Seen++;if($script:Seen -eq $script:Cut){throw 'simulated_crash'}}
 $crashed=$false
 try{NewMockableTransaction $script:MockRoot $ops $hook;InvokeMockableTransaction $script:MockRoot $read $write $hook}catch{if($_.Exception.Message -cne 'simulated_crash'){throw};$crashed=$true}
 Check $crashed ('apply-cut-hit-'+$cut)
 $null=RestoreMockableTransaction $script:MockRoot $read $write
 ExpectOriginal ('apply-cut-restored-'+$cut)
 $null=$script:Cases.Add([pscustomobject]@{stage='apply';cut=$cut;checkpoint=$applyEvents[$cut-1];passed=$true})
}
for($cut=1;$cut -le $restoreEvents.Count;$cut++){
 Setup ('restore-cut-'+$cut);NewMockableTransaction $script:MockRoot $ops;InvokeMockableTransaction $script:MockRoot $read $write
 $script:Seen=0;$script:Cut=$cut
 $hook={param($name) $script:Seen++;if($script:Seen -eq $script:Cut){throw 'simulated_crash'}}
 $crashed=$false
 try{$null=RestoreMockableTransaction $script:MockRoot $read $write $hook}catch{if($_.Exception.Message -cne 'simulated_crash'){throw};$crashed=$true}
 Check $crashed ('restore-cut-hit-'+$cut)
 $null=RestoreMockableTransaction $script:MockRoot $read $write;ExpectOriginal ('restore-cut-recovered-'+$cut)
 $null=$script:Cases.Add([pscustomobject]@{stage='restore';cut=$cut;checkpoint=$restoreEvents[$cut-1];passed=$true})
}
Setup 'external-conflict';NewMockableTransaction $script:MockRoot $ops;InvokeMockableTransaction $script:MockRoot $read $write
$external=TxClone (MockRead 'rule/allow-b');$external.Program='C:\changed-by-other.exe';MockCAS 'rule/allow-b' (MockRead 'rule/allow-b') $external
Reject {RestoreMockableTransaction $script:MockRoot $read $write} 'external-restore-conflict'
Check (TxEqual (MockRead 'rule/allow-b') $external) 'external-change-not-overwritten'
Setup 'no-intent';NewMockableTransaction $script:MockRoot $ops
$external=TxClone $ops[0].after;MockCAS $ops[0].key $ops[0].before $external
$null=RestoreMockableTransaction $script:MockRoot $read $write
Check (TxEqual (MockRead $ops[0].key) $external) 'no-intent-no-rollback'
Setup 'apply-conflict';NewMockableTransaction $script:MockRoot $ops
$external=TxClone (MockRead 'profile/Domain');$external.Enabled='False';MockCAS 'profile/Domain' (MockRead 'profile/Domain') $external
Reject {InvokeMockableTransaction $script:MockRoot $read $write} 'apply-conflict'
Check (TxEqual (MockRead 'profile/Domain') $external) 'apply-conflict-no-write'
Setup 'tamper';NewMockableTransaction $script:MockRoot $ops
$file=Join-Path $script:MockRoot 'transaction.json';$envelope=ConvertFrom-Json ([IO.File]::ReadAllText($file));$envelope.payload=$envelope.payload.Replace('NotConfigured','Allow');[IO.File]::WriteAllText($file,(TxJson $envelope))
Reject {RestoreMockableTransaction $script:MockRoot $read $write} 'tampered-journal-rejected';ExpectOriginal 'tamper-no-mutation'
Setup 'lock';$lock=TxLock $script:MockRoot
try{Reject {NewMockableTransaction $script:MockRoot $ops} 'exclusive-lock'}finally{$lock.Dispose()}
Setup 'single-operation';NewMockableTransaction $script:MockRoot @($ops[0]);InvokeMockableTransaction $script:MockRoot $read $write;$null=RestoreMockableTransaction $script:MockRoot $read $write;ExpectOriginal 'single-operation'
Reject {TxValidateOperations @($ops[0],$ops[0])} 'duplicate-key'
$result=[pscustomobject]@{suite='file-backed-mock-transaction';passed=$true;assertions=$script:Checks;apply_fault_boundaries=$applyEvents.Count;restore_fault_boundaries=$restoreEvents.Count;cases=@($script:Cases.ToArray());runtime=$PSVersionTable.PSVersion.ToString();backend='local JSON mock; NOT Windows firewall';failure_method='exceptions at checkpoint boundaries; NOT OS process termination or power loss';windows_apply_tested=$false;windows_restore_tested=$false}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'transaction-tests.json'),(ConvertTo-Json $result -Depth 10))
# Keep representative mock resources + journal, not all repetitive fixtures.
Copy-Item (Join-Path $work 'normal/transaction.json') (Join-Path $OutputDirectory 'example-mock-journal.json')
Copy-Item (Join-Path $work 'normal/mock-resources.json') (Join-Path $OutputDirectory 'example-mock-restored-resources.json')
Remove-Item -LiteralPath $work -Recurse -Force
[pscustomobject]@{passed=$true;assertions=$script:Checks;apply_fault_boundaries=$applyEvents.Count;restore_fault_boundaries=$restoreEvents.Count}|ConvertTo-Json -Compress
