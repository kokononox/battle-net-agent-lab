param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('test_failed: '+$Name)};$script:checks++}
function Throws([scriptblock]$Body,[string]$Pattern){$failed=$false;try{& $Body|Out-Null}catch{$failed=([string]$_.Exception.Message -match $Pattern)};Check $failed $Pattern}
. (Join-Path $Root 'app/audit-model.ps1')
# Local model mocks only; native policy/ACL/privileges are never invoked on this Linux host.
function UAssertPath([string]$Path){}
function UJson($Value){ConvertTo-Json -Depth 16 -InputObject $Value}
function UWritePrivateBytes([string]$Path,[byte[]]$Bytes){$f=[IO.File]::Open($Path,'CreateNew','Write','None');try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('audit-model-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
$enable='ENABLE BLOCKED CONNECTION LOGGING';$restore='RESTORE PREVIOUS AUDIT POLICY'
$read={ $script:flags };$write={param([int]$Value) $r=Read-AuditReceipt $script:folder;Check ($null -ne $r -and $r.phase -in @('prepared','restoring')) 'receipt-before-policy-write';$script:flags=$Value;$script:writes++ }
function Reset([int]$Flags){$script:folder=Join-Path $temp ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $script:folder;$script:flags=$Flags;$script:writes=0}
try{
 Reset 4
 Throws {Invoke-AuditPolicy $folder 'enable' '' $read $write} 'consent'
 Throws {Invoke-AuditPolicy $folder 'restore' '' $read $write} 'consent'
 Check ($script:writes -eq 0 -and -not (Test-Path (Join-Path $folder 'audit-state.json'))) 'no-consent-no-state'
 Throws {Invoke-AuditPolicy $folder 'arbitrary' '' $read $write} 'audit_action'
 Throws {Audit-Flags 7} 'unsupported';Check ((Audit-Flags 0) -eq 4) 'none-normalization'
 $s=Invoke-AuditPolicy $folder 'status' '' $read $write;Check (-not $s.failure_enabled -and -not $s.changed -and $null -eq $s.receipt) 'status-read-only'
 $s=Invoke-AuditPolicy $folder 'enable' $enable $read $write;Check ($s.failure_enabled -and $s.changed -and $flags -eq 2 -and $writes -eq 1) 'none-to-failure'
 Check ($s.receipt.before -eq 4 -and $s.receipt.after -eq 2 -and $s.receipt.phase -ceq 'enabled') 'sealed-recovery-data'
 Check (-not $s.automatic_restore -and -not $s.firewall_changed -and -not $s.hosts_changed -and -not $s.coverage_verified) 'no-excess-claims'
 Throws {Invoke-AuditPolicy $folder 'enable' $enable $read $write} 'no_blind_retry'
 $s=Invoke-AuditPolicy $folder 'restore' $restore $read $write;Check ($flags -eq 4 -and $s.receipt.phase -ceq 'restored') 'restore-before'
 $count=$writes;$s=Invoke-AuditPolicy $folder 'restore' $restore $read $write;Check ($writes -eq $count -and -not $s.changed) 'restore-idempotent'
 $s=Invoke-AuditPolicy $folder 'enable' $enable $read $write;Check (@(Get-ChildItem $folder -Filter 'restored-*.json').Count -eq 1) 'previous-restored-receipt-archived'
 Reset 1;$s=Invoke-AuditPolicy $folder 'enable' $enable $read $write;Check ($flags -eq 3 -and $s.success_enabled) 'success-preserved'
 $s=Invoke-AuditPolicy $folder 'restore' $restore $read $write;Check ($flags -eq 1 -and $s.success_enabled -and -not $s.failure_enabled) 'restore-preserves-original-success'
 foreach($f in @(2,3)){
  Reset $f;$s=Invoke-AuditPolicy $folder 'enable' $enable $read $write;Check (-not $s.changed -and $writes -eq 0 -and $null -eq $s.receipt) 'preexisting-failure-not-adopted'
  Throws {Invoke-AuditPolicy $folder 'restore' $restore $read $write} 'no_owned_receipt'
 }
 Reset 4
 Throws {Invoke-AuditPolicy $folder 'enable' $enable $read {param($v) $script:flags=$v;throw 'mock_crash_after_write'}} 'mock_crash'
 Check ((Read-AuditReceipt $folder).phase -ceq 'prepared' -and $flags -eq 2) 'crash-receipt-retained'
 $s=Invoke-AuditPolicy $folder 'status' '' $read $write;Check ($s.failure_enabled -and -not $s.changed) 'status-after-crash'
 $s=Invoke-AuditPolicy $folder 'restore' $restore $read $write;Check ($flags -eq 4) 'recover-crash'
 Reset 4
 Throws {Invoke-AuditPolicy $folder 'enable' $enable $read {param($v)throw 'mock_failure_before_write'}} 'mock_failure'
 $s=Invoke-AuditPolicy $folder 'restore' $restore $read $write;Check ($writes -eq 0 -and $s.receipt.phase -ceq 'restored') 'prepared-before-value-no-policy-write'
 Reset 4;$null=Invoke-AuditPolicy $folder 'enable' $enable $read $write;$script:flags=3
 Throws {Invoke-AuditPolicy $folder 'restore' $restore $read $write} 'drift';Check ($flags -eq 3 -and $writes -eq 1) 'drift-not-overwritten'
 Reset 4
 Throws {Invoke-AuditPolicy $folder 'enable' $enable $read {param($v)$script:flags=1}} 'readback_conflict'
 Check ((Read-AuditReceipt $folder).phase -ceq 'prepared') 'readback-conflict-retains-receipt'
 Reset 4;$script:reads=0
 Throws {Invoke-AuditPolicy $folder 'enable' $enable {$script:reads++;if($script:reads -eq 1){4}else{1}} $write} 'changed_before_enable'
 Check ($writes -eq 0) 'race-before-enable-no-write'
 Reset 4;$null=Invoke-AuditPolicy $folder 'enable' $enable $read $write;$script:reads=0
 Throws {Invoke-AuditPolicy $folder 'restore' $restore {$script:reads++;if($script:reads -eq 1){2}else{3}} $write} 'changed_before_restore'
 Check ($writes -eq 1 -and (Read-AuditReceipt $folder).phase -ceq 'restoring') 'restore-race-no-extra-write'
 Reset 4;$null=Invoke-AuditPolicy $folder 'enable' $enable $read $write
 Throws {Invoke-AuditPolicy $folder 'restore' $restore $read {param($v)$script:flags=3}} 'restore_readback_conflict'
 Check ((Read-AuditReceipt $folder).phase -ceq 'restoring') 'restore-conflict-recoverable'
 [IO.File]::WriteAllText((Join-Path $folder 'audit-state.json'),'{}');Throws {Read-AuditReceipt $folder} 'schema|property|audit_receipt_invalid'
 Add-Type -Path (Join-Path $Root 'app/audit-native.cs')
 $t=[UnifiedAudit096.Native+Policy];Check ([Runtime.InteropServices.Marshal]::SizeOf($t::new()) -eq 36) 'native-policy-layout-36'
 Check ([Runtime.InteropServices.Marshal]::OffsetOf($t,'Flags').ToInt32() -eq 16) 'flags-offset'
 Check ([Runtime.InteropServices.Marshal]::OffsetOf($t,'Category').ToInt32() -eq 20) 'category-offset'
 Check ([UnifiedAudit096.Native]::Subcategory.ToString() -ceq '0cce9226-69ae-11d9-bed3-505054503030') 'fixed-subcategory'
}catch{$_.ScriptStackTrace|Write-Host;throw}finally{Remove-Item $temp -Recurse -Force}
$result=@{suite='audit-policy';passed=$true;assertions=$script:checks;Windows_Audit_API_executed=$false;Windows_ACL_executed=$false;environment='PowerShell 7 Linux; transaction mocks and C# compile/layout only'}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/audit-policy-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
