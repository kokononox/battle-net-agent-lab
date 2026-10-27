$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$report=[ordered]@{schema='normal-exit-review-diagnostic-01';diagnostic_completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;payload_verified=$false;storage_qualification=$null;live_review=$null;real_legacy_journal_preserved=$false;live_record_write_status='not_requested';firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;credentials_read=$false;raw_identity_exported=$false;controller_upgrade_requested=$false;original_restore_verified=$false;reboot_qualified=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$legacyPath=$null;$legacyHash=$null;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);$p=$root
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'exit_runner_local_folder_required'};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
 if($root.StartsWith('\')){throw 'exit_runner_local_folder_required'}
 $dest=Join-Path $root ('NORMAL-EXIT-REVIEW-01-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'exit_runner_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'exit_runner_ps51_64bit_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'exit_runner_administrator_required'}
 $report.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "session-core.ps1": "a1607e3100734eb4c2fa8e820a6eb95ed759bfd5dee20e4a454e7544f53357c3",
  "native.ps1": "750e8c9a72411a4b22702815cf15b88e12658cc00be4965d07e4a00f74c86ef5",
  "isolation-core.ps1": "f2e9645558845911472f37627cac2277b3031de4025b957c8346dc7a676181ed",
  "isolation-native.ps1": "d851e408a06c43cbd20e97d3a973f477e25b7ef27fc2f3c6666ad9a78838fc6c",
  "normal-exit-record.ps1": "398b1fe8d002e6f08ff4830ac18cea87e9d8bbe654cc54d8c4a5c8d6b8c187cc",
  "Qualification.ps1": "6beec8bc58b9b46a7f69d847fdfe6f94b56c354a43d05952403805a270ea0d6b"
}
'@
 foreach($item in $hashes.PSObject.Properties){$f=Join-Path $root $item.Name;if(([IO.File]::GetAttributes($f) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $item.Value){throw 'exit_runner_payload_mismatch'}}
 $report.payload_verified=$true
 foreach($name in @('session-core.ps1','native.ps1','isolation-core.ps1','isolation-native.ps1','normal-exit-record.ps1','Qualification.ps1')){. (Join-Path $root $name)}
 $report.stage='legacy_read_guard';$privateRoot=IsoSecureRoot $false
 if(-not [IO.Directory]::Exists($privateRoot)){throw 'exit_runner_existing_legacy_root_required'}
 $legacyPath=Join-Path $privateRoot 'session.json';UAssertPath $legacyPath
 $legacyHash=(Get-FileHash -LiteralPath $legacyPath -Algorithm SHA256).Hash
 Write-Host 'No firewall, VPN, DNS, route, rule, task, controller or legacy-journal change will be requested.'
 Write-Host 'First: private-file/lock qualification in a disposable synthetic ProgramData folder.'
 $report.stage='separate_storage_qualification';$report.storage_qualification=Invoke-ExitStorageQualification
 if(-not $report.storage_qualification.completed -or -not $report.storage_qualification.cleanup_completed){throw 'exit_runner_storage_qualification_failed'}
 Write-Host 'Separate fixture storage qualification passed and fixture folder removed.'
 Write-Host 'Now reading real legacy state. Full before-image checks may take time; do not repeat the command.'
 $report.stage='real_review_and_optional_record';$report.live_review=Invoke-ExitReviewAndConsent
 if($report.live_review.record_operation_attempted){$report.live_record_write_status='attempted_inspect_protected_record_if_failed'}
 if($report.live_review.normal_mode_acknowledgment_recorded){$report.live_record_write_status='created_or_revalidated_after_explicit_consent'}
 if(-not $report.live_review.completed){throw 'exit_runner_live_review_not_completed'}
 $report.diagnostic_completed=$true;$report.stage='completed';$report.code=$report.live_review.code;$rc=0
}catch{
 $m=[string]$_.Exception.GetBaseException().Message
 if($m -cmatch '^(exit_runner|normal_exit|iso|unsafe_journal|session)_[a-z_0-9]{1,100}$'){$report.code=$m}else{$report.code='exit_runner_unavailable'}
 Write-Host ('Stopped at '+$report.stage+': '+$report.code)
}finally{
 if($null -ne $legacyPath -and $null -ne $legacyHash){try{
  UAssertPath $legacyPath
  $report.real_legacy_journal_preserved=((Get-FileHash -LiteralPath $legacyPath -Algorithm SHA256).Hash -ceq $legacyHash)
  if(-not $report.real_legacy_journal_preserved){$report.diagnostic_completed=$false;$report.code='exit_runner_legacy_journal_changed_during_run';$rc=1}
 }catch{$report.diagnostic_completed=$false;$report.code='exit_runner_legacy_journal_preservation_unavailable';$rc=1}}
 if($null -ne $dest){try{
  $bytes=[Text.Encoding]::UTF8.GetBytes(($report|ConvertTo-Json -Depth 24));$stream=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  Write-Host ('Report: '+$dest)
 }catch{Write-Host 'Report could not be saved. Send only the stage/code text.';$rc=1}}
 Write-Host 'Return only the new NORMAL-EXIT-REVIEW-01-*.json file, including cancel/failure. Do not send protected files.'
 Write-Host 'This is NOT an isolation Apply, original Restore qualification, reboot test, or no-leak certificate.'
}
exit $rc
