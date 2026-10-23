param([string]$Helper,[string]$Exe,[string]$Work)
$ErrorActionPreference='Stop'
. $Helper
[void][IO.Directory]::CreateDirectory($Work)
if((Get-WLabExitClassification $null) -ne 'unknown'){throw 'null exit was not unknown'}
if((Get-WLabExitClassification '0') -ne 'unknown'){throw 'string exit was accepted as int'}
if((Get-WLabExitClassification ([int]0)) -ne 'succeeded'){throw 'zero exit failed'}
if((Get-WLabExitClassification ([int]7)) -ne 'failed'){throw 'nonzero exit succeeded'}
$checks=@(Invoke-WLabChildSelfTest $Exe $Work)
$fast=0
foreach($i in 0..7){
$expected=if(($i%2) -eq 0){0}else{7}
$job=Start-WLabChild $Exe @('--child-probe',([string]$expected)) (Join-Path $Work ('fast-'+$i))
if(!$job.Process.WaitForExit(5000)){throw 'fast child did not exit'}
$r=Complete-WLabChild $job
if($r.exit_code -ne $expected -or !$r.native_handle_acquired -or !$r.stdio_drained){throw ('fast exit/log mismatch: '+$i)}
$r2=Complete-WLabChild $job
if($r2.exit_code -ne $expected -or !(Test-WLabChildExited $job)){throw 'cached result was not reusable after Process.Dispose'}
$fast++
}
[pscustomobject]@{platform='PowerShell on current test OS';null_classified_unknown=$true;string_zero_classified_unknown=$true;actual_zero_and_nonzero_selftests=$checks;fast_exit_children_verified=$fast;result_reuse_after_cleanup=$true;windows_runtime_tested=$IsWindows}|ConvertTo-Json -Depth 8
