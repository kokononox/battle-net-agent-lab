$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$root='/data/ufw-journal-storage-test-v011';$oldRoot='/data/ufw-journal-storage-test-v01/package/UFW-JOURNAL-STORAGE-01';$newRoot=Join-Path $root 'package/UFW-JOURNAL-STORAGE-011'
$m=Import-Module (Join-Path $newRoot 'Ufw.SessionJournal.psm1') -Force -PassThru
$script:checks=0;$script:shimArrayCalls=0
function Check-Compat($b,$label){$script:checks++;if(-not $b){throw $label}}
# Model the WinPS5.1 JSON ARRAY output contract. Object parsing is unchanged.
# This is a PS7 regression shim, NOT an execution of Windows PowerShell.
function global:ConvertFrom-Json {
 [CmdletBinding()]param([Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)][string]$InputObject)
 process{
  if($InputObject.TrimStart().StartsWith('[')){
   $script:shimArrayCalls++;$value=@(Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject)
   Write-Output -NoEnumerate $value
  }else{Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject}
 }
}
$probe=@(ConvertFrom-Json -InputObject '[{"a":1},{"a":2},{"a":3}]')
Check-Compat ($probe.Count -eq 1 -and $probe[0] -is [array] -and $probe[0].Count -eq 3) 'shim actually emits a nested array to array-expression consumers'
$base=Join-Path ([IO.Path]::GetTempPath()) ('ufw-compat-test-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($base);$script:modelBase=$base
try{
 . (Join-Path $oldRoot 'StorageFixture.ps1')
 function Assert-UfwStorageFixturePlatform {}
 function Get-UfwStorageFixtureBase {return $script:modelBase}
 $old=Invoke-UfwJournalStorageFixture $m
 Check-Compat (-not $old.completed -and $old.stage -ceq 'append_and_memory_recovery' -and $old.code -ceq 'ufw_core_profile_coverage') 'old fixture reproduces the exact user failure under PS51 array contract'
 Check-Compat ($old.initial_roundtrip_verified -and $old.exclusive_lock_verified -and $old.cleanup_completed) 'old fixture fails after successful storage checks and cleans up'
 Check-Compat (-not $old.native_Windows_file_API_executed) 'reproduction does not claim native Windows execution'
 $before=$script:shimArrayCalls
 . (Join-Path $newRoot 'StorageFixture.ps1')
 function Assert-UfwStorageFixturePlatform {}
 function Get-UfwStorageFixtureBase {return $script:modelBase}
 $new=Invoke-UfwJournalStorageFixture $m
 Check-Compat ($new.completed -and $new.cleanup_completed -and $new.checkpoint_count -eq 11) 'row-wise clone completes under same PS51 array contract'
 Check-Compat ($new.memory_profile_recovery_with_file_checkpoints_verified -and $new.partial_record_refused -and $new.checksum_corruption_refused) 'corrected fixture reaches later tests'
 Check-Compat ($script:shimArrayCalls -eq $before) 'new fixture parses JSON objects only, never a top-level JSON array'
 Check-Compat (@(Get-ChildItem $base -Force).Count -eq 0) 'both fixtures cleaned their owned directories'
 Check-Compat (-not $new.profile_query_requested -and -not $new.firewall_change_requested -and -not $new.real_legacy_journal_access_requested -and -not $new.real_preparation_record_created) 'scope unchanged'
 $code=[IO.File]::ReadAllText((Join-Path $newRoot 'StorageFixture.ps1'));Check-Compat ($code.Contains('foreach($row in $script:StorageFixture.rows)') -and -not $code.Contains('ConvertTo-Json -InputObject $script:StorageFixture.rows')) 'fix is at fixture clone boundary'
 $result=[ordered]@{suite='WinPS51-top-level-JSON-array-contract-regression-011';passed=$true;assertions=$script:checks;old_fixture_exact_failure_reproduced=$true;new_fixture_passed_same_shim=$true;top_level_array_clone_removed=$true;native_Windows_PowerShell_executed=$false;production_modules_modified=$false;ready_for_apply=$false}
 $result|ConvertTo-Json|Set-Content (Join-Path $root 'PS51-COMPAT-RESULTS.json') -Encoding UTF8;$result|ConvertTo-Json -Compress
}finally{
 Remove-Item Function:\ConvertFrom-Json -ErrorAction SilentlyContinue
 if([IO.Directory]::Exists($base)){Remove-Item -LiteralPath $base -Recurse -Force}
}
