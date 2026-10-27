param([string]$Root='/data/ufw-journal-storage-test-v011/package/UFW-JOURNAL-STORAGE-011')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'StorageFixture.ps1')
$m=Import-Module (Join-Path $Root 'Ufw.SessionJournal.psm1') -Force -PassThru
$script:checks=0
function Check-Fixture($b,$label){$script:checks++;if(-not $b){throw $label}}
# Real platform guard must stop before storage calls on Linux.
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){$r=Invoke-UfwJournalStorageFixture $m;Check-Fixture (-not $r.completed -and $r.code -ceq 'ufw_fixture_windows_required' -and -not $r.native_Windows_file_API_executed) 'real platform guard'}
# Observe accidental calls to real preparation/profile APIs as test failures.
& $m {
 $script:forbiddenCalls=0
 function script:Save-UfwNativePreparation {param($Receipt,$Draft)$script:forbiddenCalls++;throw 'ufw_fixture_unexpected_real_store'}
 function script:Invoke-UfwPreparationConsentCallbacks {param($Ops)$script:forbiddenCalls++;throw 'ufw_fixture_unexpected_real_consent'}
 & $script:Core {function script:Invoke-UfwInstallerPreflightReadOnly {throw 'ufw_fixture_unexpected_profile_query'};function script:Invoke-UfwProfilePreflightReadOnly {throw 'ufw_fixture_unexpected_profile_query'}}
}
$base=Join-Path ([IO.Path]::GetTempPath()) ('ufw-fixture-model-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($base)
$script:modelBase=$base
function Assert-UfwStorageFixturePlatform {}
function Get-UfwStorageFixtureBase {return $script:modelBase}
try{
 $r=Invoke-UfwJournalStorageFixture $m
 Check-Fixture ($r.completed -and $r.cleanup_completed -and $r.code -ceq 'ufw_fixture_storage_tests_passed') 'full fixture real Linux IO simulation'
 Check-Fixture (-not $r.native_Windows_file_API_executed -and -not $r.root_acl_verified -and -not $r.session_acl_verified -and -not $r.record_acl_verified -and -not $r.lock_acl_verified) 'Linux simulation cannot claim Windows ACL proof'
 foreach($key in @('initial_roundtrip_verified','CreateNew_collision_refused','existing_record_preserved','stale_head_refused','exclusive_lock_verified','append_chain_verified','baseline_change_refused','checksum_corruption_refused','partial_record_refused','memory_profile_recovery_with_file_checkpoints_verified','no_execution_authority')){Check-Fixture ($r.$key -ceq $true) ('fixture '+$key)}
 Check-Fixture ($r.checkpoint_count -eq 11) 'eleven checkpoints'
 foreach($key in @('real_legacy_journal_access_requested','real_preparation_record_created','profile_query_requested','firewall_change_requested','VPN_change_requested','DNS_query_generated','ready_for_apply','no_leak_certified')){Check-Fixture ($r.$key -ceq $false) ('scope '+$key)}
 Check-Fixture (@(Get-ChildItem $base -Force).Count -eq 0) 'no residual test folders'
 $count=& $m {$script:forbiddenCalls};Check-Fixture ($count -eq 0) 'no live-store or live-consent invocation'
 $ctx=& $m {Get-Variable StorageFixture -Scope Script -ErrorAction SilentlyContinue};Check-Fixture ($null -eq $ctx) 'module fixture context cleared'
 Check-Fixture (($r|ConvertTo-Json -Depth 12) -notmatch 'UfwInstaller-Session-[a-f0-9]{32}|[a-f0-9]{64}|fixture-model-') 'report omits private paths, identities and hashes'
 # Entire-tree validation precedes deletion. Unknown root files must remain intact.
 $tree=Join-Path $base ('UnifiedFW-JournalQualification-'+[guid]::NewGuid().ToString('N'));& $m {param($p)New-UfwPrivateJournalDirectory $p} $tree
 $sentinel=Join-Path $tree 'DO_NOT_DELETE.txt';[IO.File]::WriteAllText($sentinel,'sentinel');$caught=''
 try{Remove-UfwStorageFixtureTree $tree $base @() $m}catch{$caught=$_.Exception.Message}
 Check-Fixture ($caught -ceq 'ufw_fixture_cleanup_unexpected_child' -and [IO.File]::ReadAllText($sentinel) -ceq 'sentinel') 'unknown root child refuses cleanup'
 [IO.File]::Delete($sentinel);Remove-UfwStorageFixtureTree $tree $base @() $m
 # Unknown nested leaf must prevent deletion even of known leaves.
 $tree=Join-Path $base ('UnifiedFW-JournalQualification-'+[guid]::NewGuid().ToString('N'));& $m {param($p)New-UfwPrivateJournalDirectory $p} $tree
 $id='a'*32;$session=Join-Path $tree ('UfwInstaller-Session-'+$id);& $m {param($p)New-UfwPrivateJournalDirectory $p} $session
 $known=Join-Path $session '00000001.json';$sentinel=Join-Path $session 'DO_NOT_DELETE.txt';[IO.File]::WriteAllText($known,'fixture');[IO.File]::WriteAllText($sentinel,'sentinel');$caught=''
 try{Remove-UfwStorageFixtureTree $tree $base @($id) $m}catch{$caught=$_.Exception.Message}
 Check-Fixture ($caught -ceq 'ufw_fixture_cleanup_unexpected_leaf' -and [IO.File]::Exists($known) -and [IO.File]::Exists($sentinel)) 'prevalidate before deleting any known leaf'
 [IO.File]::Delete($sentinel);Remove-UfwStorageFixtureTree $tree $base @($id) $m
 $caught='';try{Remove-UfwStorageFixtureTree $base $base @() $m}catch{$caught=$_.Exception.Message};Check-Fixture ($caught -ceq 'ufw_fixture_cleanup_root_invalid' -and [IO.Directory]::Exists($base)) 'cleanup cannot target parent'
 # Parse and bound executable callsites in package-specific entry/fixture files.
 foreach($name in @('StorageFixture.ps1','Run-Test.ps1')){
  $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $name),[ref]$t,[ref]$e);Check-Fixture ($e.Count -eq 0) ('parse '+$name)
  foreach($cmd in $ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
   $n=$cmd.GetCommandName()
   if($n -match '^(Get-Net.*|Set-Net.*|New-Net.*|Remove-Net.*|Enable-Net.*|Disable-Net.*|Get-Vpn.*|Set-Vpn.*|Resolve-DnsName|Invoke-WebRequest|Invoke-RestMethod|Set-ExecutionPolicy|Register-ScheduledTask|Unregister-ScheduledTask|Get-ScheduledTask|Start-Process|Save-UfwNativePreparation|New-UfwNativePreparationOps|Invoke-UfwPreparationConsentCallbacks|Invoke-UfwInstallerPreflightReadOnly|Invoke-UfwProfilePreflightReadOnly|IsoLoad|ULoad|USave|IsoSave|Restore-IsoSession)$'){throw ('unexpected live call '+$n)}
   if($n -ceq 'Remove-Item'){throw 'recursive deletion command forbidden in fixture'}
  }
  Check-Fixture $true ('no live policy/preparation calls '+$name)
 }
 $source=[IO.File]::ReadAllText((Join-Path $Root 'StorageFixture.ps1'));Check-Fixture ($source.Contains('[IO.Directory]::Delete($dir,$false)') -and $source.Contains('[IO.Directory]::Delete($Root,$false)')) 'no recursive directory deletion'
 $data=New-UfwStorageFixtureData ('a'*32);Check-Fixture ($data.draft.execution_authorized -ceq $false -and $data.receipt.authorizes_firewall_change -ceq $false) 'synthetic data not authority'
 $result=[ordered]@{suite='Windows-journal-storage-fixture-package-model-011';passed=$true;assertions=$script:checks;real_Linux_fixture_file_IO_executed=$true;platform_guard_tested=$true;Windows_native_API_or_ACL_executed=$false;fixture_cleanup_safety_tested=$true;real_user_journal_accessed=$false;profile_queries_performed=$false;ready_for_apply=$false}
 $result|ConvertTo-Json|Set-Content '/data/ufw-journal-storage-test-v011/MODEL-RESULTS.json' -Encoding UTF8
 $result|ConvertTo-Json -Compress
}finally{
 # Test-only parent contains no user's files. Package cleanup itself is nonrecursive.
 if([IO.Directory]::Exists($base)){Remove-Item -LiteralPath $base -Recurse -Force}
}
