param([Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. "$PSScriptRoot/Profile.ps1"
$checks=0;$faults=0;$recoveries=0;$partials=0;$fields=0;$conflicts=0;$noops=0;$restores=0;$roots=@();$original=$null;$baseline=$null;$passed=$false;$errorCode=$null;$baselineEqual=$false;$finalNC=$false;$nativeChanged=$false;$cleanup=$false;$drift=-1
function Check([bool]$Ok){if(-not $Ok){throw 'profile_test_assertion'};$script:checks++}
function Reject([scriptblock]$Body,[string]$Expected){$ok=$false;try{& $Body|Out-Null}catch{if($_.Exception.Message -cne $Expected){throw};$ok=$true};Check $ok}
function Prepare {
 $r=InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-profile-'+[guid]::NewGuid().ToString('N')));$script:roots+=,$r
 $v=InitializeProfileRoundtrip $r;Check $v.native_notconfigured_noop;$script:noops++;return $r
}
function Worker([string]$Root,[string]$Action,[string]$Fault='None'){
 & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PSScriptRoot/Worker.ps1" -Root $Root -Action $Action -Fault $Fault|Out-Host;return $LASTEXITCODE
}
try{
 AssertInactiveDomain;$baseline=ReadPolicyInventory;$original=ReadProfileImages
 Check ((GetStoredDomain).DefaultOutboundAction -eq 'NotConfigured')
 $r=Prepare;$s=(ReadProfileRecord $r).state
 # Every raw field of all six profile images remains under comparison; no display exceptions.
 for($i=0;$i -lt 6;$i++){foreach($p in $s.original[$i].image.PSObject.Properties){
  $x=ProfileClone $s.original
  if($p.Value -is [array]){$x[$i].image.($p.Name)=@($p.Value)+@('test')}else{$x[$i].image.($p.Name)='test'}
  Reject {CompareProfileObserved $s $x} 'profile_external_conflict';$fields++
 }}
 Check ((Worker $r Block) -eq 0);Check ((ReadProfileRecord $r).state.phase -ceq 'blocked')
 Check ([string](GetStoredDomain).DefaultOutboundAction -ceq 'Block');$nativeChanged=$true
 $rev=(ReadProfileRecord $r).revision;Check ((Worker $r Block) -eq 0);Check ((ReadProfileRecord $r).revision -eq $rev)
 Check ((Worker $r Restore) -eq 0);$restores++;Check ([string](GetStoredDomain).DefaultOutboundAction -ceq 'NotConfigured')
 $rev=(ReadProfileRecord $r).revision;Check ((Worker $r Restore) -eq 0);Check ((ReadProfileRecord $r).revision -eq $rev)
 Reject {InvokeProfileRoundtrip $r Block} 'profile_restore_started'
 foreach($a in @('Block','Restore')){foreach($f in @('BeforeMutation','AfterMutation')){
  $r=Prepare;if($a -ceq 'Restore'){Check ((Worker $r Block) -eq 0)}
  Check ((Worker $r $a $f) -eq 73);$faults++;Check ((ReadProfileRecord $r).state.pending)
  Check ((Worker $r $a) -eq 0);$recoveries++
  if($a -ceq 'Block'){Check ((Worker $r Restore) -eq 0)}
  $restores++;Check ([string](GetStoredDomain).DefaultOutboundAction -ceq 'NotConfigured');Check ((ReadProfileRecord $r).state.phase -ceq 'restored')
  Write-Host ('profile_fault_recovered_'+$faults)
 }}
 foreach($f in @('BeforeMutation','AfterMutation')){
  $r=Prepare;Check ((Worker $r Block $f) -eq 73);$faults++
  Check ((Worker $r Restore) -eq 0);$recoveries++;$partials++;$restores++
  Check ([string](GetStoredDomain).DefaultOutboundAction -ceq 'NotConfigured')
 }
 # Explicit LAB external mutation on the same inactive Domain property; NOT adopted on recovery.
 $r=Prepare;Check ((Worker $r Block) -eq 0);$rev=(ReadProfileRecord $r).revision
 AssertInactiveDomain;Set-NetFirewallProfile -InputObject (GetStoredDomain) -DefaultOutboundAction Allow -ErrorAction Stop|Out-Null
 Reject {InvokeProfileRoundtrip $r Restore} 'profile_external_conflict';$conflicts++;Check ((ReadProfileRecord $r).revision -eq $rev)
 # Undo our explicit negative-test mutation, not any unknown concurrent change.
 $known=ProfileExpected $original $true;foreach($p in $known){if($p.name -ceq 'Domain'){$p.image.DefaultOutboundAction='2'}}
 Check ((IntegratedHash (ReadProfileImages)) -ceq (IntegratedHash $known));AssertInactiveDomain
 Set-NetFirewallProfile -InputObject (GetStoredDomain) -DefaultOutboundAction Block -ErrorAction Stop|Out-Null
 Check ((Worker $r Restore) -eq 0);$restores++
 $r=Prepare;Check ((Worker $r Block) -eq 0)
 [IO.File]::WriteAllText((Join-Path $r 'journal.json'),'bad')
 Reject {InvokeProfileRoundtrip $r Restore} 'profile_journal_required';Check ([string](GetStoredDomain).DefaultOutboundAction -ceq 'Block')
 $missing=InitializeJournalRoot (Join-Path $env:RUNNER_TEMP ('sstp-profile-missing-'+[guid]::NewGuid().ToString('N')))
 Reject {InvokeProfileRoundtrip $missing Restore} 'profile_journal_required'
}catch{
 $errorCode='profile_test_failed';Write-Host ('profile_checks_before_failure_'+$checks)
 if($_.Exception.Message -match '^(profile|journal|integrated|inventory)_[a-z_]+$'){Write-Host $_.Exception.Message}else{Write-Host ('profile_provider_failure_'+$_.Exception.GetType().Name.ToLowerInvariant())}
}finally{
 # Separate CI cleanup only: one inactive Domain, immutable original known in THIS test process.
 try{
  if($null -ne $original){
   AssertInactiveDomain;$actual=ReadProfileImages;$blocked=ProfileExpected $original $true
   if((IntegratedHash $actual) -ceq (IntegratedHash $blocked)){
    Set-NetFirewallProfile -InputObject (GetStoredDomain) -DefaultOutboundAction NotConfigured -ErrorAction Stop|Out-Null
   }elseif((IntegratedHash $actual) -cne (IntegratedHash $original)){throw 'profile_cleanup_conflict'}
   for($i=0;$i -lt 12;$i++){if((IntegratedHash (ReadProfileImages)) -ceq (IntegratedHash $original)){break};Start-Sleep -Milliseconds 250}
   $cleanup=(IntegratedHash (ReadProfileImages)) -ceq (IntegratedHash $original)
   $finalNC=[string](GetStoredDomain).DefaultOutboundAction -ceq 'NotConfigured'
   $d=ComparePolicyInventory $baseline (ReadPolicyInventory);$baselineEqual=$d.policy_equal;$drift=$d.display_rule_changes
  }
  if(-not $cleanup -or -not $baselineEqual -or -not $finalNC){$errorCode='profile_cleanup_failed'}
 }catch{$errorCode='profile_cleanup_failed';Write-Host ('profile_cleanup_failure_'+$_.Exception.GetType().Name.ToLowerInvariant())}
 $passed=$null -eq $errorCode -and $faults -eq 6 -and $recoveries -eq 6 -and $partials -eq 2 -and $noops -eq 9 -and $restores -eq 8 -and $conflicts -eq 1 -and $fields -gt 50 -and $cleanup -and $baselineEqual -and $finalNC
 if(-not $passed -and $null -eq $errorCode){$errorCode='profile_test_failed'}
 $out=[ordered]@{schema='sstp-profile-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;error_code=$errorCode;checks=$checks;profile_field_cases=$fields;fault_cases=$faults;fresh_process_recoveries=$recoveries;partial_restores=$partials;native_notconfigured_noops=$noops;verified_restore_completions=$restores;observed_inactive_domain_block=$nativeChanged;external_conflict_stops=$conflicts;cleanup_exact=$cleanup;final_stored_notconfigured=$finalNC;unrelated_full_policy_equal=$baselineEqual;unrelated_display_changes=$drift;active_profile_targeted=$false;whole_machine_enforcement_tested=$false;guard_coordinator_tested=$false;sstp_tested=$false;reboot_tested=$false;user_device_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($out|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if(-not $passed){exit 1}
