# Private, memory-only live selection/review binding. Never imports approval JSON.
# Uses unchanged local-review-v011 and runtime CandidateEntry/ProgramReview helpers.
function Get-UfwLiveIdentityText($Actor,$Candidate,$Programs){
 if($Actor -isnot [string] -or $Actor -cnotmatch '^S-1-[0-9-]+$'){throw 'ufw_live_actor'}
 Assert-UfwCandidatePrograms $Programs
 if($Candidate.draft.ready_for_apply -isnot [bool] -or $Candidate.draft.ready_for_apply -or $Candidate.draft.plan_executable -isnot [bool] -or $Candidate.draft.plan_executable -or $Candidate.draft.input_valid -isnot [bool] -or -not $Candidate.draft.input_valid){throw 'ufw_live_not_a_draft'}
 $n=$Candidate.draft.normalized_input
 if($n.profile_scope -cne 'current_user' -or $n.profile_owner_sid -cne $Actor -or @($n.endpoint_ips).Count -ne 1){throw 'ufw_live_profile_scope'}
 # Persisted view contains only a digest of this private observation, not authority.
 return Get-UfwLocalJson ([pscustomobject][ordered]@{actor=$Actor;candidate=$Candidate;programs=$Programs})
}
function New-UfwLiveReviewContext($IO,[string]$SessionId){
 foreach($k in @('Actor','Candidate','Programs','Snapshot','HostPath','Tick','Display','Answer')){if(-not $IO.ContainsKey($k) -or $IO[$k] -isnot [scriptblock]){throw 'ufw_live_missing_adapter'}}
 $actor=& $IO.Actor;$candidate=& $IO.Candidate $null;$programs=& $IO.Programs
 $text=Get-UfwLiveIdentityText $actor $candidate $programs
 $spec=[pscustomobject][ordered]@{schema='ufw-owned-sstp-spec-01';session_id=$SessionId;observation_binding=(Get-UfwJournalHash $text);endpoint_ips=@($candidate.draft.normalized_input.endpoint_ips);system_host_path=(& $IO.HostPath);system_host_sha256=([string]$candidate.image_hash).ToLowerInvariant()}
 $snapshot=& $IO.Snapshot
 $view=New-UfwMixedBackendView $snapshot $spec
 return [pscustomobject]@{io=$IO;actor=$actor;candidate=$candidate;programs=$programs;identity_text=$text;view=$view;accepted=$false;accepted_tick=[long]0;last_tick=[long]0;revoked=$false}
}
function Test-UfwLiveObservation($Context){
 if($Context.revoked){return $false}
 try{
  $actor=& $Context.io.Actor;$candidate=& $Context.io.Candidate $Context.candidate.binding;$programs=& $Context.io.Programs
  if((Get-UfwLiveIdentityText $actor $candidate $programs) -cne $Context.identity_text){throw 'ufw_live_binding_changed'}
  return $true
 }catch{$Context.revoked=$true;$Context.accepted=$false;return $false}
}
function Invoke-UfwLiveReview($Context,$View){
 if($Context.accepted -or $Context.revoked -or (Get-UfwLocalJson $View) -cne (Get-UfwLocalJson $Context.view)){throw 'ufw_live_review_context'}
 & $Context.io.Display $Context
 $challenge='ISOLATE '+[guid]::NewGuid().ToString('N').Substring(0,12)
 $answer=& $Context.io.Answer $challenge
 if($answer -isnot [string] -or $answer -cne $challenge){$Context.revoked=$true;return [pscustomobject]@{cancelled=$true;binding=$View.binding}}
 if(-not (Test-UfwLiveObservation $Context)){throw 'ufw_live_review_changed'}
 $snapshot=& $Context.io.Snapshot
 if((Get-UfwLocalSnapshotText $snapshot) -cne (Get-UfwLocalSnapshotText $Context.view.snapshot)){$Context.revoked=$true;throw 'ufw_live_policy_changed_during_review'}
 $tick=& $Context.io.Tick
 if($tick -isnot [long] -or $tick -lt 0){$Context.revoked=$true;throw 'ufw_live_clock'}
 $Context.accepted=$true;$Context.accepted_tick=$tick;$Context.last_tick=$tick
 return [pscustomobject]@{cancelled=$false;binding=$View.binding}
}
function Test-UfwLiveLease($Context){
 # One bounded lease covers forward changes and capture; never recovery.
 if(-not $Context.accepted -or $Context.revoked){return $false}
 try{
  $tick=& $Context.io.Tick
  if($tick -isnot [long] -or $tick -lt $Context.last_tick -or $tick-$Context.accepted_tick -gt 180000){throw 'ufw_live_lease_expired'}
  $Context.last_tick=$tick
  if(-not (Test-UfwLiveObservation $Context)){return $false}
  # Slow observers must not extend the lease by blocking through its deadline.
  $end=& $Context.io.Tick
  if($end -isnot [long] -or $end -lt $tick -or $end-$Context.accepted_tick -gt 180000){throw 'ufw_live_lease_expired'}
  $Context.last_tick=$end;return $true
 }catch{$Context.revoked=$true;$Context.accepted=$false;return $false}
}
function New-UfwLiveCoordinatorBindings($Context){
 return @{
  Inspect=(New-UfwLocalModuleCallback {param($c)return $c.view} $Context)
  Review=(New-UfwLocalModuleCallback {param($c,$view)return Invoke-UfwLiveReview $c $view} $Context)
  Refresh=(New-UfwLocalModuleCallback {param($c)return Test-UfwLiveLease $c} $Context)
 }
}
function New-UfwWindowsLiveReviewIO($Expected,[string[]]$Paths,$PolicyIO){
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess){throw 'ufw_live_windows_x64_required'}
 # Caller loads pinned helpers inside the same private module. Paths are selected
 # locally; observing identity does not trust, execute, or grant the programs.
 $bound=[pscustomobject]@{expected=(Copy-UfwLocalData $Expected);paths=@($Paths);policy=$PolicyIO}
 return @{
  Actor={return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
  Candidate=(New-UfwLocalModuleCallback {param($b,$previous)return Read-SstpReviewCandidate $b.expected $previous} $bound)
  Programs=(New-UfwLocalModuleCallback {param($b)return ConvertTo-UfwCandidatePrograms $b.paths {param($p)Read-UfwProgramNativeObservation $p}} $bound)
  Snapshot=(New-UfwLocalModuleCallback {param($b)return (Read-UfwLocalStableSnapshot $b.policy).snapshot} $bound)
  HostPath={return [IO.Path]::Combine([Environment]::SystemDirectory,'svchost.exe')}
  Tick={return [long]([Diagnostics.Stopwatch]::GetTimestamp()*1000.0/[Diagnostics.Stopwatch]::Frequency)}
  Display=(New-UfwLocalModuleCallback {param($b,$c)Show-UfwLivePolicyReview $c} $bound)
  Answer={param($challenge)return Read-Host ('Type exactly "'+$challenge+'" for this temporary policy change, or Enter to cancel')}
 }
}
function Show-UfwLivePolicyReview($Context){
 Write-Host 'LOCAL ONLY: do not upload this view or a screenshot.'
 Write-Host 'Temporary isolation REVIEW; not a claim of leak-free operation or a released launcher.'
 Write-Host 'Only an already-connected, unchanged SSTP session is in scope. No reconnect/reboot support.'
 Write-Host ('Selected profile: '+$Context.candidate.binding.profile_name)
 Write-Host ('Configured server: '+$Context.candidate.draft.normalized_input.server)
 Write-Host ('Transport: system svchost.exe / SstpSvc / outbound TCP443 / '+($Context.view.transport.endpoint_ips -join ', '))
 Write-Host 'Endpoint is connection correlation, NOT independent TLS authentication; physical adapter is not pinned.'
 foreach($p in $Context.programs){Write-Host ('Selected EXE (NO destination grants): '+$p.path+' / SHA256 '+$p.sha256)}
 Write-Host 'Exact local outbound Allow rules proposed for temporary disabling:'
 foreach($op in $Context.view.operations){if($op.kind -ceq 'disable_reviewed_local_allow'){Write-Host ($op.name+' : enabled -> disabled');Write-Host ('Exact before (all rule/filter fields): '+(Get-UfwLocalJson $op.before))}}
 Write-Host 'Existing Blocks, profile defaults, inbound rules and unrelated disabled rules stay unchanged.'
 Write-Host 'Runtime destinations are proposals only. Children/services get no implicit grant. Recovery is local and separately gated.'
 Write-Host 'Consent lasts at most 180 seconds; connection/program/actor changes revoke it. No saved approval is created.'
}

function New-UfwLiveBackendGuard($Context,[scriptblock]$ExistingGuard){
 if($null -eq $ExistingGuard){throw 'ufw_live_existing_guard_required'}
 return New-UfwLocalModuleCallback {
  param($b,$phase,$view)
  if($phase -cnotin @('backup','forward','immediately_before_forward','restore','immediately_before_restore','recovery','finish')){return $false}
  $permit=& $b.guard $phase $view
  if($permit -isnot [bool] -or -not $permit){return $false}
  # Existing independent actor/audit/quiescence/exit guard is NEVER bypassed.
  # Recovery does not need a live VPN, the original selected EXE or its lease.
  if($phase -cin @('restore','immediately_before_restore','recovery','finish')){return $true}
  if((Get-UfwLocalJson $view) -cne (Get-UfwLocalJson $b.context.view)){return $false}
  return Test-UfwLiveLease $b.context
 } ([pscustomobject]@{context=$Context;guard=$ExistingGuard})
}
