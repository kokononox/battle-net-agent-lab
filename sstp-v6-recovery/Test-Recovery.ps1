param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Overlay.ps1')
. (Join-Path $PSScriptRoot 'Resume.ps1')
$script:checks=0;$script:sets=0;$script:cleaned=0;$script:childError=$null
function Check($Value){if(-not $Value){throw ('resume_check_'+($script:checks+1))};$script:checks++}
function Reject([scriptblock]$Code,[string]$Expected){$got='';try{& $Code|Out-Null}catch{$got=$_.Exception.Message};Check ($got -ceq $Expected)}
function FreshResume([string]$Root,[string]$Fault='None',[int]$Code=0){
 $p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $PSScriptRoot 'Test-ResumeWorker.ps1')+'"'),'-Root',('"'+$Root+'"'),'-Fault',$Fault) -WindowStyle Hidden -Wait -PassThru
 $ok=$p.HasExited -and $p.ExitCode -eq $Code
 if(-not $ok){
  $outcome=Join-Path $Root 'resume-worker-result.json'
  if([IO.File]::Exists($outcome)){$script:childError=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($outcome))}
 }
 Check $ok
}
function MakePending([string]$Root,[bool]$LeaveV6){
 NewOverlay $Root @('192.0.2.1','2001:db8::1') -Scope Fixture -FixtureProgram $script:program|Out-Null
 $script:sets++
 $rec=OverlayLoad $Root;$original=OverlayClone $rec.state
 if(-not $LeaveV6){
  $o=$rec.state.objects[2];$actual=OverlayRead $o.spec.name
  Check ((OverlayHash $actual.image) -ceq (OverlayHash (OverlayExpected $o $false)))
  Remove-NetFirewallRule -InputObject $actual.rule -ErrorAction Stop
  Check ($null -eq (OverlayRead $o.spec.name))
 }
 $rec.state.phase='staging';$rec.state.pending=[pscustomobject]@{index=2;operation='create';target=$false}
 $rec.state.objects[2].exists=$false;$rec.state.objects[2].original=$null
 $rec.state.objects[2].spec.remote=@(ComplementAddresses @($rec.state.allowed_ips) 128)
 $rec=OverlaySave $Root $rec
 return $original
}
function RemovePrepared([string]$Root){
 $r=OverlayLoad $Root;Check ($r.state.phase -ceq 'prepared')
 Check (@($r.state.objects|Where-Object{$_.enabled}).Count -eq 0)
 InvokeOverlay $Root Remove|Out-Null
 $r=OverlayLoad $Root;foreach($o in $r.state.objects){Check ($null -eq (OverlayRead $o.spec.name))}
 $script:cleaned++
}
$r=[ordered]@{schema='sstp-v6-recovery-test-1';passed=$false;checks=0;sets=0;cleaned_sets=0;fresh_process_recoveries=0;rejected_existing_rule=$false;rejected_owned_drift=$false;remaining_objects=-1;unrelated_policy_equal=$false;foreign_display_changes=-1;error_code=$null;all_rules_created_disabled=$true;user_device_tested=$false}
$dir=Join-Path $env:RUNNER_TEMP ('sstp-recovery-'+[guid]::NewGuid().ToString('N'));$roots=@();$before=$null
try{
 $null=[IO.Directory]::CreateDirectory($dir)
 $script:program=Join-Path $dir ('sstp-overlay-fixture-'+[guid]::NewGuid().ToString('N')+'.exe')
 [IO.File]::Copy((Join-Path $env:SystemRoot 'System32\whoami.exe'),$script:program)
 $before=ReadPolicyInventory
 $root=Join-Path $dir 'normal';$roots+=,$root;$null=MakePending $root $false
 FreshResume $root
 $rec=OverlayLoad $root;Check ($rec.state.phase -ceq 'prepared' -and $null -eq $rec.state.pending)
 $rev=$rec.revision;ResumeOverlayPreparation $root|Out-Null;Check ((OverlayLoad $root).revision -eq $rev)
 RemovePrepared $root
 $root=Join-Path $dir 'existing';$roots+=,$root;$known=MakePending $root $true
 $rev=(OverlayLoad $root).revision
 Reject {ResumeOverlayPreparation $root} 'resume_v6_exists_no_adoption'
 Check ((OverlayLoad $root).revision -eq $rev);$r.rejected_existing_rule=$true
 # Only the harness restores its deliberately altered journal from its known image.
 $now=OverlayLoad $root;$null=WriteJournal $root $now.revision $known;RemovePrepared $root
 $root=Join-Path $dir 'drift';$roots+=,$root;$null=MakePending $root $false
 $rec=OverlayLoad $root;$o=$rec.state.objects[1]
 Set-NetFirewallRule -PolicyStore PersistentStore -Name $o.spec.name -Description 'intentional fixture drift' -ErrorAction Stop
 Reject {ResumeOverlayPreparation $root} 'resume_owned_conflict';$r.rejected_owned_drift=$true
 Set-NetFirewallRule -PolicyStore PersistentStore -Name $o.spec.name -Description 'Destination overlay test build; not an independent kill switch' -ErrorAction Stop
 FreshResume $root;RemovePrepared $root
 foreach($fault in @('BeforeCreate','AfterCapture')){
  $root=Join-Path $dir $fault;$roots+=,$root;$null=MakePending $root $false
  FreshResume $root $fault 73;FreshResume $root
  $r.fresh_process_recoveries++;RemovePrepared $root
 }
 $left=0;foreach($root in $roots){$state=OverlayLoad $root;foreach($o in $state.state.objects){if($null -ne (OverlayRead $o.spec.name)){$left++}}}
 $r.remaining_objects=$left;Check ($left -eq 0)
 $cmp=ComparePolicyInventory $before (ReadPolicyInventory);$r.unrelated_policy_equal=$cmp.policy_equal;$r.foreign_display_changes=$cmp.display_rule_changes;Check $cmp.policy_equal
 $r.passed=$true
}catch{
 $r.error_code='resume_test_failed';if($_.Exception.Message -cmatch '^(resume|overlay|journal)_[a-z_0-9]{1,80}$'){$r.error_code=$_.Exception.Message}
 [Console]::Error.WriteLine('resume_test_line_'+$_.InvocationInfo.ScriptLineNumber+'_type_'+$_.Exception.GetType().Name)
}finally{
 $r['child_error']=$script:childError;$r.checks=$script:checks;$r.sets=$script:sets;$r.cleaned_sets=$script:cleaned
 if($OutputPath){[IO.File]::WriteAllText($OutputPath,($r|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))}
}
$r|ConvertTo-Json -Depth 5
if(-not $r.passed){exit 1};exit 0
