param([Parameter(Mandatory=$true)][string]$Config)
. (Join-Path $PSScriptRoot 'Common.ps1');. (Join-Path $PSScriptRoot 'Inventory.ps1')
$c=Read-Context $Config
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'system_snapshot_required'}
$phase=Get-Content -Raw (Join-Path $c.root 'snapshot-phase.json') | ConvertFrom-Json
if($phase.value -eq 'baseline'){
 # BITS enumeration may itself start the broker: capture registrations AFTER it, in both arms.
 Save-Private (Join-Path $c.root 'bits-before.json') (Get-BitsSnapshot)
 $baseReg=Get-RegistrationSnapshot;Save-Private (Join-Path $c.root 'registrations-before.json') $baseReg
 Save-Private (Join-Path $c.root 'svc-trust.json') (New-SvcTrust $baseReg)
 & $c.python -I (Join-Path $c.root 'TestClassifier.py') --live $c.root 2> (Join-Path $c.root 'classifier-live-stderr.private.txt')
 if($LASTEXITCODE -ne 0){Save-Private (Join-Path $c.root 'system-baseline-receipt.json') @{system_identity=$true;captured=$false;error_code='live_classifier_tests_failed'};throw 'live_classifier_tests_failed'}
 Save-Private (Join-Path $c.root 'system-baseline-receipt.json') @{system_identity=$true;captured=$true}
}elseif($phase.value -eq 'prelaunch'){
 $before=Get-Content -Raw (Join-Path $c.root 'bits-before.json') | ConvertFrom-Json
 $watch=@{complete=$false;system_identity=$true;samples=0;error_code=$null;observed=@{};ever_added=0;ever_modified=0}
 try {
  $first=Get-BitsSnapshot;Save-Private (Join-Path $c.root 'bits-prelaunch.json') $first;$delta=Compare-Bits $before $first
  $changes=Registration-Changes $c;$cl=Get-Content -Raw (Join-Path $c.root 'classification.json') | ConvertFrom-Json
  Save-Private (Join-Path $c.root 'system-prelaunch-receipt.json') @{system_identity=$true;registration_changes=$changes;raw_registration_changes=$cl.raw_changes;classified_reschedules=$cl.classified_reschedules;bits_added=$delta.added;bits_modified=$delta.modified;captured=$true}
  $clock=[Diagnostics.Stopwatch]::StartNew()
  do {
   $sample=Get-BitsSnapshot;$watch.samples++;$d=Compare-Bits $before $sample
   foreach($k in $sample.jobs.Keys){$v=$sample.jobs[$k];$watch.observed[$k+':'+$v.definition_hash]=$v}
   $watch.ever_added=[Math]::Max($watch.ever_added,$d.added);$watch.ever_modified=[Math]::Max($watch.ever_modified,$d.modified)
   Save-Private (Join-Path $c.root 'bits-watch.json') $watch
   if(Test-Path (Join-Path $c.root 'bits-stop.json')){break}
   Start-Sleep -Seconds 2
  }while($clock.Elapsed.TotalSeconds -lt 340)
  if(-not (Test-Path (Join-Path $c.root 'bits-stop.json'))){throw 'bits_watch_deadline'}
  $watch.complete=$true
 }catch{$watch.error_code='bits_observation_incomplete'}
 finally{Save-Private (Join-Path $c.root 'bits-watch.json') $watch;Save-Private (Join-Path $c.root 'bits-watch-done.json') @{complete=$watch.complete;samples=$watch.samples;system_identity=$true;error_code=$watch.error_code}}
}else{throw 'snapshot_phase_refused'}
