param([ValidateSet('Prepare','Apply','Status','Restore','Guardian')][string]$Mode='Status',[string]$Request,[string]$Output)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$flat=Test-Path -LiteralPath (Join-Path $PSScriptRoot 'session-core.ps1')
if($flat){. (Join-Path $PSScriptRoot 'session-core.ps1');. (Join-Path $PSScriptRoot 'native.ps1')}
else{. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab/session-core.ps1');. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab/native.ps1')}
. (Join-Path $PSScriptRoot 'isolation-core.ps1');. (Join-Path $PSScriptRoot 'isolation-native.ps1')
function IsoTaskName($S){'UnifiedFW-Isolation-'+$S.owner}
function IsoTaskExpectedArguments{'-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+(Join-Path $script:IsoRoot 'isolation-worker.ps1')+'" -Mode Guardian'}
function IsoTaskRead($S){
 $tasks=@(Get-ScheduledTask -ErrorAction Stop|Where-Object{$_.TaskPath -ceq '\' -and $_.TaskName -ceq (IsoTaskName $S)})
 if(-not $tasks.Count){return $null};if($tasks.Count -ne 1){throw 'iso_task_ambiguous'};$t=$tasks[0]
 $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 if(@($t.Actions).Count -ne 1 -or -not (UStringEqual $t.Actions[0].Execute $ps) -or $t.Actions[0].Arguments -cne (IsoTaskExpectedArguments) -or [string]$t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or [string]$t.Principal.RunLevel -cne 'Highest'){throw 'iso_task_collision_no_adoption'}
 return $t
}
function IsoInstallController($S){
 $existingTask=IsoTaskRead $S;if($null -ne $existingTask -and $S.phase -cne 'armed'){throw 'iso_existing_task_on_new_session_no_adoption'}
 $paths=@{ 'isolation-worker.ps1'=(Join-Path $PSScriptRoot 'isolation-worker.ps1');'isolation-core.ps1'=(Join-Path $PSScriptRoot 'isolation-core.ps1');'isolation-native.ps1'=(Join-Path $PSScriptRoot 'isolation-native.ps1');'native.ps1'=$(if($flat){Join-Path $PSScriptRoot 'native.ps1'}else{Join-Path (Split-Path $PSScriptRoot -Parent) 'lab/native.ps1'});'session-core.ps1'=$(if($flat){Join-Path $PSScriptRoot 'session-core.ps1'}else{Join-Path (Split-Path $PSScriptRoot -Parent) 'lab/session-core.ps1'})}
 foreach($name in @($paths.Keys|Sort-Object)){
  $dest=Join-Path $script:IsoRoot $name;$bytes=[IO.File]::ReadAllBytes($paths[$name]);$expected=(Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
  if(Test-Path -LiteralPath $dest){if((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -cne $expected){
   if(-not (Get-Variable IsoCanUpgradeControllers -Scope Script -ErrorAction SilentlyContinue) -or -not $script:IsoCanUpgradeControllers){throw 'iso_protected_controller_changed_restore_with_original_version_first'}
   $tmp=Join-Path $script:IsoRoot ('controller-'+[guid]::NewGuid().ToString('N')+'.tmp')
   try{UWritePrivateBytes $tmp $bytes;[IO.File]::Replace($tmp,$dest,[Management.Automation.Language.NullString]::Value)}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
  }}else{UWritePrivateBytes $dest $bytes}
  if((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -cne $expected){throw 'iso_controller_copy_readback'}
 }
 $t=IsoTaskRead $S;if($null -ne $t){if($S.phase -cne 'armed'){throw 'iso_existing_task_on_new_session_no_adoption'};return}
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument (IsoTaskExpectedArguments)
 $trigger=New-ScheduledTaskTrigger -AtStartup
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
 Register-ScheduledTask -TaskName (IsoTaskName $S) -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description ('UnifiedFW persistent isolation guardian; owner='+$S.owner+'; scoped Restore only') -ErrorAction Stop|Out-Null
 $null=IsoTaskRead $S
}
function IsoAssertActiveControllerVersion($S){
 if($null -eq $S -or $S.phase -cne 'armed'){return}
 foreach($name in @('isolation-worker.ps1','isolation-core.ps1','isolation-native.ps1')){
  $source=Join-Path $PSScriptRoot $name;$dest=Join-Path $script:IsoRoot $name
  if(-not (Test-Path -LiteralPath $dest) -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash){throw 'iso_protected_controller_changed_restore_with_original_version_first'}
 }
}
function IsoTaskStop($S){
 $t=IsoTaskRead $S;if($null -eq $t){return}
 Stop-ScheduledTask -InputObject $t -ErrorAction Stop
 Unregister-ScheduledTask -InputObject $t -Confirm:$false -ErrorAction Stop
}
function IsoGuardianReceipt($S,[string]$ErrorText){
 $payload=UJson ([ordered]@{schema='unified-isolation-heartbeat-1';session_id=$S.id;utc=[datetime]::UtcNow.ToString('o');configuration_verified=(-not [bool]$ErrorText);error=$ErrorText})
 $dest=Join-Path $script:IsoRoot 'guardian.json';$tmp=Join-Path $script:IsoRoot ('heartbeat-'+[guid]::NewGuid().ToString('N')+'.tmp')
 try{UWritePrivateBytes $tmp ([Text.Encoding]::UTF8.GetBytes((UJson ([ordered]@{payload=$payload;sha256=(UHash $payload)}))))
  if([IO.File]::Exists($dest)){[IO.File]::Replace($tmp,$dest,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$dest)}
 }finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}
function IsoSummary($S){
 if($null -eq $S){return [pscustomobject]@{phase='not_configured';health='not_protected_by_this_engine';configuration_verified=$false;guardian_running=$false;no_leak_certified=$false}}
 $verified=$false;$health=[string]$S.health;$guardian=$false;$fresh=$false;$connected=$false;$guardianError='';$restorationVerified=$false
 if($S.phase -ceq 'restored'){try{IsoAssertRestoredState $S (IsoNativeOps);$restorationVerified=$true;$health='restoration_verified_current_snapshot_not_reboot_qualified'}catch{$health='restoration_unverified:'+ $_.Exception.Message}}
 if($S.phase -ceq 'armed'){try{IsoVerify $S;$verified=$true;$health='configuration_verified_not_packet_tested'}catch{$health='critical:'+ $_.Exception.Message}}
 try{$t=IsoTaskRead $S;$guardian=($null -ne $t -and [string]$t.State -ceq 'Running');if($S.phase -ceq 'restored' -and $null -ne $t){$restorationVerified=$false;$health='restoration_unverified_controller_task_present'}}catch{$restorationVerified=$false;$health='critical:'+ $_.Exception.Message}
 $connection=if($null -ne $S.plan -and $S.plan.policy.PSObject.Properties.Name -contains 'connection'){[string]$S.plan.policy.connection}else{'vpn'}
 if($null -ne $S.plan -and $connection -ceq 'vpn' -and $null -ne $S.plan.vpn){$connected=@(Get-NetIPInterface -ErrorAction Stop|Where-Object{[string]$_.InterfaceAlias -ceq $S.plan.vpn.name -and [int]$_.InterfaceIndex -eq [int]$S.plan.vpn.interface_index -and [string]$_.ConnectionState -ceq 'Connected'}).Count -gt 0}
 $receipt=Join-Path $script:IsoRoot 'guardian.json'
 if(Test-Path -LiteralPath $receipt){try{
  if((Get-Item -LiteralPath $receipt).Length -gt 16384){throw 'heartbeat_size'}
  $e=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receipt));if($e.sha256 -cne (UHash $e.payload)){throw 'heartbeat_checksum'}
  $h=ConvertFrom-Json -InputObject $e.payload
  if($h.schema -ceq 'unified-isolation-heartbeat-1' -and $h.session_id -ceq $S.id){$age=([datetime]::UtcNow-[datetime]::Parse($h.utc).ToUniversalTime()).TotalSeconds;$fresh=($age -ge 0 -and $age -lt 30);$guardianError=[string]$h.error}
 }catch{$guardianError='heartbeat_unreadable'}}
 if($guardianError -and $S.phase -ceq 'armed'){$health='guardian_error:'+ $guardianError}
 if($verified -and $guardian -and -not $fresh){$health='baseline_verified_guardian_heartbeat_stale_or_starting'}
 if($verified -and -not $guardian){$health='baseline_verified_guardian_not_running'}
 return [pscustomobject]@{id=$S.id;owner=$S.owner;phase=$S.phase;restoration_verified_now=$restorationVerified;restoration_reboot_qualified=$false;restoration_evidence_scope='current_sequential_snapshot_only';connection=$connection;scope='whole_system';health=$health;configuration_verified=$verified;guardian_running=$guardian;guardian_heartbeat_fresh=$fresh;guardian_last_error=$guardianError;vpn_interface_connected=$connected;configured_generation=$(if($null -ne $S.plan){$S.plan.policy.generation}else{$null});configured_config_digest=$(if($null -ne $S.plan){$S.plan.policy.config_digest}else{$null});foreign_allow_backup_count=@($S.foreign).Count;rule_count=@($S.entries|Where-Object{-not $_.removed}).Count;no_leak_certified=$false;profile_persistence='PersistentStore; closing_UI_does_not_restore';VPN_changes='new_interface_or_server_requires_explicit_review_apply; no_automatic_broader_exceptions';limits='periodic_guardian_not_atomic_against_Admin_GPO_or_other_WFP; existing_flows_and_reboot_need_packet_tests; no_external_DNS_DHCP_exception'}
}
function IsoGuardian{
 while($true){
  $lock=$null
  try{
   $script:IsoRoot=IsoSecureRoot $false;$lock=UOpenPrivateFile (Join-Path $script:IsoRoot 'operation.lock') ([IO.FileMode]::OpenOrCreate)
   $s=IsoLoad;if($null -eq $s -or $s.phase -ceq 'restored'){return}
   if($s.phase -ceq 'armed'){
    # Re-enforce only the default-outbound field already owned by this session; never force Allow.
    foreach($p in $s.profiles){$now=IsoProfileRead $p.name;if($now.default_outbound -cne 'Block'){IsoProfileSet $p.name 'Block';$p.after=IsoProfileRead $p.name;IsoSave $s}}
    $new=IsoForeignAllows $s;if($new.Count){IsoQuarantine $s $new (IsoNativeOps)}
    IsoVerify $s;IsoGuardianReceipt $s ''
   }
  }catch{
   # No automatic recovery that broadens access. Preserve persistent restrictions on any error.
   if($null -ne $lock -and $null -ne $s){try{IsoGuardianReceipt $s ([string]$_.Exception.Message)}catch{}}
  }finally{if($null -ne $lock){$lock.Dispose()}}
  Start-Sleep -Seconds 3
 }
}
$script:IsoCanUpgradeControllers=$false
$guardLock=$null;$s=$null;$started=$false;$result=$null
try{
 UAdmin
 $script:IsoRoot=IsoSecureRoot ($Mode -in @('Apply','Guardian'))
 if($Mode -ceq 'Guardian'){IsoGuardian;exit 0}
 if(-not (Test-Path -LiteralPath $script:IsoRoot)){
  if($Mode -in @('Status','Restore')){$result=@{ok=$true;isolation_status=(IsoSummary $null)}}else{$s=$null}
 }else{$deadline=[datetime]::UtcNow.AddSeconds(30);do{try{$guardLock=UOpenPrivateFile (Join-Path $script:IsoRoot 'operation.lock') ([IO.FileMode]::OpenOrCreate)}catch{if([datetime]::UtcNow -ge $deadline){throw 'iso_operation_busy_retry_status'};Start-Sleep -Milliseconds 250}}while($null -eq $guardLock);$s=IsoLoad}
 if($Mode -ceq 'Prepare' -or $Mode -ceq 'Apply'){
  UAssertPath $Request;if((Get-Item -LiteralPath $Request).Length -gt 2097152){throw 'iso_request_size'};$q=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request))
  if($null -ne $s -and $s.phase -cne 'restored' -and $s.owner -cne $q.policy.owner){throw 'iso_other_owner_active_restore_original_package'}
  if($null -ne $s -and $s.phase -cnotin @('armed','restored')){throw 'iso_partial_session_use_status_recovery_no_retry'}
  if($null -ne $s -and $s.phase -ceq 'restored'){IsoAssertRestoredState $s (IsoNativeOps)}
  IsoAssertActiveControllerVersion $s
  $plan=IsoPrepare $q.policy $(if($null -ne $s -and $s.phase -ceq 'armed'){$s}else{$null})
  $review=[pscustomobject][ordered]@{connection=$(if($q.policy.PSObject.Properties.Name -contains 'connection'){$q.policy.connection}else{'vpn'});scope='whole_system';vpn=$plan.vpn;rule_count=$plan.rules.Count;quarantine_allow_count=$plan.foreign.Count;quarantine_allow_names=@($plan.foreign|ForEach-Object{$_.name});profiles=$plan.profiles;whitelist=$q.policy.whitelist;overlaps=$q.policy.overlaps;control_plane=$plan.control_plane;no_leak_certified=$false}
  $token=UHash (UJson $plan)
  if($Mode -ceq 'Prepare'){$result=@{ok=$true;isolation_plan=@{generation=$q.policy.generation;review_digest=$token;review=$review}}}
  else{
   if($q.confirmation -cne 'APPLY ISOLATION' -or $q.review_digest -cne $token){throw 'iso_review_stale_reprepare_required'}
   if($null -ne $s -and $s.phase -ceq 'armed'){IsoInstallController $s;$started=$true;$s=Invoke-IsoUpdate $s $plan (IsoNativeOps)}
   else{
    $script:IsoCanUpgradeControllers=($null -ne $s -and $s.phase -ceq 'restored')
    if($null -ne $s){$history=Join-Path $script:IsoRoot ('restored-'+$s.id+'.json');UWritePrivateBytes $history ([IO.File]::ReadAllBytes((Join-Path $script:IsoRoot 'session.json')))}
    $profiles=@($plan.profiles|ForEach-Object{[pscustomobject]@{name=$_.name;before=$_;after=$null;intent=$false;restored=$false}})
    $s=[pscustomobject][ordered]@{schema='unified-isolation-session-1';id=[guid]::NewGuid().ToString('N');owner=$q.policy.owner;phase='prepared';health='not_yet_armed';created_utc=[datetime]::UtcNow.ToString('o');entries=@();foreign=@();profiles=$profiles;plan=$null;guardian_utc='';guardian_error=''}
    IsoSave $s;IsoInstallController $s;$started=$true;$s=Invoke-IsoArm $s $plan (IsoNativeOps)
   }
   $s.health='configuration_verified_not_packet_tested';IsoSave $s
   Start-ScheduledTask -TaskName (IsoTaskName $s) -TaskPath '\' -ErrorAction Stop
   $result=@{ok=$true;isolation_status=(IsoSummary $s);firewall_change_status='native_transaction_completed_configuration_only';no_leak_certified=$false}
  }
 }elseif($Mode -ceq 'Status'){$result=@{ok=$true;isolation_status=(IsoSummary $s)}}
 elseif($Mode -ceq 'Restore' -and $null -ne $s){
  if(-not $Request){throw 'iso_explicit_restore_request_required'};$q=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request));if($q.confirmation -cne 'RESTORE ISOLATION'){throw 'iso_restore_consent_required'}
  # The operation lock excludes the guardian during Restore. Keep its task
  # registered on preflight failure; remove it only after a completed Restore.
  $started=$true;$s=Restore-IsoSession $s (IsoNativeOps);IsoTaskStop $s;$summary=IsoSummary $s;if(-not $summary.restoration_verified_now){throw 'iso_restore_post_cleanup_verification_failed'};$result=@{ok=$true;isolation_status=$summary;firewall_change_status='scoped_restore_verified_current_snapshot_only';no_leak_certified=$false}
 }
 if($null -eq $result){$result=@{ok=$true;isolation_status=(IsoSummary $null)}}
}catch{$result=@{ok=$false;error=[string]$_.Exception.Message;firewall_change_status=$(if($started){'unknown_or_partial_inspect_protected_journal_no_automatic_Allow'}else{'no_firewall_mutation_started_by_this_request'});no_leak_certified=$false}}
finally{if($null -ne $guardLock){$guardLock.Dispose()}}
if($Output){UAssertPath $Output;$json=ConvertTo-Json -InputObject $result -Depth 48;[IO.File]::WriteAllText($Output,$json,(New-Object Text.UTF8Encoding($false)))}else{$result|ConvertTo-Json -Depth 48}
if(-not $result.ok){exit 1}
