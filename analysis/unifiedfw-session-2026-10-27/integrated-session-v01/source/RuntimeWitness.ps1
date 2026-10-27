# Same private journal, lock, chain and parser; no new portable approval file.
function Get-UfwWindowsBootMarker {
 $os=@(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop)
 if($os.Count -ne 1 -or $os[0].LastBootUpTime -isnot [datetime] -or [string]::IsNullOrWhiteSpace([string]$os[0].CSName)){throw 'ufw_unified_witness_boot_observation'}
 # Boot identity correlation, not authenticated boot or an anti-rollback counter.
 return Get-UfwJournalHash (([string]$os[0].CSName).ToUpperInvariant()+'|'+$os[0].LastBootUpTime.ToUniversalTime().ToString('o'))
}
function Connect-UfwRuntimeWitness($Context,$Storage,[scriptblock]$BootProbe){
 if($Context.used -or $null -ne $Context.witness -or $null -eq $BootProbe){throw 'ufw_unified_witness_connect_order'}
 $back=Read-UfwUnifiedStorage $Storage
 if($back.sequence -lt 1 -or $back.records[0].data.binding -cne $Context.live.view.binding){throw 'ufw_unified_witness_policy_binding'}
 $state=Get-UfwLocalBackendState ([pscustomobject]@{storage=$Storage;view=$back.records[0].data})
 if($state.closed -or $state.restore_started -or $null -ne $state.runtime_arm){throw 'ufw_unified_witness_connect_order'}
 $Context.witness=[pscustomobject]@{storage=$Storage;boot=$BootProbe;armed=$false;evidence_saved=$false;arm=$null}
}
function Write-UfwRuntimeArm($Context){
 $w=$Context.witness
 if($null -eq $w -or $w.armed){throw 'ufw_unified_witness_arm_order'}
 $fresh=& $Context.ops.Load $Context.path;Assert-UfwBoundRuntimeRecord $Context $fresh
 if((& $Context.ops.Actor) -cne $Context.actor -or -not (Test-UfwLiveLease $Context.live)){throw 'ufw_unified_witness_live_binding'}
 $boot=& $w.boot
 $back=Read-UfwUnifiedStorage $w.storage
 $state=Get-UfwLocalBackendState ([pscustomobject]@{storage=$w.storage;view=$back.records[0].data})
 if($state.closed -or $state.restore_started -or $null -ne $state.runtime_arm -or $state.saved.Count -ne $back.records[0].data.operations.Count -or $state.results -ne $state.saved.Count){throw 'ufw_unified_witness_arm_order'}
 $programs=Get-UfwCandidateJson @($fresh.data.programs|Sort-Object program_id)
 $arm=[pscustomobject][ordered]@{schema='ufw-runtime-arm-01';phase='manual_window_may_open';actor_sid=$Context.actor;candidate_head=$fresh.head;programs_json=$programs;programs_sha256=$Context.program_digest;view_binding=$Context.live.view.binding;boot_marker=$boot}
 Assert-UfwRuntimeWitnessPayload $arm 'runtime_arm' $back.records[0].data.binding $null
 # Durable intent/readback BEFORE Window. Any uncertainty must prevent the UI.
 Write-UfwUnifiedStorage $w.storage 'runtime_arm' $arm|Out-Null
 $check=Get-UfwLocalBackendState ([pscustomobject]@{storage=$w.storage;view=$back.records[0].data})
 if((Get-UfwLocalJson $check.runtime_arm) -cne (Get-UfwLocalJson $arm)){throw 'ufw_unified_witness_arm_readback'}
 $w.arm=Copy-UfwLocalData $arm;$w.armed=$true
}
function Write-UfwRuntimeEvidence($Context){
 $w=$Context.witness
 if($null -eq $w -or -not $w.armed -or $w.evidence_saved -or $null -eq $Context.capture_result){throw 'ufw_unified_witness_evidence_order'}
 if((& $Context.ops.Actor) -cne $Context.actor -or (& $w.boot) -cne $w.arm.boot_marker){throw 'ufw_unified_witness_observation_changed'}
 # NO addresses, ports, command lines, DNS or packet payload. Lifecycle only.
 $events=@();$errors=1
 if($null -ne $Context.batch){
  $errors=$Context.batch.parse_errors
  foreach($e in $Context.batch.events){
   if($e.id -notin @(4688,4689,1101,1102,1104,4719)){continue}
   if($events.Count -ge 8192){throw 'ufw_unified_witness_events'}
   $events+=,[pscustomobject][ordered]@{id=$e.id;record=$e.record;pid=$e.pid;path=$e.path;parent_pid=$e.parent_pid;parent_path=$e.parent_path;actor=$e.actor}
  }
 }
 if($events.Count -gt 8192){throw 'ufw_unified_witness_events'}
 $json=Get-UfwLocalJson $events;$r=$Context.capture_result
 $proof=[pscustomobject][ordered]@{schema='ufw-runtime-evidence-01';arm_sha256=(Get-UfwJournalHash (Get-UfwLocalJson $w.arm));events_json=$json;events_sha256=(Get-UfwJournalHash $json);parse_errors=$errors;capture_code=$r.code;capture_completed=$r.completed;audit_restore_verified=$r.audit_restore_verified;capture_interrupted=$r.capture_interrupted}
 Assert-UfwRuntimeWitnessPayload $proof 'runtime_evidence' $w.arm.view_binding $w.arm
 $back=Read-UfwUnifiedStorage $w.storage
 $state=Get-UfwLocalBackendState ([pscustomobject]@{storage=$w.storage;view=$back.records[0].data})
 if($state.closed -or $state.restore_started -or $null -eq $state.runtime_arm -or $null -ne $state.runtime_evidence -or (Get-UfwLocalJson $state.runtime_arm) -cne (Get-UfwLocalJson $w.arm)){throw 'ufw_unified_witness_evidence_order'}
 Write-UfwUnifiedStorage $w.storage 'runtime_evidence' $proof|Out-Null
 $check=Get-UfwLocalBackendState ([pscustomobject]@{storage=$w.storage;view=$back.records[0].data})
 if((Get-UfwLocalJson $check.runtime_evidence) -cne (Get-UfwLocalJson $proof)){throw 'ufw_unified_witness_evidence_readback'}
 $w.evidence_saved=$true
}
function Read-UfwRuntimeRecoveryWitness($Storage,[string]$Actor,[string]$CurrentBoot){
 $back=Read-UfwUnifiedStorage $Storage
 $state=Get-UfwLocalBackendState ([pscustomobject]@{storage=$Storage;view=$back.records[0].data})
 if($null -eq $state.runtime_arm){return [pscustomobject]@{status='no_durable_runtime_arm';may_have_run=$true;quiescence_authorized=$false;arm=$null;evidence=$null;same_boot=$false}}
 $arm=$state.runtime_arm
 if($Actor -cne $arm.actor_sid){throw 'ufw_unified_witness_actor_mismatch'}
 # Reuse the pinned real selection validator on recovery; no current EXE open.
 $programs=@(ConvertFrom-Json $arm.programs_json);Assert-UfwCandidatePrograms $programs
 if((Get-UfwCandidateProgramDigest $programs) -cne $arm.programs_sha256){throw 'ufw_unified_witness_programs'}
 $same=$CurrentBoot -cmatch '^[a-f0-9]{64}$' -and $CurrentBoot -ceq $arm.boot_marker
 return [pscustomobject]@{status=$(if($null -eq $state.runtime_evidence){'armed_capture_unknown'}else{'capture_evidence_not_quiescence_proof'});may_have_run=$true;quiescence_authorized=$false;arm=(Copy-UfwLocalData $arm);evidence=(Copy-UfwLocalData $state.runtime_evidence);same_boot=$same}
}
