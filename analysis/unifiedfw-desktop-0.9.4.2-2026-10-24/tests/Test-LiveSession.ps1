param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1')
$script:checks=0;$script:db=@{};$script:creates=0;$script:enables=0;$script:removes=0
function Check([bool]$ok,[string]$why){$script:checks++;if(-not $ok){throw ('assertion:'+ $why)}}
function Throws([scriptblock]$body,[string]$pattern){$caught=$false;try{& $body|Out-Null}catch{$caught=$true;Check ($_.Exception.Message -like $pattern) ('error:'+ $_.Exception.Message)};Check $caught 'expected_throw'}
function Clone($v){ConvertFrom-Json -InputObject (UJson $v)}
$owner='0123456789abcdef0123456789abcdef'
$rules=@();foreach($i in 1..4){$component='blacklist';if($i -gt 2){$component='whitelist'};$name='UnifiedFW-'+$owner+'-'+$component+'-'+$i.ToString('x24');$rules+=,[pscustomobject]@{name=$name;owner=$owner;component=$component;spec=[pscustomobject]@{number=$i}}}
$plan=[pscustomobject]@{owner=$owner;rules=$rules}
$read={param($name) if($script:db.ContainsKey($name)){Clone $script:db[$name]}else{$null}}
$create={param($r,$id) $script:creates++;if($script:db.ContainsKey($r.name)){throw 'mock_collision'};$script:db[$r.name]=[pscustomobject][ordered]@{name=$r.name;session=$id;spec=$r.spec;enabled=$false;extra='full-behavior-image'}}
$validate={param($image,$rule,$id) if($null -eq $image -or $image.enabled -or $image.name -cne $rule.name -or $image.session -cne $id -or -not (UEqual $image.spec $rule.spec)){throw 'mock_validation'}}
$enabled={param($image) $copy=Clone $image;$copy.enabled=$true;return $copy}
$enable={param($name) $script:enables++;$script:db[$name].enabled=$true}
$remove={param($name) $script:removes++;$script:db.Remove($name)}
$base=Join-Path ([IO.Path]::GetTempPath()) ('UnifiedLive-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($base)
function Fresh([string]$label){$dir=Join-Path $base $label;$null=[IO.Directory]::CreateDirectory($dir);$script:db=@{foreign=[pscustomobject]@{action='Block';tag='never_touch'}};$script:creates=0;$script:enables=0;$script:removes=0;return $dir}
try{
 $dir=Fresh 'normal';$s=NewUSession $dir $plan $read;Check ($s.phase -ceq 'prepared') 'prepared'
 $s=InvokeUSession $dir $read $create $validate $enabled $enable
 Check ($s.phase -ceq 'applied' -and $script:creates -eq 4 -and $script:enables -eq 4) 'joint_apply'
 Check ($script:db.Count -eq 5) 'all_components_plus_foreign'
 Throws {NewUSession $dir $plan $read} 'restore_existing_session_before_apply'
 $s=RestoreUSession $dir $read $remove;Check ($s.phase -ceq 'restored' -and $script:db.Count -eq 1 -and $script:removes -eq 4) 'joint_restore'
 $null=RestoreUSession $dir $read $remove;Check ($script:removes -eq 4) 'restore_idempotent'
 $oldID=$s.id;$null=NewUSession $dir $plan $read;Check ([IO.File]::Exists((Join-Path $dir ('restored-'+$oldID+'.json')))) 'evidence_preserved'
 $dir=Fresh 'collision';$script:db[$rules[2].name]=[pscustomobject]@{foreign='same_name'};Throws {NewUSession $dir $plan $read} 'existing_rule_collision';Check ($script:creates -eq 0 -and -not [IO.File]::Exists((Join-Path $dir 'session.json'))) 'collision_no_write'
 # All 4 persisted-intent / creation / sealing / enable checkpoints and final commit.
 $labels=@();foreach($r in $rules){foreach($stage in @('before_create','after_create','sealed','after_enable')){$labels+=,($stage+':'+$r.name)}};$labels+=,'applied'
 $cases=@();$index=0
 foreach($label in $labels){$index++;$dir=Fresh ('failure-'+$index);$null=NewUSession $dir $plan $read;$script:failLabel=$label
  $hook={param($at) if($at -ceq $script:failLabel){throw 'injected'}}
  Throws {InvokeUSession $dir $read $create $validate $enabled $enable $hook} 'injected'
  # Reload journal from disk, no in-memory session supplied to Restore.
  $reload=ULoad $dir;Check ($null -ne $reload) 'reload_after_failure'
  if($label.StartsWith('after_create:')){
   Throws {RestoreUSession $dir $read $remove} 'unsealed_rule_requires_inspection:*'
   $unsealed=$label.Substring('after_create:'.Length);Check (-not $script:db[$unsealed].enabled) 'unsealed_never_enabled'
   # Do not claim automatic recovery for a crash in this intentionally fail-closed window.
   $cases+=,[pscustomobject]@{checkpoint=$label;result='disabled_orphan_requires_inspection'}
  }else{
   $s=RestoreUSession $dir $read $remove;Check ($s.phase -ceq 'restored' -and $script:db.Count -eq 1) 'recovery_restores_exact_foreign_only'
   $cases+=,[pscustomobject]@{checkpoint=$label;result='restored'}
  }
 }
 # Removal interruptions recover idempotently, including removal before journal save.
 foreach($stage in @('before_remove','after_remove')){foreach($r in $rules){
  $dir=Fresh ('restore-'+$stage+'-'+$r.spec.number);$null=NewUSession $dir $plan $read;$null=InvokeUSession $dir $read $create $validate $enabled $enable
  $script:failLabel=$stage+':'+$r.name;$hook={param($at) if($at -ceq $script:failLabel){throw 'injected'}}
  Throws {RestoreUSession $dir $read $remove $hook} 'injected'
  $s=RestoreUSession $dir $read $remove;Check ($s.phase -ceq 'restored' -and $script:db.Count -eq 1) 'restore_interruption_recovery'
 }}
 $dir=Fresh 'drift';$null=NewUSession $dir $plan $read;$null=InvokeUSession $dir $read $create $validate $enabled $enable
 $script:db[$rules[3].name].extra='external_change';$before=UJson $script:db[$rules[3].name]
 Throws {RestoreUSession $dir $read $remove} 'restore_rule_drift:*';Check ((UJson $script:db[$rules[3].name]) -ceq $before -and $script:removes -eq 0) 'drift_never_deleted'
 $dir=Fresh 'concurrent';$null=NewUSession $dir $plan $read;$null=InvokeUSession $dir $read $create $validate $enabled $enable
 $hook={param($at) if($at.StartsWith('before_remove:')){$name=$at.Substring('before_remove:'.Length);$script:db[$name].extra='concurrent'}}
 Throws {RestoreUSession $dir $read $remove $hook} 'restore_concurrent_change';Check ($script:removes -eq 0) 'reread_before_remove'
 $dir=Fresh 'tamper';$null=NewUSession $dir $plan $read;$file=Join-Path $dir 'session.json';$raw=[IO.File]::ReadAllText($file);[IO.File]::WriteAllText($file,$raw.Replace('prepared','applying'))
 Throws {ULoad $dir} 'session_integrity';Check ($script:creates -eq 0) 'tamper_no_mutation'
 $dir=Fresh 'reappeared';$null=NewUSession $dir $plan $read;$null=InvokeUSession $dir $read $create $validate $enabled $enable
 $script:failLabel='after_remove:'+$rules[3].name;$hook={param($at) if($at -ceq $script:failLabel){throw 'injected'}}
 Throws {RestoreUSession $dir $read $remove $hook} 'injected';$s=RestoreUSession $dir $read $remove
 # A completed Restore is never run again to delete rules appearing afterwards.
 $script:db[$rules[3].name]=[pscustomobject]@{foreign='new_rule'};$null=RestoreUSession $dir $read $remove;Check ($script:db.ContainsKey($rules[3].name)) 'completed_restore_does_not_delete_later_rule'
 # New capture-before-semantic-validation path: semantic failure stays Disabled and restorable.
 $dir=Fresh 'semantic-failure-after-capture';$null=NewUSession $dir $plan $read
 Throws {InvokeUSession $dir $read $create {throw 'semantic-invalid'} $enabled $enable -ValidateCapture $validate} 'semantic-invalid'
 $s=ULoad $dir
 Check ($null -ne $s.entries[0].disabled_image -and $script:enables -eq 0) 'semantic_failure_recorded_before_enable'
 $s=RestoreUSession $dir $read $remove
 Check ($s.phase -ceq 'restored' -and $script:db.Count -eq 1) 'semantic_failure_restores_exact_capture'
 foreach($r in $rules){
  $dir=Fresh ('captured-'+$r.spec.number);$null=NewUSession $dir $plan $read;$script:failLabel='captured:'+$r.name
  $hook={param($at) if($at -ceq $script:failLabel){throw 'injected'}}
  Throws {InvokeUSession $dir $read $create $validate $enabled $enable -Hook $hook -ValidateCapture $validate} 'injected'
  $s=RestoreUSession $dir $read $remove;Check ($s.phase -ceq 'restored' -and $script:db.Count -eq 1) 'capture_checkpoint_recovery'
 }
 $report=[ordered]@{assertions=$script:checks;passed=$true;apply_exception_checkpoints=$labels.Count;restore_exception_checkpoints=8;capture_exception_checkpoints=4;semantic_failure_after_capture_tested=$true;windows_executed=$false;disabled_orphan_manual_inspection_cases=4;cases=$cases}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence/live-session-tests.json'),(ConvertTo-Json -InputObject $report -Depth 16))
 [pscustomobject]@{passed=$true;assertions=$script:checks;apply_checkpoints=17;restore_checkpoints=8;capture_checkpoints=4}|ConvertTo-Json -Compress
}finally{if([IO.Directory]::Exists($base)){[IO.Directory]::Delete($base,$true)}}
