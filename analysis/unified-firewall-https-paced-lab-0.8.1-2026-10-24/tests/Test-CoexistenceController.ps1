param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){throw 'Linux_only_controller_harness_not_a_Windows_acceptance_test'}
$Root=[IO.Path]::GetFullPath($Root);$state=Join-Path $Root 'private-state'
if([IO.Directory]::Exists($state)){throw 'harness_requires_clean_development_copy_no_private_state'}
$base=Join-Path ([IO.Path]::GetTempPath()) ('CoexController-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($base)
$checks=0
function Check([bool]$OK,[string]$Why){$script:checks++;if(-not $OK){throw ('controller_assertion:'+ $Why)}}
$doubles=@'
# TEST DOUBLES ONLY. No Windows cmdlets or external network are used.
$script:case='__CASE__';$script:db=@{foreign=[pscustomobject]@{tag='preserve_foreign'}}
$script:creates=0;$script:enables=0;$script:removes=0;$script:probes=0;$script:injected=$false
function Clone($Value){ConvertFrom-Json -InputObject (UJson $Value)}
function UAdmin{}
function Import-Module{param($Name,$ErrorAction)}
function UValidateRequest($Data){}
function Join-Path{param($Path,$ChildPath)
 if($Path -ceq '__ROOT__' -and $ChildPath -like 'runtime/*'){return ('C:\Fixture\'+$ChildPath.Replace('/','\'))}
 Microsoft.PowerShell.Management\Join-Path $Path $ChildPath
}
function UReadEnvironment{[pscustomobject]@{profiles=@('Domain','Private','Public'|ForEach-Object{[pscustomobject]@{enabled='True';allow_local_rules='True'}});vpn_query_errors=@();vpn=@([pscustomobject]@{status='Connected';tunnel='Sstp'});authenticated_bypass_filter_ids=@();legacy_enabled_rule_names=@()}}
function CReadRoute($Address){
 if($script:case -ceq 'route_rejected'){throw 'mock_endpoint_not_on_sstp'}
 if($script:case -ceq 'route_change' -and $script:db.Count -gt 1){throw 'mock_route_change_during_active_rules'}
 [pscustomobject]@{address=$Address;interface_index=42;source_ipv4='10.20.30.40';packet_path_proven=$false}
}
function USecureRoot($Create){return '__JOURNAL__'}
function UReadNative($Name,$Store){if($script:db.ContainsKey($Name)){return (Clone $script:db[$Name])};return $null}
function UCreateNative($Rule,$ID){$script:creates++;$script:db[$Rule.name]=[pscustomobject]@{rule=[pscustomobject]@{Enabled='2';Name=$Rule.name};session=$ID;component=$Rule.component;spec=(Clone $Rule.spec)}}
function UValidateCaptureNative($Image,$Rule,$ID){if($Image.rule.Enabled -cne '2' -or $Image.session -cne $ID){throw 'mock_capture_error'}}
function UValidateNative($Image,$Rule,$ID,$Store,$Enabled){
 if($script:case -ceq 'semantic_failure' -and -not $script:injected){$script:injected=$true;throw 'mock_semantic_failure_after_capture'}
 if($Image.session -cne $ID -or -not (UEqual $Image.spec $Rule.spec)){throw 'mock_native_validation'}
}
function UEnableNative($Name){$script:enables++;$script:db[$Name].rule.Enabled='1'}
function URemoveNative($Name){$script:removes++;$script:db.Remove($Name)}
function ReadPolicyInventory{[pscustomobject]@{rows=@($script:db.Keys|Sort-Object|ForEach-Object{Clone $script:db[$_]})}}
function ComparePolicyInventory($Before,$After){[pscustomobject]@{strict_equal=(UEqual $Before $After)}}
function Get-FileHash{param($LiteralPath,$Algorithm,$ErrorAction) [pscustomobject]@{Hash=('A'*64)}}
function TReference($Address,$Port,$Challenge){$script:probes++;[pscustomobject]@{schema='unifiedfw-tcp-probe-1';role='REF';request_id=$Challenge.request_id;probe_valid=$true;connected=($script:case -cne 'baseline_unreachable');handshake_ok=($script:case -cne 'baseline_unreachable')}}
function TRunProcess($Exe,$Script,$Request,$Output){
 if($Script.EndsWith('coexistence-classify.py')){
  & python3 $Script --request $Request --output $Output
  if($LASTEXITCODE -ne 0){throw 'real_classifier_failed'}
  return (ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Output)))
 }
 $script:probes++;$probeRequest=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Request));$challenge=$probeRequest.challenge
 $blocked=@($script:db.Values|Where-Object{$null -ne $_.PSObject.Properties['spec'] -and $_.spec.program -ceq $Exe}).Count -gt 0
 if($script:case -ceq 'drift' -and $blocked -and -not $script:injected){$script:injected=$true;$name=@($script:db.Keys|Where-Object{$_ -cne 'foreign'})[0];Add-Member -InputObject $script:db[$name] -NotePropertyName foreign_drift -NotePropertyValue $true}
 [pscustomobject]@{schema='unifiedfw-tcp-probe-1';role=$challenge.role;request_id=$challenge.request_id;probe_valid=$true;connected=(-not $blocked);handshake_ok=(-not $blocked)}
}
'@
try{
 $exe=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
 foreach($case in @('success','readonly','route_rejected','baseline_unreachable','route_change','semantic_failure','drift')){
  $job=Join-Path $Root ('private-state/coexistence-jobs/harness-'+$case);$journal=Join-Path $base ($case+'-journal');$null=[IO.Directory]::CreateDirectory($job);$null=[IO.Directory]::CreateDirectory($journal)
  $request=Join-Path $job 'request.json';$output=Join-Path $job 'result.json';Copy-Item -LiteralPath (Join-Path $Root 'tests/coexistence-request.json') -Destination $request
  $source=[IO.File]::ReadAllText((Join-Path $Root 'lab/coexistence-manage.ps1'))
  # Only platform plumbing is translated: literal module base path and Linux
  # slash for the same containment check. Main controller body is unchanged.
  $source=$source.Replace('$PSScriptRoot',("'"+($Root+"/lab").Replace("'","''")+"'"))
  $source=$source.Replace('TrimEnd([char]92)+[char]92','TrimEnd([char]47)+[char]47')
  $injected=$doubles.Replace('__CASE__',$case).Replace('__ROOT__',$Root).Replace('__JOURNAL__',$journal)
  $source=$source.Replace('$root=Split-Path',($injected+"`n"+'$root=Split-Path'))
  $receipt=Join-Path $job 'harness-receipt.json'
  $save='[IO.File]::WriteAllText('+("'"+$receipt+"'")+', (UJson ([ordered]@{creates=$script:creates;enables=$script:enables;removes=$script:removes;probes=$script:probes;remaining=$script:db.Count;foreign_preserved=($script:db.foreign.tag -ceq ''preserve_foreign'')})))'
  $source=$source.Replace('exit $exitCode',($save+"`n"+'exit $exitCode'))
  $controller=Join-Path $base ($case+'.ps1');[IO.File]::WriteAllText($controller,$source)
  $args=@('-NoLogo','-NoProfile','-File',$controller,'-Request',$request,'-Output',$output);if($case -ceq 'readonly'){$args+='-ReadOnly'}
  & $exe @args|Out-Null
  $code=$LASTEXITCODE;$result=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($output));$receiptData=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receipt))
  Check $receiptData.foreign_preserved ($case+':foreign_preserved')
  if($case -ceq 'success'){
   Check ($code -eq 0 -and $result.completed -and $result.classification.outcome -ceq 'passed') 'complete_controller_matrix_passed'
   Check ($result.restore_verified -and $receiptData.remaining -eq 1 -and $receiptData.creates -eq 9 -and $receiptData.removes -eq 9) 'all_owned_rules_restored'
   Check ($receiptData.probes -eq 126 -and $result.route_check_count -ge 85) 'all_probes_and_round_route_guards'
   Check (-not $result.classification.global_whitelist_tested -and -not $result.classification.vpn_route_verified) 'no_overclaim'
  }elseif($case -ceq 'readonly'){
   Check ($code -eq 0 -and $result.completed -and $result.classification.outcome -ceq 'ready_for_scoped_test') 'preflight_only'
   Check ($receiptData.probes -eq 0 -and $receiptData.creates -eq 0 -and -not $result.firewall_mutation_attempted) 'readonly_no_network_no_rules'
  }elseif($case -cin @('route_rejected','baseline_unreachable')){
   Check ($code -ne 0 -and $result.classification.outcome -ceq 'inconclusive') ($case+':blocked_before_apply')
   Check ($receiptData.creates -eq 0 -and $receiptData.enables -eq 0 -and -not $result.firewall_mutation_attempted) ($case+':no_rule_mutation')
  }elseif($case -ceq 'drift'){
   Check ($code -ne 0 -and $result.classification.outcome -ceq 'inconclusive') 'drift_not_passed'
   Check ($result.cleanup -like 'restore_failed*' -and -not $result.restore_verified -and $receiptData.remaining -gt 1) 'drift_refused_not_force_deleted'
  }else{
   Check ($code -ne 0 -and $result.classification.outcome -ceq 'inconclusive') ($case+':not_passed')
   Check ($result.restore_verified -and $receiptData.remaining -eq 1 -and $receiptData.creates -eq $receiptData.removes) ($case+':restored_after_error')
   if($case -ceq 'semantic_failure'){Check ($receiptData.enables -eq 0) 'semantic_failure_never_enabled'}
  }
 }
 $report=[ordered]@{passed=$true;assertions=$checks;cases=@('success','readonly','route_rejected','baseline_unreachable','route_change','semantic_failure','drift');backend='Linux controller body with platform separator translation, native/network/route test doubles and real Python classifier';windows_executed=$false;external_network_used=$false;fixed_file_admission_stubbed=$true}
 [IO.File]::WriteAllText((Join-Path $Root 'evidence/coexistence-controller-tests.json'),(ConvertTo-Json -InputObject $report -Depth 8));$report|ConvertTo-Json -Compress
}finally{
 if([IO.Directory]::Exists($base)){[IO.Directory]::Delete($base,$true)}
 if([IO.Directory]::Exists($state)){[IO.Directory]::Delete($state,$true)}
}
