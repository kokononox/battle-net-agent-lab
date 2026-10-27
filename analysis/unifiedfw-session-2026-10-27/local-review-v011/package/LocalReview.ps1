# Local, memory-only review. No persisted approval authority, firewall or VPN executor.
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Endpoint.ps1')
. (Join-Path $PSScriptRoot 'Sstp.TransportPlan.ps1')
function Read-SstpReviewCandidate($Expected,$PreviousBinding=$null,[ref]$Diagnostics=$null){
 $metrics=[pscustomobject][ordered]@{stage='identity_before';configured_address_source_before='unknown';configured_address_source_after='unknown';configured_address_count_before=0;configured_address_count_after=0;host_TCP443_count_before=0;host_TCP443_count_after=0;matched_tuple_count_before=0;matched_tuple_count_after=0;stable_matched_tuple_count=0;identity_and_unshared_host_checks_passed=$false}
 if($null -ne $Diagnostics){$Diagnostics.Value=$metrics}
 if($Expected.profile_scope -cne 'current_user'){throw 'review_current_user_only'}
 $before=$null;$after=$null
 $first=Invoke-SstpLifecycleObservation $Expected ([ref]$before) $PreviousBinding
 if(-not $first.completed -or -not $first.identity_chain_verified -or $null -eq $before){
  $detail=$first.PSObject.Properties['code'];if($null -ne $detail -and [string]$detail.Value -cmatch '^observer_[a-z_0-9]{1,90}$'){throw ([string]$detail.Value)}
  throw 'review_live_identity_required'
 }
 if($null -ne $PreviousBinding -and (-not $first.binding_compared_to_previous -or $first.binding_changed_since_previous)){throw 'review_binding_changed'}
 $metrics.stage='endpoint_before';$a=Read-EndpointNativeSnapshot $Expected.server
 $metrics.configured_address_source_before=$a.mapping_source;$metrics.configured_address_count_before=[int]$a.address_count
 $metrics.host_TCP443_count_before=@($a.flow_keys).Count;$metrics.matched_tuple_count_before=@($a.matches).Count
 $metrics.stage='identity_after' 
 $last=Invoke-SstpLifecycleObservation $Expected ([ref]$after) $before
 if(-not $last.completed -or -not $last.identity_chain_verified -or $null -eq $after -or -not $last.binding_compared_to_previous -or $last.binding_changed_since_previous){
  $detail=$last.PSObject.Properties['code'];if($null -ne $detail -and [string]$detail.Value -cmatch '^observer_[a-z_0-9]{1,90}$'){throw ([string]$detail.Value)}
  throw 'review_binding_changed'
 }
 $metrics.stage='endpoint_after';$b=Read-EndpointNativeSnapshot $Expected.server
 $metrics.configured_address_source_after=$b.mapping_source;$metrics.configured_address_count_after=[int]$b.address_count
 $metrics.host_TCP443_count_after=@($b.flow_keys).Count;$metrics.matched_tuple_count_after=@($b.matches).Count
 foreach($k in @('pid','creation','image_hash')){if([string]$a.$k -cne [string]$b.$k){throw 'review_service_host_changed'}}
 if(@($a.members).Count -ne 1 -or @($b.members).Count -ne 1 -or $a.members[0] -cne 'SstpSvc' -or $b.members[0] -cne 'SstpSvc'){throw 'review_unshared_host_required'}
 $metrics.identity_and_unshared_host_checks_passed=$true;$metrics.stage='stable_tuple_check'
 $stable=@($a.matches|Where-Object{$b.matches -contains $_}|Sort-Object -Unique)
 $metrics.stable_matched_tuple_count=$stable.Count
 if($stable.Count -ne 1 -or @($a.matches).Count -ne 1 -or @($b.matches).Count -ne 1){throw 'review_unique_stable_endpoint_required'}
 $parts=([string]$stable[0]).Split('|');if($parts.Count -ne 6 -or $parts[3] -cne '443'){throw 'review_tuple_shape_unknown'}
 $address=ConvertTo-SstpPlanIP $parts[2]
 $inputRecord=[pscustomobject][ordered]@{schema='sstp-endpoint-review-input-01';profile_guid=$Expected.profile_guid;profile_scope=$Expected.profile_scope;profile_owner_sid=$Expected.owner_sid;server=$Expected.server;endpoint_ips=@($address)}
 $draft=New-SstpExactTransportDraft $inputRecord
 if(-not $draft.input_valid -or $draft.ready_for_apply -or $draft.plan_executable){throw 'review_draft_invalid'}
 $metrics.stage='candidate_ready'
 return [pscustomobject]@{binding=$after;draft=$draft;tuple=[string]$stable[0];pid=$b.pid;creation=$b.creation;image_hash=$b.image_hash}
}
function Show-SstpReviewCandidate($Candidate){
 # Raw data appears ONLY in this local console, not in the sanitized report.
 $n=$Candidate.draft.normalized_input
 Write-Host 'LOCAL DISPLAY ONLY - do not send a screenshot of this section.'
 Write-Host ('Profile GUID: '+$n.profile_guid)
 Write-Host ('Scope: '+$n.profile_scope)
 Write-Host ('Server in profile: '+$n.server)
 Write-Host ('Candidate IP: '+($n.endpoint_ips -join ', '))
 Write-Host 'Proposed transport: system svchost / SstpSvc / outbound TCP / remote port 443 / exact displayed IP.'
 Write-Host 'Physical adapter: not pinned. Application data: verified SSTP binding only.'
 Write-Host 'Source: existing connection correlated with configured server; NOT independent server authentication.'
 Write-Host 'Signature, service tag, DNS/TLS bootstrap and firewall enforcement are NOT verified.'
 Write-Host 'Confirmation acknowledges this draft only; it does not enable isolation or save an approved pin.'
}
function Read-SstpLocalReviewAnswer($Challenge){Read-Host ('Type exactly "'+$Challenge+'" to acknowledge this draft, or press Enter to cancel')}
function Invoke-SstpLocalEndpointReview($Expected){
 $r=[ordered]@{schema='sstp-local-review-011';completed=$false;stage='candidate_before';code='';candidate_before_metrics=$null;candidate_after_metrics=$null;candidate_displayed_locally=$false;manual_acknowledgment_received=$false;fresh_revalidation_passed=$false;draft_review_acknowledged=$false;approval_scope='none';persistent_approval_created=$false;approval_authority_implemented=$false;endpoint_pin_approved_for_firewall=$false;raw_identity_exported=$false;network_policy_changed=$false;VPN_change_requested=$false;DNS_query_generated=$false;credentials_read=$false;snapshots_atomic=$false;ready_for_apply=$false;no_leak_certified=$false}
 $before=$null;$after=$null;$answer=$null;$challenge=$null
 try{
  $metricsBefore=$null;$metricsAfter=$null
  $before=Read-SstpReviewCandidate $Expected $null ([ref]$metricsBefore)
  $r.stage='local_display';Show-SstpReviewCandidate $before;$r.candidate_displayed_locally=$true
  $challenge='REVIEW '+[guid]::NewGuid().ToString('N').Substring(0,12)
  $r.stage='local_confirmation';$answer=Read-SstpLocalReviewAnswer $challenge
  if($answer -isnot [string] -or $answer -cne $challenge){$r.completed=$true;$r.stage='completed';$r.code='review_cancelled';return [pscustomobject]$r}
  $r.manual_acknowledgment_received=$true
  $r.stage='fresh_revalidation';$after=Read-SstpReviewCandidate $Expected $before.binding ([ref]$metricsAfter)
  if($after.draft.input_digest -cne $before.draft.input_digest){throw 'review_candidate_changed_after_prompt'}
  foreach($k in @('tuple','pid','creation','image_hash')){if([string]$after.$k -cne [string]$before.$k){throw 'review_connection_changed_after_prompt'}}
  $r.fresh_revalidation_passed=$true;$r.draft_review_acknowledged=$true;$r.approval_scope='draft_acknowledgment_this_invocation_only_not_firewall_authorization'
  $r.completed=$true;$r.stage='completed';$r.code='review_draft_acknowledged_no_enforcement_authority'
 }catch{
  $m=[string]$_.Exception.GetBaseException().Message
  if($m -cmatch '^(review|observer|endpoint)_[a-z_0-9]{1,90}$'){$r.code=$m}else{$r.code='review_unavailable'}
 }finally{
  if($null -ne (Get-Variable metricsBefore -ErrorAction SilentlyContinue)){$r.candidate_before_metrics=$metricsBefore}
  if($null -ne (Get-Variable metricsAfter -ErrorAction SilentlyContinue)){$r.candidate_after_metrics=$metricsAfter}
  $before=$null;$after=$null;$answer=$null;$challenge=$null}
 return [pscustomobject]$r
}
