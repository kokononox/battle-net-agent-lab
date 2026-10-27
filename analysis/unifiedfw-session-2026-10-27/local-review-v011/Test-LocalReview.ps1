param([string]$Root='/data/sstp-local-review-v011/package/SSTP-LOCAL-REVIEW-011')
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. (Join-Path $Root 'LocalReview.ps1')
$script:checks=0
function Check($b,$m){$script:checks++;if(-not $b){throw $m}}
function Reset-Fixture{
 $script:mode='normal';$script:life=0;$script:snap=0;$script:display=0;$script:prompt=0
 $script:expected=[pscustomobject]@{schema='sstp-observer-selection-1';profile_guid='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';profile_scope='current_user';profile_name='Fixture';server='vpn.fixture.invalid';owner_sid='S-1-5-21-1-2-3-1001'}
}
function Invoke-SstpLifecycleObservation{param($Expected,[ref]$PrivateBinding,$PreviousBinding=$null)
 $script:life++;$PrivateBinding.Value=[pscustomobject]@{marker='private-binding'}
 [pscustomobject]@{code=$(if($script:mode -ceq 'identity_failure'){'observer_selected_profile_changed'}else{'live_identity_observed_not_enforcement_qualified'});completed=($script:mode -cne 'identity_failure');identity_chain_verified=($script:mode -cne 'identity_failure');binding_compared_to_previous=($null -ne $PreviousBinding);binding_changed_since_previous=($script:mode -ceq 'binding_change' -and $script:life -ge 3)}
}
function Read-EndpointNativeSnapshot($Server){
 $script:snap++;$ip=if($script:mode -ceq 'address_change' -and $script:snap -ge 3){'192.0.2.11'}else{'192.0.2.10'}
 $key='192.0.2.50|50001|'+$ip+'|443|123|123456789'
 $m=@('SstpSvc');if($script:mode -ceq 'shared'){$m=@('Other','SstpSvc')}
 $keys=@($key);if($script:mode -ceq 'multiple'){$keys+=,'192.0.2.50|50002|192.0.2.10|443|123|123456789'}
 if($script:mode -ceq 'cold'){$keys=@()}
 $ownerPid=123;if($script:mode -ceq 'pid_change' -and $script:snap -ge 3){$ownerPid=124}
 $creation=1;if($script:mode -ceq 'creation_change' -and $script:snap -ge 3){$creation=2}
 $hash='private-file-hash';if($script:mode -ceq 'hash_change' -and $script:snap -ge 3){$hash='changed'}
 if($script:mode -ceq 'tuple_change' -and $script:snap -ge 3){$keys=@('192.0.2.50|50002|192.0.2.10|443|123|123456789')}
 if($script:mode -ceq 'intra_host_change' -and $script:snap -eq 2){$creation=2}
 [pscustomobject]@{pid=$ownerPid;creation=$creation;image_hash=$hash;members=$m;matches=$keys;flow_keys=@('private-flow');mapping_source=$(if($script:mode -ceq 'cold'){'local_cache_unresolved'}else{'local_cache_not_trusted_pin'});address_count=$(if($script:mode -ceq 'cold'){0}else{1})}
}
function Show-SstpReviewCandidate($Candidate){$script:display++;Check ($Candidate.draft.transport_templates[0].remote_address -ceq '192.0.2.10') 'actual address displayed';Check (-not $Candidate.draft.ready_for_apply) 'display not authorization'}
function Read-SstpLocalReviewAnswer($Challenge){
 $script:prompt++;Check ($Challenge -cmatch '^REVIEW [a-f0-9]{12}$') 'fresh challenge shape'
 switch($script:mode){'cancel'{return ''};'wrong'{return 'REVIEW yes'};'lowercase'{return $Challenge.ToLowerInvariant()};'raw_error'{throw 'PRIVATE_SERVER_PATH'};default{return $Challenge}}
}
Reset-Fixture;$r=Invoke-SstpLocalEndpointReview $script:expected
Check ($r.completed -and $r.draft_review_acknowledged -and $r.fresh_revalidation_passed) 'success within invocation'
Check ($script:life -eq 4 -and $script:snap -eq 4 -and $script:display -eq 1 -and $script:prompt -eq 1) 'two captures around prompt'
foreach($k in @('persistent_approval_created','approval_authority_implemented','endpoint_pin_approved_for_firewall','raw_identity_exported','network_policy_changed','VPN_change_requested','DNS_query_generated','credentials_read','snapshots_atomic','ready_for_apply','no_leak_certified')){Check ($r.$k -ceq $false) ('boundary '+$k)}
Check (($r|ConvertTo-Json -Depth 10) -notmatch '192\.0\.2|fixture.invalid|private-binding|private-file-hash|aaaaaaaa') 'sanitized result'
foreach($case in @('cancel','wrong','lowercase')){Reset-Fixture;$script:mode=$case;$r=Invoke-SstpLocalEndpointReview $script:expected;Check ($r.completed -and $r.code -ceq 'review_cancelled' -and -not $r.manual_acknowledgment_received -and $script:snap -eq 2) 'cancel no recapture'}
foreach($case in @('identity_failure','shared','multiple','cold','intra_host_change')){Reset-Fixture;$script:mode=$case;$r=Invoke-SstpLocalEndpointReview $script:expected;Check (-not $r.completed -and -not $r.draft_review_acknowledged -and $script:prompt -eq 0) ('stop before prompt '+$case)}
foreach($case in @('address_change','pid_change','creation_change','hash_change','tuple_change','binding_change')){Reset-Fixture;$script:mode=$case;$r=Invoke-SstpLocalEndpointReview $script:expected;Check (-not $r.completed -and $r.manual_acknowledgment_received -and -not $r.draft_review_acknowledged -and -not $r.ready_for_apply) ('invalidate after prompt '+$case)}
Reset-Fixture;$script:expected.profile_scope='all_users';$r=Invoke-SstpLocalEndpointReview $script:expected;Check ($r.code -ceq 'review_current_user_only' -and $script:life -eq 0) 'unimplemented scope blocked'
Reset-Fixture;$script:mode='raw_error';$r=Invoke-SstpLocalEndpointReview $script:expected;Check ($r.code -ceq 'review_unavailable' -and ($r|ConvertTo-Json) -notmatch 'PRIVATE_SERVER_PATH') 'raw error redacted'
Reset-Fixture;$script:mode='identity_failure';$r=Invoke-SstpLocalEndpointReview $script:expected;Check ($r.code -ceq 'observer_selected_profile_changed') 'preserve lifecycle reason'
Reset-Fixture;$script:mode='cold';$r=Invoke-SstpLocalEndpointReview $script:expected
Check ($r.candidate_before_metrics.configured_address_count_before -eq 0 -and $r.candidate_before_metrics.stable_matched_tuple_count -eq 0) 'cold cache counters'
Check ($r.candidate_before_metrics.host_TCP443_count_before -eq 1 -and $r.candidate_before_metrics.configured_address_source_before -ceq 'local_cache_unresolved') 'cache and flow separated'
Reset-Fixture;$script:mode='multiple';$r=Invoke-SstpLocalEndpointReview $script:expected
Check ($r.candidate_before_metrics.matched_tuple_count_before -eq 2 -and $r.candidate_before_metrics.stable_matched_tuple_count -eq 2 -and -not $r.draft_review_acknowledged) 'ambiguity counters no relaxation'
Check (($r|ConvertTo-Json -Depth 12) -notmatch '192\.0\.2|private-flow|fixture.invalid|private-file-hash') 'metrics contain no raw identity'
[pscustomobject]@{schema='sstp-local-review-model-011';assertions=$script:checks;passed=$true;Windows_native_API_executed=$false;real_human_prompt_tested=$false;firewall_changed=$false;persistent_approval_implemented=$false;ready_for_apply=$false}|ConvertTo-Json|Set-Content -LiteralPath '/data/sstp-local-review-v011/MODEL-RESULTS.json' -Encoding UTF8
Write-Host ('PASS '+$script:checks+' assertions')
