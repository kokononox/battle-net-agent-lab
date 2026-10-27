# Dedicated preparation-only entry. The journal module still has no native firewall writer.
Set-StrictMode -Version 2.0
function Invoke-UfwPreparationEntry($Module){
 return & $Module {
  $script:PreparationEntryContext=[pscustomobject]@{observations=@();review_shown=$false}
  try{
   $ops=New-UfwNativePreparationOps
   $ops.ReadObservation={
    $p=Invoke-UfwInstallerPreflightReadOnly
    $ctx=$script:PreparationEntryContext
    if($ctx.observations.Count -ge 3){throw 'ufw_journal_observation_limit'}
    $summary=[ordered]@{core_completed=$p.completed;core_code=$p.code;baseline_draft_constructible=$p.baseline_draft_constructible;reader_completed=$false;reader_code='not_available';native_profile_reads_attempted=0;two_observations_match=$false;profiles=@();reasons=@()}
    if($null -ne $p.profile_observation){
     $o=$p.profile_observation;$summary.reader_completed=$o.completed;$summary.reader_code=$o.code;$summary.native_profile_reads_attempted=$o.native_store_reads_attempted;$summary.two_observations_match=$o.two_observations_match
     if($null -ne $o.assessment){
      $summary.profiles=@($o.assessment.profiles|ForEach-Object{[pscustomobject][ordered]@{name=$_.name;local_outbound=$_.local_outbound;effective_outbound=$_.effective_outbound;local_enabled=$_.local_enabled;effective_enabled=$_.effective_enabled;local_allow_local_rules=$_.local_allow_local_rules;effective_allow_local_rules=$_.effective_allow_local_rules}})
      $summary.reasons=@($o.assessment.reasons)
     }
    }
    $ctx.observations+=,[pscustomobject]$summary
    if(-not $p.completed){throw 'ufw_journal_native_preflight_incomplete'}
    return $p.profile_observation
   }
   $ops.ShowReview={
    param($draft,$challenge)
    $script:PreparationEntryContext.review_shown=$true
    Write-Host 'PREPARATION JOURNAL ONLY. No firewall, VPN, route, rule or task change.'
    Write-Host 'The values below are the CURRENT baseline. Block will stay Block; nothing is converted to Allow.'
    $draft.entries|ForEach-Object{$_.before}|Format-Table name,local_outbound,effective_outbound,effective_enabled -AutoSize|Out-Host
    Write-Host 'Exact confirmation permits ONLY a NEW separate protected preparation record.'
    Write-Host 'It does NOT approve isolation, restore normal internet, or migrate the old journal.'
    Write-Host 'Enter or any other answer cancels. Confirmation expires after two minutes.'
    Write-Host 'Do not send the challenge, protected journal, or a screenshot of this prompt.'
   }
   $result=Invoke-UfwPreparationConsentCallbacks $ops
   $status='not_requested'
   if($result.journal_write_attempted){$status='attempted_may_exist_inspect_if_failed'}
   if($result.journal_preparation_recorded){$status='prepared_and_revalidated_no_firewall_authority'}
   return [pscustomobject][ordered]@{completed=$result.completed;code=$result.code;review_shown=$script:PreparationEntryContext.review_shown;consent_received=$result.consent_received;journal_write_attempted=$result.journal_write_attempted;journal_preparation_recorded=$result.journal_preparation_recorded;journal_write_status=$status;profile_observations=$script:PreparationEntryContext.observations;real_legacy_journal_access_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;normal_mode_restored=$false;original_restore_verified=$false;ready_for_apply=$false;no_leak_certified=$false}
  }finally{Remove-Variable PreparationEntryContext -Scope Script -ErrorAction SilentlyContinue}
 }
}
