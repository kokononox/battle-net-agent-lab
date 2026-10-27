Set-StrictMode -Version 2.0
function Invoke-UfwProgramLocalReview {
 $r=[ordered]@{schema='ufw-program-local-review-result-01';completed=$false;code='';selected_count=0;observed_count=0;review_displayed=$false;results=@();raw_identity_exported=$false;program_config_saved=$false;program_trusted=$false;authenticode_verification_requested=$false;program_execution_requested=$false;firewall_change_requested=$false;journal_write_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
 $private=@();$seen=@{}
 try{
  Write-Host 'Select ONLY the installer EXE and any helper EXEs you explicitly want reviewed.'
  Write-Host 'Programs will NOT be executed. No file picker, shell launch, trust check or DNS request.'
  Write-Host 'Enter one full local EXE path at a time; blank ends selection (maximum 16).'
  Write-Host 'Do not send paths, file hashes, file IDs or a screenshot/transcript.'
  while($r.selected_count -lt 16){
   $answer=Read-Host ('EXE '+($r.selected_count+1)+' full path, or Enter to finish')
   if([string]::IsNullOrEmpty($answer)){break}
   if($answer.Length -ge 2 -and $answer.StartsWith('"') -and $answer.EndsWith('"')){$answer=$answer.Substring(1,$answer.Length-2)}
   $r.selected_count++;$idx=$r.selected_count
   $item=Read-UfwProgramNativeObservation $answer
   if($seen.ContainsKey($item.Path.ToLowerInvariant()) -or $seen.ContainsKey($item.VolumeId+':'+$item.FileId)){throw 'ufw_program_duplicate_selection'}
   $seen[$item.Path.ToLowerInvariant()]=$true;$seen[$item.VolumeId+':'+$item.FileId]=$true
   $private+=,$item;$r.observed_count++
   $r.results+=,[pscustomobject][ordered]@{program_number=$idx;header_architecture=$item.Architecture;same_handle_double_hash_matched=$item.SameHandleDoubleHashMatched;native_identity_observed=$item.NativeIdentityObserved;authenticode_verified=$false;program_trusted=$false;execution_authorized=$false}
   Write-Host ('Observed program '+$idx+'; EXE header '+$item.Architecture+'. No execution or permission granted.')
  }
  if($r.selected_count -eq 0){$r.completed=$true;$r.code='ufw_program_cancelled_no_selection';return [pscustomobject]$r}
  Write-Host 'LOCAL PRIVATE REVIEW ONLY -- do not share this table.'
  foreach($p in $private){Write-Host ('Path: '+$p.Path);Write-Host ('SHA256: '+$p.Sha256);Write-Host ('Local file identity: '+$p.VolumeId+':'+$p.FileId);Write-Host ('Length: '+$p.Length+'; architecture: '+$p.Architecture)}
  $r.review_displayed=$true;$r.completed=$true;$r.code='ufw_program_observed_review_only_no_authority'
  Write-Host 'These observations are NOT code trust, signature approval, saved policy, consent or an Apply-ready plan.'
 }catch{
  $msg=[string]$_.Exception.GetBaseException().Message
  if($msg -cmatch '^ufw_program_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_program_observation_unavailable'}
 }finally{$private=@();$seen=@{};$answer=$null}
 return [pscustomobject]$r
}
function Read-UfwProgramNativeObservation([string]$Path){return [UfwProgramReview01.Reader]::Observe($Path)}
