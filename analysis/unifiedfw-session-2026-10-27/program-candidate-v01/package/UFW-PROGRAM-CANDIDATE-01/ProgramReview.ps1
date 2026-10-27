Set-StrictMode -Version 2.0
function Select-UfwProgramFiles {
 if([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA){throw 'ufw_program_file_picker_sta_required'}
 Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
 $dialog=New-Object System.Windows.Forms.OpenFileDialog
 try{
  $dialog.Title='Select installer EXE (Ctrl-click for explicitly known helper EXEs)'
  $dialog.Filter='Executable files (*.exe)|*.exe'
  $dialog.Multiselect=$true;$dialog.CheckFileExists=$true;$dialog.CheckPathExists=$true
  $dialog.ValidateNames=$true;$dialog.DereferenceLinks=$false;$dialog.RestoreDirectory=$true
  $dialog.AutoUpgradeEnabled=$false;$dialog.AddExtension=$false
  $dialog.InitialDirectory=[IO.Path]::GetPathRoot([Environment]::SystemDirectory)
  if($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK){return [pscustomobject]@{cancelled=$true;paths=@()}}
  return [pscustomobject]@{cancelled=$false;paths=@($dialog.FileNames)}
 }finally{$dialog.Dispose()}
}
function Read-UfwProgramNativeObservation([string]$Path){return [UfwProgramReview01.Reader]::Observe($Path)}
function Invoke-UfwProgramLocalReview {
 $r=[ordered]@{schema='ufw-program-local-review-result-011';completed=$false;code='';selection_method='windows_open_file_dialog';picker_completed=$false;selection_cancelled=$false;selected_count=0;observed_count=0;review_displayed=$false;results=@();raw_identity_exported=$false;program_config_saved=$false;program_trusted=$false;authenticode_verification_requested=$false;program_execution_requested=$false;firewall_change_requested=$false;journal_write_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
 $private=@();$seen=@{};$selection=$null
 try{
  Write-Host 'Choose the existing installer EXE in the file selection window; it will NOT be executed.'
  Write-Host 'One file is enough. Ctrl-click only explicitly known helper EXEs; maximum 16 files.'
  Write-Host 'Cancel performs no EXE identity observation by this tool. Use a local fixed drive.'
  Write-Host 'Do not navigate to network locations, enable previews, or share screenshots/transcripts.'
  $selection=Select-UfwProgramFiles
  if($null -eq $selection -or $selection.cancelled -isnot [bool] -or $selection.paths -isnot [array]){throw 'ufw_program_picker_invalid_result'}
  $r.picker_completed=$true
  if($selection.cancelled){if($selection.paths.Count -ne 0){throw 'ufw_program_picker_invalid_result'};$r.selection_cancelled=$true;$r.completed=$true;$r.code='ufw_program_cancelled_no_selection';return [pscustomobject]$r}
  $r.selected_count=$selection.paths.Count
  if($r.selected_count -lt 1 -or $r.selected_count -gt 16){throw 'ufw_program_selection_count'}
  # Validate the entire selection before opening any selected EXE, avoiding partial work on malformed input.
  $selectedPaths=@{}
  foreach($path in $selection.paths){
   if($path -isnot [string]){throw 'ufw_program_picker_invalid_result'}
   [void][UfwProgramReview01.Reader]::ValidatePathText($path)
   if($selectedPaths.ContainsKey($path.ToLowerInvariant())){throw 'ufw_program_duplicate_selection'}
   $selectedPaths[$path.ToLowerInvariant()]=$true
  }
  $idx=0
  foreach($path in $selection.paths){
   $idx++;$item=Read-UfwProgramNativeObservation $path
   if($seen.ContainsKey($item.Path.ToLowerInvariant()) -or $seen.ContainsKey($item.VolumeId+':'+$item.FileId)){throw 'ufw_program_duplicate_selection'}
   $seen[$item.Path.ToLowerInvariant()]=$true;$seen[$item.VolumeId+':'+$item.FileId]=$true
   $private+=,$item;$r.observed_count++
   $r.results+=,[pscustomobject][ordered]@{program_number=$idx;header_architecture=$item.Architecture;same_handle_double_hash_matched=$item.SameHandleDoubleHashMatched;native_identity_observed=$item.NativeIdentityObserved;authenticode_verified=$false;program_trusted=$false;execution_authorized=$false}
   Write-Host ('Observed program '+$idx+'; EXE header '+$item.Architecture+'. No execution or permission granted.')
  }
  Write-Host 'LOCAL PRIVATE REVIEW ONLY -- do not share this table.'
  foreach($p in $private){Write-Host ('Path: '+$p.Path);Write-Host ('SHA256: '+$p.Sha256);Write-Host ('Local file identity: '+$p.VolumeId+':'+$p.FileId);Write-Host ('Length: '+$p.Length+'; architecture: '+$p.Architecture)}
  $r.review_displayed=$true;$r.completed=$true;$r.code='ufw_program_observed_review_only_no_authority'
  Write-Host 'NOT code trust, signature approval, saved policy, consent or an Apply-ready plan.'
 }catch{
  $msg=[string]$_.Exception.GetBaseException().Message
  if($msg -cmatch '^ufw_program_[a-z_0-9]{1,100}$'){$r.code=$msg}else{$r.code='ufw_program_observation_unavailable'}
 }finally{$private=@();$seen=@{};$selection=$null}
 return [pscustomobject]$r
}
