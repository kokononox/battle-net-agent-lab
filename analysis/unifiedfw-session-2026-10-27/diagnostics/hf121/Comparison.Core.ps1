# No image values, rule names, IP addresses, program paths, or aliases are returned.
function Get-HF12DifferenceFields($A,$B){
 $out=@()
 foreach($part in @(@($A.PSObject.Properties.Name)+@($B.PSObject.Properties.Name)|Sort-Object -Unique)){
  $ap=$A.PSObject.Properties[$part];$bp=$B.PSObject.Properties[$part]
  if($null -eq $ap -or $null -eq $bp){$out+='image_shape';continue}
  foreach($field in @(@($ap.Value.PSObject.Properties.Name)+@($bp.Value.PSObject.Properties.Name)|Sort-Object -Unique)){
   $af=$ap.Value.PSObject.Properties[$field];$bf=$bp.Value.PSObject.Properties[$field]
   if($null -ne $af -and $null -ne $bf -and (UEqual $af.Value $bf.Value)){continue}
   $label=[string]$part+'.'+[string]$field
   if($label -cnotmatch '^[A-Za-z0-9_.]{1,96}$'){$label='unexpected_field_name'}
   $out+=,$label
  }
 };return ,@($out|Sort-Object -Unique)
}
function Compare-HF12Images($Before,$Bulk,$After,[int]$Index){
 $r=[ordered]@{index=$Index;result='';different_fields=@()}
 if($null -eq $Before -or $null -eq $After -or -not (UEqual $Before $After)){$r.result='changed_during_test'}
 elseif($null -eq $Bulk){$r.result='bulk_image_missing'}
 elseif(UEqual $Before $Bulk){$r.result='exact_match'}
 else{$r.result='unexplained_difference';$r.different_fields=Get-HF12DifferenceFields $Before $Bulk}
 return [pscustomobject]$r
}
function Get-HF12SafeError($Record){
 $message=[string]$Record.Exception.Message
 $codes=@('iso_bulk_missing_identity','iso_bulk_duplicate_identity','iso_bulk_store','not_local_rule','iso_bulk_rule_identity','filter_coverage','filter_identity','duplicate_rule_identity','unsupported_cim_image_type','windows_required','administrator_required','powershell_51_64bit_required','payload_hash_mismatch','local_non_reparse_folder_required','unexpected_test_rule_name')
 if($codes -ccontains $message){return $message};return 'read_failed_see_stage'
}
function Invoke-HF12StoreComparison([string]$Store,[int]$MaxSamples=4){
 if($Store -cnotin @('PersistentStore','ActiveStore') -or $MaxSamples -lt 1 -or $MaxSamples -gt 8){throw 'invalid_comparison_parameters'}
 $report=[ordered]@{store=$Store;stage='selecting';completed=$false;total_rules=0;local_rules=0;sample_count=0;sample_results=@();error_code='';error_type='';error_script='';error_line=0;bulk_collections_expected=8;atomic=$false;sampled_parity=$false}
 try{
  Write-Host ('['+$Store+'] Selecting at most '+$MaxSamples+' local rules...')
  $all=@(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop);$report.total_rules=$all.Count
  $local=@($all|Where-Object{[string]$_.PolicyStoreSourceType -ceq 'Local'});$report.local_rules=$local.Count
  # Prioritize enabled outbound Allows, then select remaining local rules deterministically.
  $ordered=@($local|Sort-Object @{Expression={if([string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow'){0}else{1}}},Name)
  $names=@($ordered|Select-Object -First $MaxSamples|ForEach-Object{[string]$_.Name})
  $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach($name in $names){if([string]::IsNullOrEmpty($name) -or -not $seen.Add($name)){throw 'unexpected_test_rule_name'}}
  $report.sample_count=$names.Count
  if(-not $names.Count){$report.stage='no_local_samples';return [pscustomobject]$report}
  $before=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  $i=0;foreach($name in $names){$i++;$report.stage='legacy_before_'+$i;Write-Host ('['+$Store+'] Original read '+$i+'/'+$names.Count+' (before)');$before.Add($name,(UReadNative $name $Store))}
  $report.stage='bulk_snapshot';Write-Host ('['+$Store+'] Reading rules and seven filter collections...')
  $snapshot=Read-IsoBulkSnapshot $Store
  $i=0;foreach($name in $names){
   $i++;$report.stage='bulk_image_'+$i;Write-Host ('['+$Store+'] Original read '+$i+'/'+$names.Count+' (after), then compare')
   $bulk=Get-IsoBulkImage $snapshot $name;$report.stage='legacy_after_'+$i;$after=UReadNative $name $Store
   $report.stage='compare_images_'+$i
   $report.sample_results+=,(Compare-HF12Images $before[$name] $bulk $after $i)
  }
  $report.completed=$true;$report.stage='completed'
  $report.sampled_parity=(@($report.sample_results|Where-Object{$_.result -cne 'exact_match'}).Count -eq 0)
 }catch{$report.error_code=Get-HF12SafeError $_;$report.error_type=$_.Exception.GetType().Name
  if($null -ne $_.InvocationInfo){
   $leaf=[IO.Path]::GetFileName([string]$_.InvocationInfo.ScriptName)
   if($leaf -cin @('Bulk.ReadOnly.ps1','ReadOnly.Native.ps1','Comparison.Core.ps1')){$report.error_script=$leaf;$report.error_line=[int]$_.InvocationInfo.ScriptLineNumber}
  };Write-Host ('['+$Store+'] Stopped at '+$report.stage+': '+$report.error_code)}
 return [pscustomobject]$report
}
