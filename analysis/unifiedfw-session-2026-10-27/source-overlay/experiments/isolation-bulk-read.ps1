# READ-ONLY PROTOTYPE; intentionally not imported by any controller or launcher.
# Needs lab/native.ps1 (UParts and URaw). Not an atomic view; never mutation/readback proof.
function IsoBulkIndex($Rows,[string]$Key){
 $index=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
 foreach($r in @($Rows)){
  $p=$r.PSObject.Properties[$Key]
  if($null -eq $p -or [string]::IsNullOrEmpty([string]$p.Value)){throw 'iso_bulk_missing_identity'}
  $id=[string]$p.Value;if($index.ContainsKey($id)){throw 'iso_bulk_duplicate_identity'}
  $index.Add($id,$r)
 };return ,$index
}
function Read-IsoBulkSnapshot([string]$Store='PersistentStore'){
 if($Store -cnotin @('PersistentStore','ActiveStore')){throw 'iso_bulk_store'}
 $rules=IsoBulkIndex @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop) 'Name'
 $parts=[ordered]@{}
 foreach($part in $script:UParts.Keys){$parts[$part]=IsoBulkIndex @(& $script:UParts[$part] -PolicyStore $Store -ErrorAction Stop) 'InstanceID'}
 return [pscustomobject]@{store=$Store;rules=$rules;parts=$parts;atomic=$false;mutation_qualified=$false}
}
function Get-IsoBulkImage($Snapshot,[string]$Name){
 if(-not $Snapshot.rules.ContainsKey($Name)){return $null}
 $r=$Snapshot.rules[$Name];if([string]$r.PolicyStoreSourceType -cne 'Local'){throw 'not_local_rule'}
 # Name can be a PowerShell-adapted alias, absent from raw CimInstanceProperties.
 if([string]$r.Name -cne $Name){throw 'iso_bulk_rule_identity'}
 $raw=URaw $r
 $image=[ordered]@{rule=$raw}
 foreach($part in $script:UParts.Keys){
  if(-not $Snapshot.parts[$part].ContainsKey($Name)){throw 'filter_coverage'}
  $raw=URaw $Snapshot.parts[$part][$Name];if([string]$raw.InstanceID -cne $Name){throw 'filter_identity'}
  $image[$part]=$raw
 };return [pscustomobject]$image
}
