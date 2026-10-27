$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
. '/data/hf121-readonly-parity/HF121-READONLY-PARITY/ReadOnly.Native.ps1'
function Fixture($Values){$x=[pscustomobject]$Values;$ps=@(foreach($key in $Values.Keys){[pscustomobject]@{Name=$key;Value=$Values[$key]}});$x|Add-Member NoteProperty CimInstanceProperties $ps;return $x}
# Model the real distinction: adapted .Name is NOT a native CIM property.
$r=Fixture ([ordered]@{InstanceID='rule-fixture';Enabled='1';PolicyStoreSourceType='Local'})
$r|Add-Member NoteProperty Name 'rule-fixture'
$f=Fixture ([ordered]@{InstanceID='rule-fixture';Values=@('value')})
$parts=[ordered]@{};foreach($part in $script:UParts.Keys){$parts[$part]=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal);$parts[$part].Add('rule-fixture',$f)}
$rules=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal);$rules.Add('rule-fixture',$r)
$snapshot=[pscustomobject]@{rules=$rules;parts=$parts}
# The old function must reproduce PropertyNotFoundException on precisely this fixture.
. '/data/hf12-readonly-parity/HF12-READONLY-PARITY/Bulk.ReadOnly.ps1'
$reproduced=$false;try{Get-IsoBulkImage $snapshot 'rule-fixture'|Out-Null}catch{$reproduced=$_.Exception.GetType().Name -ceq 'PropertyNotFoundException'}
if(-not $reproduced){throw 'old_failure_not_reproduced'}
. '/data/hf121-readonly-parity/HF121-READONLY-PARITY/Bulk.ReadOnly.ps1'
$now=Get-IsoBulkImage $snapshot 'rule-fixture'
$expected=[ordered]@{rule=(URaw $r)};foreach($part in $script:UParts.Keys){$expected[$part]=URaw $f}
if(-not (UEqual $now ([pscustomobject]$expected))){throw 'new_raw_image_changed'}
if($null -ne $now.rule.PSObject.Properties['Name']){throw 'name_invented_in_raw_image'}
$rules['rule-fixture'].Name='different'
$rejected=$false;try{Get-IsoBulkImage $snapshot 'rule-fixture'|Out-Null}catch{$rejected=$_.Exception.Message -ceq 'iso_bulk_rule_identity'}
if(-not $rejected){throw 'live_name_mismatch_not_rejected'}
@{suite='adapted-Name-not-in-CIM-regression';old_PropertyNotFound_reproduced=$true;fixed_raw_image_matches_legacy_shape=$true;no_raw_property_invented=$true;wrong_live_name_rejected=$true;Windows_API_executed=$false}|ConvertTo-Json|Set-Content '/data/hf121-readonly-parity/adapted-name-regression.json'
Write-Host 'Old failure reproduced; fixed reader preserves raw image and rejects wrong live name.'
