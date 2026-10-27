param([string]$Root='/data/hf121-readonly-parity/HF121-READONLY-PARITY')
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
. (Join-Path $Root 'ReadOnly.Native.ps1');. (Join-Path $Root 'Comparison.Core.ps1')
$script:checks=0
function Assert($x,$m){$script:checks++;if(-not $x){throw $m}}
function Clone($x){ConvertFrom-Json (UJson $x)}
$image=[pscustomobject]@{rule=[pscustomobject]@{Name='PRIVATE_NAME';Enabled='1'};interface=[pscustomobject]@{InterfaceAlias=@('PRIVATE_ALIAS')};address=[pscustomobject]@{RemoteAddress=@('192.0.2.55')}}
$x=Compare-HF12Images $image (Clone $image) (Clone $image) 1
Assert ($x.result -ceq 'exact_match') 'exact'
$changed=Clone $image;$changed.rule.Enabled='2'
Assert ((Compare-HF12Images $image $image $changed 1).result -ceq 'changed_during_test') 'churn not parity'
Assert ((Compare-HF12Images $null $image $image 1).result -ceq 'changed_during_test') 'absent before'
Assert ((Compare-HF12Images $image $image $null 1).result -ceq 'changed_during_test') 'absent after'
Assert ((Compare-HF12Images $image $null $image 1).result -ceq 'bulk_image_missing') 'missing bulk'
$x=Compare-HF12Images $image $changed $image 2
Assert ($x.result -ceq 'unexplained_difference') 'stable bracket difference'
Assert (($x.different_fields -join ',') -ceq 'rule.Enabled') 'field only'
$changed=Clone $image;$changed.interface.InterfaceAlias=@('SECRET_OTHER_ALIAS');$changed.address.RemoteAddress=@('203.0.113.77')
$x=Compare-HF12Images $image $changed $image 1;$export=UJson $x
Assert (-not ($export -match 'PRIVATE|SECRET|192\.0\.2|203\.0\.113')) 'no private values or names'
Assert ($x.different_fields.Count -eq 2) 'two different fields'
$changed=Clone $image;$changed|Add-Member NoteProperty extra ([pscustomobject]@{secret='do not export'})
Assert ((Compare-HF12Images $image $changed $image 1).different_fields -contains 'image_shape') 'shape without values'
$changed=Clone $image;$changed.rule|Add-Member NoteProperty 'bad field PRIVATE' 'value'
Assert ((Compare-HF12Images $image $changed $image 1).different_fields -contains 'unexpected_field_name') 'sanitize property names'
try{throw 'private path and hostname'}catch{$safe=Get-HF12SafeError $_};Assert ($safe -ceq 'read_failed_see_stage') 'raw exception not exported'
try{throw 'filter_coverage'}catch{$safe=Get-HF12SafeError $_};Assert ($safe -ceq 'filter_coverage') 'known code preserved'
# Test orchestration with synthetic rule inventory and two images around snapshot.
$script:inventory=@();foreach($i in 1..7){$script:inventory+=,[pscustomobject]@{Name=('secret'+$i);PolicyStoreSourceType='Local';Enabled='True';Direction='Outbound';Action='Allow'}}
$script:reads=0;$script:snapshots=0;$script:storeReads=@();$script:mode='match'
function Get-NetFirewallRule{param($PolicyStore,$ErrorAction)return $script:inventory}
function UReadNative{param($Name,$Store)$script:reads++;$script:storeReads+=,$Store;Clone $image}
function Read-IsoBulkSnapshot{param($Store)$script:snapshots++;if($script:mode -ceq 'throw'){throw 'filter_coverage'};[pscustomobject]@{store=$Store}}
function Get-IsoBulkImage{param($Snapshot,$Name)if($script:mode -ceq 'missing'){return $null};Clone $image}
$r=Invoke-HF12StoreComparison 'PersistentStore' 4
Assert ($r.completed -and $r.sampled_parity) 'successful store'
Assert ($r.sample_count -eq 4 -and $script:reads -eq 8 -and $script:snapshots -eq 1) 'bounded sample bracketing'
Assert (@($script:storeReads|Where-Object{$_ -cne 'PersistentStore'}).Count -eq 0) 'same store'
Assert (-not ((UJson $r) -match 'secret|PRIVATE|192\.0\.2')) 'exported store excludes values'
$script:mode='missing';$r=Invoke-HF12StoreComparison 'ActiveStore' 2
Assert ($r.completed -and -not $r.sampled_parity) 'completed is not parity'
$script:mode='throw';$r=Invoke-HF12StoreComparison 'ActiveStore' 2
Assert (-not $r.completed -and -not $r.sampled_parity -and $r.error_code -ceq 'filter_coverage') 'native failure not pass'
$script:inventory=@();$r=Invoke-HF12StoreComparison 'PersistentStore' 4
Assert (-not $r.completed -and -not $r.sampled_parity -and $r.stage -ceq 'no_local_samples') 'empty sample not pass'
$failed=$false;try{Invoke-HF12StoreComparison 'PersistentStore' 100}catch{$failed=$true};Assert $failed 'bound enforced'
# Only read-only firewall command names can appear in the complete diagnostic scripts.
$allowed=@('Get-NetFirewallRule','Get-NetFirewallAddressFilter','Get-NetFirewallApplicationFilter','Get-NetFirewallInterfaceFilter','Get-NetFirewallInterfaceTypeFilter','Get-NetFirewallPortFilter','Get-NetFirewallSecurityFilter','Get-NetFirewallServiceFilter')
$allfiles=@(Get-ChildItem -LiteralPath $Root -Filter '*.ps1');$parseCount=0
foreach($f in $allfiles){
 $t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e)
 Assert ($e.Count -eq 0) ('parse '+$f.Name);$parseCount++
 foreach($node in $a.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
  $name=$node.GetCommandName()
  if($name -match 'NetFirewall'){Assert ($allowed -ccontains $name) 'no firewall mutation command'}
  Assert ($name -notmatch '^(Set-VpnConnection|Remove-VpnConnection|New-NetRoute|Set-NetRoute|Start-Service|Stop-Service|Set-ExecutionPolicy|Invoke-WebRequest|Invoke-RestMethod|Invoke-IsoArm|Restore-IsoSession)$') 'no mutator or network probe'
 }
}
$result=@{suite='hf12-readonly-parity-diagnostic';passed=$true;assertions=$script:checks;parsed_files=$parseCount;Windows_API_executed=$false;report_privacy_checks_passed=$true}
$result|ConvertTo-Json|Set-Content '/data/hf121-readonly-parity/model-tests.json';$result|ConvertTo-Json -Compress
