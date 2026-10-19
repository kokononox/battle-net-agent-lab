# Read-only subset: no locks, journal writes, rule mutations or recovery calls.
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Ranges.ps1')
. (Join-Path $PSScriptRoot 'Inventory.ps1')
function JournalHash([string]$Text) {
 $sha=[Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}

function AssertJournalPath([string]$Path) {
 if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or $Path -match '(^|[\\/])\.\.([\\/]|$)') { throw 'journal_path' }
 $full=[IO.Path]::GetFullPath($Path)
 if ($full.Substring(2).Contains(':')) { throw 'journal_path' }
 $item=$full
 while ($item) {
  if (Test-Path -LiteralPath $item) {
   if ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'journal_reparse' }
  }
  $parent=[IO.Path]::GetDirectoryName($item)
  if ($parent -eq $item) { break };$item=$parent
 }
 return $full
}

function AssertJournalAcl([string]$Root) {
 $acl=Get-Acl -LiteralPath $Root
 if (-not $acl.AreAccessRulesProtected) { throw 'journal_acl_inheritance' }
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'journal_acl_owner' }
 $seen=@{}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  $sid=$rule.IdentityReference.Value
  if ($sid -notin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.IsInherited) { throw 'journal_acl_rule' }
  if (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -eq 0 -or ($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -eq 0 -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'journal_acl_children' }
  $seen[$sid]=$true
 }
 if ($seen.Count -ne 2) { throw 'journal_acl_missing' }
}

function ReadJournalFile([string]$Path) {
 $Path=AssertJournalPath $Path
 if (-not [IO.File]::Exists($Path)) { return $null }
 if ((Get-Item -LiteralPath $Path).Length -gt 1048576) { throw 'journal_size' }
 $e=[IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8) | ConvertFrom-Json
 if ((($e.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'payload,schema,sha256' -or $e.schema -ne 'sstp-journal-envelope-1' -or $e.payload -isnot [string] -or $e.sha256 -cne (JournalHash $e.payload)) { throw 'journal_integrity' }
 $p=$e.payload | ConvertFrom-Json
 if ((($p.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'revision,schema,state' -or $p.schema -ne 'sstp-journal-1' -or $p.revision -isnot [int] -or $p.revision -lt 0 -or $null -eq $p.state) { throw 'journal_schema' }
 return $p
}

function OverlayHash($Value){JournalHash (ConvertTo-Json -InputObject $Value -Depth 24 -Compress)}

function OverlayClone($Value){ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 24 -Compress)}

function OverlayExpected($Object,[bool]$Enabled){
 $x=OverlayClone $Object.original;$x.rule.Enabled='2';if($Enabled){$x.rule.Enabled='1'};return $x
}

function OverlayRead([string]$Name,[string]$Store='PersistentStore'){
 $rows=@(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop|Where-Object{[string]$_.Name -ceq $Name})
 if($rows.Count -eq 0){return $null};if($rows.Count -ne 1){throw 'overlay_rule_duplicate'}
 $r=$rows[0];$image=[ordered]@{rule=(InventoryRaw $r)};$view=[ordered]@{}
 foreach($pair in @(@('address','Get-NetFirewallAddressFilter'),@('application','Get-NetFirewallApplicationFilter'),@('interface','Get-NetFirewallInterfaceFilter'),@('interface_type','Get-NetFirewallInterfaceTypeFilter'),@('port','Get-NetFirewallPortFilter'),@('security','Get-NetFirewallSecurityFilter'),@('service','Get-NetFirewallServiceFilter'))){
  $f=@(& $pair[1] -AssociatedNetFirewallRule $r -ErrorAction Stop)
  if($f.Count -ne 1){throw 'overlay_filter_count'};$image[$pair[0]]=InventoryRaw $f[0]
  switch($pair[0]){
   'application'{$view.program=[string]$f[0].Program}
   'service'{$view.service=[string]$f[0].Service}
   'interface'{$view.alias=@($f[0].InterfaceAlias)}
   'interface_type'{$view.interface_type=[string]$f[0].InterfaceType}
   'port'{$view.protocol=[string]$f[0].Protocol;$view.local_port=@($f[0].LocalPort);$view.remote_port=@($f[0].RemotePort)}
   'address'{$view.local=@($f[0].LocalAddress);$view.remote=@($f[0].RemoteAddress)}
  }
 }
 [pscustomobject]@{image=[pscustomobject]$image;rule=$r;view=[pscustomobject]$view}
}

function AssertOverlaySemantic($Spec,$Read,[bool]$Enabled){
 if($null -eq $Read){throw 'overlay_rule_missing'}
 $r=$Read.rule;$v=$Read.view
 $value='False';if($Enabled){$value='True'}
 if([string]$r.Name -cne $Spec.name -or [string]$r.DisplayName -cne $Spec.name -or [string]$r.Description -cne 'Destination overlay test build; not an independent kill switch' -or [string]$r.Group -cne $Spec.group -or [string]$r.Enabled -cne $value -or [string]$r.Direction -cne 'Outbound' -or [string]$r.Action -cne 'Block' -or [string]$r.Profile -cne 'Any'){throw 'overlay_rule_semantic'}
 if([string]$v.program -ine $Spec.program -or [string]$v.service -cne 'Any' -or (@($v.alias)-join ',') -cne 'Any' -or [string]$v.interface_type -cne $Spec.interface_type -or [string]$v.protocol -cnotin @('Any','256') -or (@($v.local)-join ',') -cne 'Any'){throw 'overlay_filter_semantic'}
 if((@($v.local_port)-join ',') -cne 'Any' -or (@($v.remote_port)-join ',') -cne 'Any'){throw 'overlay_port_semantic'}
 $remote=@($v.remote)
 if($Spec.kind -ceq 'guard'){if(($remote-join ',') -cne 'Any'){throw 'overlay_guard_semantic'}}
 elseif((IntervalSignature $remote) -cne (IntervalSignature $Spec.remote)){throw 'overlay_address_semantic'}
}

function AssertOverlayState($State){
 if($null -eq $State -or $State.schema -cne 'sstp-destination-overlay-1' -or $State.session -cnotmatch '^[a-f0-9]{32}$' -or $State.phase -cnotin @('staging','prepared','enabling','active','disabling','inactive','removing','removed') -or $State.objects -isnot [array] -or $State.objects.Count -ne 3){throw 'overlay_state_schema'}
 $kinds=@('guard','v4','v6');$pos=0
 foreach($o in $State.objects){
  if($o.spec.kind -cne $kinds[$pos] -or $o.spec.name -cne ('SstpDestinationOverlay-'+$State.session+'-'+$kinds[$pos]) -or $o.spec.group -cne ('SstpDestinationOverlay-'+$State.session) -or $o.exists -isnot [bool] -or $o.enabled -isnot [bool]){throw 'overlay_state_identity'}
  if($State.scope -ceq 'RemoteAccess'){
   if($o.spec.interface_type -cne 'RemoteAccess' -or $o.spec.program -cne 'Any'){throw 'overlay_state_scope'}
  }elseif($State.scope -ceq 'Fixture'){
   if($o.spec.interface_type -cne 'Any' -or [IO.Path]::GetFileName($o.spec.program) -cnotmatch '^sstp-overlay-fixture-[a-f0-9]{32}\.exe$' -or -not [IO.Path]::IsPathRooted($o.spec.program)){throw 'overlay_state_fixture'}
  }else{throw 'overlay_state_scope'}
  if($null -ne $o.original -and $o.original.rule.Enabled -cne '2'){throw 'overlay_state_original'}
  if($o.exists -and $null -eq $o.original){throw 'overlay_state_original'}
  $pos++
 }
 if($null -ne $State.pending){if($State.pending.index -isnot [int] -or $State.pending.index -lt 0 -or $State.pending.index -gt 2 -or $State.pending.operation -cnotin @('set','delete','create')){throw 'overlay_state_pending'}}
}

