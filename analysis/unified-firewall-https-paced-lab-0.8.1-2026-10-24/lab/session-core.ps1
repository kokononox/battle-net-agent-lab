# Add-only owned-rule session, callbacks isolate all Windows calls.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function UJson($v){ConvertTo-Json -InputObject $v -Depth 64 -Compress}
function UHash([string]$v){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($v)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function UEqual($a,$b){(UJson $a) -ceq (UJson $b)}
function UAssertPath([string]$path){
 $p=[IO.Path]::GetFullPath($path)
 while($p){if([IO.File]::Exists($p) -or [IO.Directory]::Exists($p)){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'session_reparse_path'}};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
}
function UOpenPrivateFile([string]$Path,[IO.FileMode]$Mode){
 UAssertPath $Path
 if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
  # Supply owner/DACL AT creation, not in a later Set-Acl race window.
  $acl=New-Object Security.AccessControl.FileSecurity;$acl.SetAccessRuleProtection($true,$false)
  $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544');$acl.SetOwner($admins)
  foreach($sidText in @('S-1-5-32-544','S-1-5-18')){$sid=New-Object Security.Principal.SecurityIdentifier($sidText);$ar=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow');$acl.AddAccessRule($ar)}
  return (New-Object IO.FileStream($Path,$Mode,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl))
 }
 return [IO.File]::Open($Path,$Mode,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function UWritePrivateBytes([string]$Path,[byte[]]$Bytes){
 $f=UOpenPrivateFile $Path ([IO.FileMode]::CreateNew)
 try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
function USave([string]$Root,$s){
 UAssertPath $Root;$dest=Join-Path $Root 'session.json';UAssertPath $dest
 $payload=UJson $s;$bytes=[Text.Encoding]::UTF8.GetBytes((UJson ([ordered]@{payload=$payload;sha256=(UHash $payload)})))
 $tmp=Join-Path $Root ('next-'+[guid]::NewGuid().ToString('N')+'.tmp');$f=$null
 try{$f=UOpenPrivateFile $tmp ([IO.FileMode]::CreateNew);$f.Write($bytes,0,$bytes.Length);$f.Flush($true);$f.Dispose();$f=$null
  if([IO.File]::Exists($dest)){[IO.File]::Replace($tmp,$dest,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$dest)}
 }finally{if($null -ne $f){$f.Dispose()};if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}
function ULoad([string]$Root){
 $file=Join-Path $Root 'session.json';UAssertPath $file;if(-not [IO.File]::Exists($file)){return $null}
 if((Get-Item -LiteralPath $file).Length -gt 33554432){throw 'session_size'}
 $e=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($file))
 if((@($e.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'payload,sha256' -or $e.payload -isnot [string] -or (UHash $e.payload) -cne $e.sha256){throw 'session_integrity'}
 $s=ConvertFrom-Json -InputObject $e.payload
 if($s.schema -cne 'unified-owned-session-1' -or $s.phase -cnotin @('prepared','applying','applied','restoring','restored') -or $s.owner -cnotmatch '^[a-f0-9]{32}$' -or $s.id -cnotmatch '^[a-f0-9]{32}$' -or $s.entries -isnot [array] -or $s.entries.Count -gt 1024){throw 'session_schema'}
 $seen=@{};foreach($e in $s.entries){if($e.name -cnotmatch ('^UnifiedFW-'+$s.owner+'-(blacklist|whitelist)-[a-f0-9]{24}$') -or $seen.ContainsKey($e.name) -or $e.intent -isnot [bool] -or $e.removed -isnot [bool]){throw 'session_entry_schema'};$seen[$e.name]=$true}
 return $s
}
function UCheckpoint([scriptblock]$Hook,[string]$Label){if($null -ne $Hook){& $Hook $Label|Out-Null}}
function NewUSession([string]$Root,$Plan,[scriptblock]$Read){
 $old=ULoad $Root;if($null -ne $old -and $old.phase -cne 'restored'){throw 'restore_existing_session_before_apply'}
 if($Plan.owner -cnotmatch '^[a-f0-9]{32}$' -or $Plan.rules -isnot [array] -or $Plan.rules.Count -lt 1 -or $Plan.rules.Count -gt 1024){throw 'session_plan'}
 # Check ALL names before journaling or creating anything. Never adopt an existing rule.
 $entries=@();$seen=@{}
 foreach($r in $Plan.rules){if($seen.ContainsKey($r.name) -or $r.name -cnotmatch ('^UnifiedFW-'+$Plan.owner+'-(blacklist|whitelist)-[a-f0-9]{24}$') -or $r.owner -cne $Plan.owner){throw 'session_name'};$seen[$r.name]=$true
  if($null -ne (& $Read $r.name)){throw 'existing_rule_collision'}
  $entries+=,[pscustomobject][ordered]@{name=$r.name;rule=$r;intent=$false;disabled_image=$null;enabled_image=$null;removed=$false}
 }
 # Preserve previous evidence rather than silently overwrite it.
 if($null -ne $old){$history=Join-Path $Root ('restored-'+$old.id+'.json');if([IO.File]::Exists($history)){throw 'session_history_collision'};UWritePrivateBytes $history ([IO.File]::ReadAllBytes((Join-Path $Root 'session.json')))}
 $s=[pscustomobject][ordered]@{schema='unified-owned-session-1';id=[guid]::NewGuid().ToString('N');owner=$Plan.owner;phase='prepared';created_utc=[datetime]::UtcNow.ToString('o');plan=$Plan;entries=$entries}
 USave $Root $s;return $s
}
function InvokeUSession([string]$Root,[scriptblock]$Read,[scriptblock]$CreateDisabled,[scriptblock]$ValidateDisabled,[scriptblock]$EnabledImage,[scriptblock]$Enable,[scriptblock]$Hook=$null,[scriptblock]$ValidateCapture=$null){
 $s=ULoad $Root;if($null -eq $s -or $s.phase -cne 'prepared'){throw 'session_not_prepared'}
 $s.phase='applying';USave $Root $s
 foreach($e in $s.entries){
  if($null -ne (& $Read $e.name)){throw 'rule_appeared_before_create'}
  $e.intent=$true;USave $Root $s;UCheckpoint $Hook ('before_create:'+ $e.name)
  & $CreateDisabled $e.rule $s.id|Out-Null
  UCheckpoint $Hook ('after_create:'+ $e.name)
  $image=& $Read $e.name
  if($null -ne $ValidateCapture){
   # Record the exact freshly-created, DISABLED, ownership-checked image first.
   # A semantic validation failure is then restorable WITHOUT ever enabling it.
   & $ValidateCapture $image $e.rule $s.id|Out-Null
   $e.disabled_image=$image;$e.enabled_image=& $EnabledImage $image;USave $Root $s
   UCheckpoint $Hook ('captured:'+ $e.name)
  }
  & $ValidateDisabled $image $e.rule $s.id|Out-Null
  if($null -eq $ValidateCapture){$e.disabled_image=$image;$e.enabled_image=& $EnabledImage $image;USave $Root $s}
  UCheckpoint $Hook ('sealed:'+ $e.name)
  # Windows is not a CAS provider; re-read narrows, does not eliminate external races.
  if(-not (UEqual (& $Read $e.name) $e.disabled_image)){throw 'rule_changed_before_enable'}
  & $Enable $e.name|Out-Null;UCheckpoint $Hook ('after_enable:'+ $e.name)
  if(-not (UEqual (& $Read $e.name) $e.enabled_image)){throw 'rule_enable_readback_conflict'}
 }
 $s.phase='applied';USave $Root $s;UCheckpoint $Hook 'applied';return $s
}
function RestoreUSession([string]$Root,[scriptblock]$Read,[scriptblock]$Remove,[scriptblock]$Hook=$null){
 $s=ULoad $Root;if($null -eq $s){return $null};if($s.phase -ceq 'restored'){return $s}
 $s.phase='restoring';USave $Root $s
 for($i=$s.entries.Count-1;$i -ge 0;$i--){$e=$s.entries[$i];if(-not $e.intent){continue}
  $now=& $Read $e.name
  if($null -eq $now){$e.removed=$true;USave $Root $s;continue}
  if($e.removed){throw 'rule_reappeared_after_removal'}
  # Crash before sealing => leave the DISABLED orphan untouched, require inspection.
  if($null -eq $e.disabled_image -or $null -eq $e.enabled_image){throw ('unsealed_rule_requires_inspection:'+ $e.name)}
  if(-not (UEqual $now $e.disabled_image) -and -not (UEqual $now $e.enabled_image)){throw ('restore_rule_drift:'+ $e.name)}
  UCheckpoint $Hook ('before_remove:'+ $e.name)
  # Recheck after the hook / immediately before a destructive call.
  if(-not (UEqual (& $Read $e.name) $now)){throw 'restore_concurrent_change'}
  & $Remove $e.name|Out-Null;UCheckpoint $Hook ('after_remove:'+ $e.name)
  if($null -ne (& $Read $e.name)){throw 'restore_remove_readback_conflict'}
  $e.removed=$true;USave $Root $s
 }
 $s.phase='restored';USave $Root $s;return $s
}
