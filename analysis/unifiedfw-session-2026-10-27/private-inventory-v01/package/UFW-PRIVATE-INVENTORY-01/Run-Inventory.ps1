$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$r=[ordered]@{schema='ufw-private-inventory-diagnostic-01';completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;payload_verified=$false;inventory=$null;firewall_change_requested=$false;audit_change_requested=$false;candidate_access_requested=$false;legacy_baseline_access_requested=$false;security_log_access_requested=$false;target_execution_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;raw_rule_identity_exported=$false;runtime_execution_authorized=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$module=$null;$mutex=$null;$ownsMutex=$false;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);if($root.StartsWith('\')){throw 'ufw_inventory_local_folder_required'};$p=$root
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_inventory_reparse_path'};$q=[IO.Path]::GetDirectoryName($p);if($p -eq $q){break};$p=$q}
 $dest=Join-Path $root ('UFW-PRIVATE-INVENTORY-01-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_inventory_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_inventory_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_inventory_admin_required'}
 $mutex=New-Object Threading.Mutex($false,'Global\UnifiedFW-PrivateInventory-01');try{$ownsMutex=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$ownsMutex=$true};if(-not $ownsMutex){throw 'ufw_inventory_another_session_active'}
 $r.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "Ufw.ProfileReader.psm1": "ddd2575ddc177e6e4eedd67c14a1aa7b1bfe17723cea973d6648f7582f788bcc",
  "Ufw.InstallerCore.psm1": "c072f580e20864053870f32c2560bba9fc973b7a28ffca76423af618d7d575cb",
  "Ufw.SessionJournal.psm1": "968085dda94525faba1292a9d3e0ff15e41d3dd14827e13b5c1c3d17b0050d72",
  "InventoryCore.ps1": "0716e80c189d9b1062f687a4b46a0327e5f6d2ace6615ffe78de71747691a586",
  "InventoryEntry.ps1": "fa955d5ef79a5d32dc6a98a0b988dadde76156fda4ad9e88c75b8c3b38bc4366"
}
'@
 foreach($v in $hashes.PSObject.Properties){$f=Join-Path $root $v.Name;if(([IO.File]::GetAttributes($f) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $v.Value){throw 'ufw_inventory_payload_mismatch'}}
 $r.payload_verified=$true;$r.stage='load_private_storage_helpers'
 $module=Import-Module (Join-Path $root 'Ufw.SessionJournal.psm1') -Force -PassThru -ErrorAction Stop
 $r.stage='private_inventory_storage_only'
 $r.inventory=& $module {param($root). (Join-Path $root 'InventoryCore.ps1');. (Join-Path $root 'InventoryEntry.ps1');Invoke-UfwInventoryNative} $root
 $r.code=$r.inventory.code;if($r.inventory.completed){$r.completed=$true;$r.stage='completed';$rc=0}
 Write-Host ('Result: '+$r.code)
 if($null -ne $r.inventory){Write-Host ('Rules read: '+$r.inventory.rules_read+'; rules with filter sets: '+$r.inventory.rules_with_filter_sets+'; private readback: '+$r.inventory.private_snapshot_readback_verified)}
}catch{$msg=[string]$_.Exception.GetBaseException().Message;if($msg -cmatch '^ufw_inventory_[a-z_0-9]{1,80}$'){$r.code=$msg}else{$r.code='ufw_inventory_unavailable'};Write-Host ('Stopped: '+$r.code)}
finally{
 if($null -ne $module){Remove-Module $module.Name -Force -ErrorAction SilentlyContinue};if($ownsMutex){try{$mutex.ReleaseMutex()}catch{}};if($null -ne $mutex){$mutex.Dispose()}
 if($null -ne $dest){try{$bytes=[Text.Encoding]::UTF8.GetBytes(($r|ConvertTo-Json -Depth 12));$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Host ('Report: '+$dest)}catch{Write-Host 'Report save failed; return only the short stage/code, without private paths.';$rc=1}}
 Write-Host 'Return only NEW UFW-PRIVATE-INVENTORY-01-*.json. No installer launch, audit changes or firewall changes are authorized. Do not share private-policy-snapshot.json, screenshots, raw rule exports or transcripts.'
}
exit $rc
