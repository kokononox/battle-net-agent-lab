$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$report=[ordered]@{schema='ufw-prepare-session-diagnostic-01';completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;payload_verified=$false;preparation=$null;scope='prepare_profile_journal_only_not_firewall_consent';real_legacy_journal_access_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$module=$null;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);$p=$root
 if($root.StartsWith('\')){throw 'ufw_prepare_local_folder_required'}
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_prepare_reparse_path'};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
 $dest=Join-Path $root ('UFW-PREPARE-SESSION-01-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_prepare_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_prepare_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_prepare_admin_required'}
 $report.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "Ufw.ProfileReader.psm1": "ddd2575ddc177e6e4eedd67c14a1aa7b1bfe17723cea973d6648f7582f788bcc",
  "Ufw.InstallerCore.psm1": "c072f580e20864053870f32c2560bba9fc973b7a28ffca76423af618d7d575cb",
  "Ufw.SessionJournal.psm1": "968085dda94525faba1292a9d3e0ff15e41d3dd14827e13b5c1c3d17b0050d72",
  "PreparationEntry.ps1": "010a775490158d8b2baa4a2681566abd0271a7f9c71032a26afb1496002c46c1"
}
'@
 foreach($item in $hashes.PSObject.Properties){$file=Join-Path $root $item.Name;if(([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $item.Value){throw 'ufw_prepare_payload_mismatch'}}
 $report.payload_verified=$true;. (Join-Path $root 'PreparationEntry.ps1')
 $module=Import-Module (Join-Path $root 'Ufw.SessionJournal.psm1') -Force -PassThru -ErrorAction Stop
 Write-Host 'Reading current profile settings only. Keep network and VPN unchanged.'
 Write-Host 'A new preparation journal can be written ONLY after exact manual confirmation.'
 Write-Host 'No isolation Apply/Restore or legacy journal access will be requested.'
 $report.stage='read_review_and_optional_preparation';$report.preparation=Invoke-UfwPreparationEntry $module
 $report.code=$report.preparation.code
 if($report.preparation.completed){$report.completed=$true;$report.stage='completed';$rc=0}
 Write-Host ('Preparation result: '+$report.code)
 Write-Host ('Journal write status: '+$report.preparation.journal_write_status)
}catch{
 $msg=[string]$_.Exception.GetBaseException().Message
 if($msg -cmatch '^(ufw_prepare|ufw_journal|ufw_core|ufw_read)_[a-z_0-9]{1,100}$'){$report.code=$msg}else{$report.code='ufw_prepare_unavailable'}
 Write-Host ('Stopped at '+$report.stage+': '+$report.code)
}finally{
 if($null -ne $module){Remove-Module $module.Name -Force -ErrorAction SilentlyContinue}
 if($null -ne $dest){try{$bytes=[Text.Encoding]::UTF8.GetBytes(($report|ConvertTo-Json -Depth 24));$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Host ('Report: '+$dest)}catch{Write-Host 'Report could not be saved. Return only the stage/code text.';$rc=1}}
 Write-Host 'Return only the NEW UFW-PREPARE-SESSION-01-*.json, including cancel/failure.'
 Write-Host 'Do NOT send protected files, challenge, screenshot, or transcript.'
 Write-Host 'This is NOT isolation, normal-mode restoration, reboot qualification or a no-leak certificate.'
}
exit $rc
