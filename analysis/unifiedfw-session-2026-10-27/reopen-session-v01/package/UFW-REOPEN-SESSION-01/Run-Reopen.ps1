$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$report=[ordered]@{schema='ufw-reopen-session-diagnostic-01';completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;payload_verified=$false;validation=$null;scope='readonly_reopen_existing_prepared_session_no_authority';real_legacy_journal_access_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;journal_write_requested=$false;journal_repair_requested=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$module=$null;$rc=1
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);$p=$root
 if($root.StartsWith('\')){throw 'ufw_reopen_local_folder_required'}
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_reopen_reparse_path'};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
 $dest=Join-Path $root ('UFW-REOPEN-SESSION-01-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_reopen_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_reopen_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_reopen_admin_required'}
 $report.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "Ufw.ProfileReader.psm1": "ddd2575ddc177e6e4eedd67c14a1aa7b1bfe17723cea973d6648f7582f788bcc",
  "Ufw.InstallerCore.psm1": "c072f580e20864053870f32c2560bba9fc973b7a28ffca76423af618d7d575cb",
  "Ufw.SessionJournal.psm1": "968085dda94525faba1292a9d3e0ff15e41d3dd14827e13b5c1c3d17b0050d72",
  "ReopenEntry.ps1": "16e10b07ecf33f5fd71abdf2c059514733f9571b9b03ebd64498972c5f36a048"
}
'@
 foreach($item in $hashes.PSObject.Properties){$file=Join-Path $root $item.Name;if(([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $item.Value){throw 'ufw_reopen_payload_mismatch'}}
 $report.payload_verified=$true
 $module=Import-Module (Join-Path $root 'Ufw.SessionJournal.psm1') -Force -PassThru -ErrorAction Stop
 Write-Host 'Reopening ONE existing preparation session read-only. Keep network and SSTP unchanged.'
 Write-Host 'No consent prompt, journal creation/repair or Apply/Restore is requested.'
 $report.stage='readonly_reopen_and_compare'
 $report.validation=& $module {param($entry). $entry;Invoke-UfwReadOnlyReopen} (Join-Path $root 'ReopenEntry.ps1')
 $report.code=$report.validation.code
 if($report.validation.completed){$report.completed=$true;$report.stage='completed';$rc=0}
 Write-Host ('Read-only validation result: '+$report.code)
}catch{
 $msg=[string]$_.Exception.GetBaseException().Message
 if($msg -cmatch '^(ufw_reopen|ufw_journal|ufw_core|ufw_read)_[a-z_0-9]{1,100}$'){$report.code=$msg}else{$report.code='ufw_reopen_unavailable'}
 Write-Host ('Stopped at '+$report.stage+': '+$report.code)
}finally{
 if($null -ne $module){Remove-Module $module.Name -Force -ErrorAction SilentlyContinue}
 if($null -ne $dest){try{$bytes=[Text.Encoding]::UTF8.GetBytes(($report|ConvertTo-Json -Depth 24));$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Host ('Report: '+$dest)}catch{Write-Host 'Report could not be saved. Return only the stage/code text.';$rc=1}}
 Write-Host 'Return only the NEW UFW-REOPEN-SESSION-01-*.json, including failure.'
 Write-Host 'Do NOT send protected journal files, screenshots, or transcripts.'
 Write-Host 'This is NOT isolation, normal-mode restoration, reboot qualification or a no-leak certificate.'
}
exit $rc
