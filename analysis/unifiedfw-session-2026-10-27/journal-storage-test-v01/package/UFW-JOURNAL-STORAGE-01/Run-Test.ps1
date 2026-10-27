$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$report=[ordered]@{schema='ufw-journal-storage-diagnostic-01';completed=$false;stage='platform_guard';code='';powershell_version=[string]$PSVersionTable.PSVersion;is_64bit=[Environment]::Is64BitProcess;payload_verified=$false;qualification=$null;scope='synthetic_disposable_journal_only';real_legacy_journal_access_requested=$false;real_preparation_record_created=$false;profile_query_requested=$false;firewall_change_requested=$false;VPN_change_requested=$false;DNS_query_generated=$false;ready_for_apply=$false;no_leak_certified=$false}
$dest=$null;$rc=1;$module=$null
try{
 $root=[IO.Path]::GetFullPath($PSScriptRoot);$p=$root
 if($root.StartsWith('\')){throw 'ufw_storage_local_folder_required'}
 while($p){if(([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'ufw_storage_reparse_path'};$q=[IO.Path]::GetDirectoryName($p);if($p -eq $q){break};$p=$q}
 $dest=Join-Path $root ('UFW-JOURNAL-STORAGE-01-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.json')
 if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'ufw_storage_windows_required'}
 if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1 -or -not [Environment]::Is64BitProcess){throw 'ufw_storage_ps51_x64_required'}
 $who=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ufw_storage_admin_required'}
 $report.stage='payload_guard'
 $hashes=ConvertFrom-Json @'
{
  "Ufw.ProfileReader.psm1": "ddd2575ddc177e6e4eedd67c14a1aa7b1bfe17723cea973d6648f7582f788bcc",
  "Ufw.InstallerCore.psm1": "c072f580e20864053870f32c2560bba9fc973b7a28ffca76423af618d7d575cb",
  "Ufw.SessionJournal.psm1": "968085dda94525faba1292a9d3e0ff15e41d3dd14827e13b5c1c3d17b0050d72",
  "StorageFixture.ps1": "8b3f011e77e8f54fd6bbddaf547c4f354a665edc4472092d209d33c940269b38"
}
'@
 foreach($item in $hashes.PSObject.Properties){$file=Join-Path $root $item.Name;if(([IO.File]::GetAttributes($file) -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $item.Value){throw 'ufw_storage_payload_mismatch'}}
 $report.payload_verified=$true;. (Join-Path $root 'StorageFixture.ps1')
 $module=Import-Module (Join-Path $root 'Ufw.SessionJournal.psm1') -Force -PassThru -ErrorAction Stop
 Write-Host 'STORAGE ONLY: synthetic private files in a separate disposable ProgramData folder.'
 Write-Host 'No real journal, firewall profile, rule, task, VPN, DNS or route will be accessed by this test.'
 Write-Host 'No consent to isolation or real session-record creation is requested.'
 $report.stage='disposable_storage_fixture';$report.qualification=Invoke-UfwJournalStorageFixture $module
 if(-not $report.qualification.completed -or -not $report.qualification.cleanup_completed -or -not $report.qualification.native_Windows_file_API_executed){throw 'ufw_storage_qualification_not_passed'}
 $report.completed=$true;$report.stage='completed';$report.code='ufw_storage_fixture_passed_no_apply';$rc=0
}catch{
 $msg=[string]$_.Exception.GetBaseException().Message
 if($msg -cmatch '^(ufw_storage|ufw_fixture|ufw_journal|ufw_core|ufw_read)_[a-z_0-9]{1,100}$'){$report.code=$msg}else{$report.code='ufw_storage_unavailable'}
 Write-Host ('Stopped at '+$report.stage+': '+$report.code)
}finally{
 if($null -ne $module){Remove-Module $module.Name -Force -ErrorAction SilentlyContinue}
 if($null -ne $dest){try{$bytes=[Text.Encoding]::UTF8.GetBytes(($report|ConvertTo-Json -Depth 24));$f=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Host ('Report: '+$dest)}catch{Write-Host 'Report could not be saved. Return only the stage/code text.';$rc=1}}
 Write-Host 'Return only the new UFW-JOURNAL-STORAGE-01-*.json, including failure.'
 Write-Host 'This is NOT a firewall, SSTP reconnect, original Restore, reboot or no-leak qualification.'
}
exit $rc
