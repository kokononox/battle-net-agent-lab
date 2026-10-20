param([ValidateSet('Window','Restore')][string]$Action='Window',[switch]$Elevated,[string]$InvokingSid)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$out=Join-Path $PSScriptRoot 'operation-result.json'
function WriteAppOutcome($Report){[IO.File]::WriteAllText($out,($Report|ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($false)))}
try{
 if($env:OS -cne 'Windows_NT' -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'app_windows_powershell51_x64_required'}
 if([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA'){throw 'app_sta_required'}
 $manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw|ConvertFrom-Json
 $required=@('App-Core.ps1','ConfigCore.ps1','Policy.ps1','Identity.ps1','IdentityPolicy.ps1','RasIdentity.cs','Overlay.ps1','Ranges.ps1','Journal.ps1','Inventory.ps1','Restore.ps1','Window.ps1','Start.ps1','seed.json')
 foreach($name in $required){if($manifest.files.PSObject.Properties.Name -cnotcontains $name){throw 'app_manifest_incomplete'}}
 foreach($f in $manifest.files.PSObject.Properties){
  if($f.Name -match '[/\\:]'){throw 'app_manifest_path'}
  $file=Join-Path $PSScriptRoot $f.Name
  if(-not [IO.File]::Exists($file) -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $f.Value){throw 'app_package_mismatch'}
 }
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 if($Elevated -and ($InvokingSid -cnotmatch '^S-1-5-[0-9-]+$' -or $id.User.Value -cne $InvokingSid)){throw 'app_same_user_elevation_required'}
 $principal=New-Object Security.Principal.WindowsPrincipal($id)
 if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  if($Elevated){throw 'app_admin_required'}
  $child=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -Wait -PassThru -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',('"'+$PSCommandPath+'"'),'-Action',$Action,'-Elevated','-InvokingSid',$id.User.Value)
  exit $child.ExitCode
 }
 . (Join-Path $PSScriptRoot 'App-Core.ps1')
 $root=AppRoot;$lock=AppLock $root
 try{$null=InitializeAppConfig $root}finally{$lock.Dispose()}
 Add-Type -AssemblyName System.Windows.Forms
 if($Action -ceq 'Restore'){
  $answer=[Windows.Forms.MessageBox]::Show('Remove only this app''s exact VPN destination restrictions? Existing kill-switch rules stay unchanged. No VPN connection is required.','Restore whitelist only','YesNo','Warning')
  if($answer -ne 'Yes'){exit 0}
  $report=RestoreApp $root;WriteAppOutcome $report
  if($report.passed){[Windows.Forms.MessageBox]::Show('Whitelist rules removed. Existing firewall and kill switch were not reset.','Restored')|Out-Null;exit 0}
  throw $report.code
 }
 . (Join-Path $PSScriptRoot 'Window.ps1')
 ShowAppWindow $root
 exit 0
}catch{
 $code='app_startup_failed';if($_.Exception.Message -cmatch '^(app|overlay|journal|inventory|policy|tool)_[a-z_0-9]{1,90}$'){$code=$_.Exception.Message}
 $report=[ordered]@{schema='sstp-whitelist-app-startup-1';version='0.1.2';passed=$false;code=$code;file=[IO.Path]::GetFileName([string]$_.InvocationInfo.ScriptName);line=[int]$_.InvocationInfo.ScriptLineNumber;full_requested_protection_ready=$false;no_reset_performed=$true}
 try{[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'startup-error.json'),($report|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))}catch{}
 try{Add-Type -AssemblyName System.Windows.Forms;[Windows.Forms.MessageBox]::Show(($code+"`r`nSend startup-error.json. No reset was performed."),'Whitelist startup error')|Out-Null}catch{}
 [Console]::Error.WriteLine($code);exit 1
}
