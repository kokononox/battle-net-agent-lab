param([ValidateSet('Window','Disable','UiSmoke')][string]$Action='Window',[switch]$Elevated)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$log=Join-Path $PSScriptRoot 'startup-error.json'
$required=@('Run.ps1','ConfigCore.ps1','Policy.ps1','Overlay.ps1','Ranges.ps1','Journal.ps1','Inventory.ps1','Preflight.ps1')
function WriteStartupFailure([string]$Code,$Err){
 $line=0;$file='launcher';$kind='StartupValidation'
 if($null -ne $Err){
  $line=[int]$Err.InvocationInfo.ScriptLineNumber;$kind=$Err.Exception.GetType().Name
  $f=[IO.Path]::GetFileName([string]$Err.InvocationInfo.ScriptName)
  if($f -cin $required -or $f -ceq 'Launcher.ps1'){$file=$f}
 }
 $report=[pscustomobject][ordered]@{schema='sstp-startup-error-1';code=$Code;exception_type=$kind;file=$file;line=$line;powershell=$PSVersionTable.PSVersion.ToString();process_bits=([IntPtr]::Size*8);apartment=[Threading.Thread]::CurrentThread.GetApartmentState().ToString()}
 $text=ConvertTo-Json -InputObject $report -Depth 4
 try{[IO.File]::WriteAllText($log,$text,(New-Object Text.UTF8Encoding($false)))}catch{}
 [Console]::WriteLine($text)
}
try{
 foreach($f in $required){if(-not [IO.File]::Exists((Join-Path $PSScriptRoot $f))){WriteStartupFailure ('startup_missing_'+$f.Replace('.','_')) $null;exit 1}}
 if([IO.File]::Exists($log)){[IO.File]::Delete($log)}
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=New-Object Security.Principal.WindowsPrincipal($identity)
 if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  if($Elevated){throw 'startup_admin_required'}
  $exe=Join-Path $PSHOME 'powershell.exe'
  $child=Start-Process -FilePath $exe -Verb RunAs -WindowStyle Normal -Wait -PassThru -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',('"'+$PSCommandPath+'"'),'-Action',$Action,'-Elevated')
  if($child.ExitCode -ne 0){
   if([IO.File]::Exists($log)){[Console]::WriteLine([IO.File]::ReadAllText($log))}else{WriteStartupFailure 'startup_child_failed' $null}
   exit 1
  }
  exit 0
 }
 $global:LASTEXITCODE=0
 & (Join-Path $PSScriptRoot 'Run.ps1') -Action $Action
 if($LASTEXITCODE -ne 0){
  if([IO.File]::Exists($log)){[Console]::WriteLine([IO.File]::ReadAllText($log))}else{WriteStartupFailure 'startup_ui_failed' $null}
  exit 1
 }
 exit 0
}catch{
 $code='startup_failed';if($_.Exception.Message -cmatch '^startup_[a-z_0-9]{1,80}$'){$code=$_.Exception.Message}
 WriteStartupFailure $code $_
 exit 1
}
