param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Inventory.ps1')
$script:checks=0
function Check($Value){if(-not $Value){throw ('startup_check_'+($script:checks+1))};$script:checks++}
$dir=Join-Path $env:RUNNER_TEMP ('sstp startup '+[char]0x0622+[char]0x0632+' '+[guid]::NewGuid().ToString('N'))
$receipt=[ordered]@{schema='sstp-visible-startup-test-1';passed=$false;checks=0;error_code=$null;spaced_unicode_path_tested=$false;ui_smoke_passed=$false;missing_dependency_reported=$false;syntax_error_reported=$false;module_error_reported=$false;policy_code_changed=$false;unrelated_policy_equal=$false;foreign_display_changes=-1;uac_nonadmin_path_tested=$false;user_device_tested=$false}
$before=$null
function Launch {
 $out=Join-Path $dir 'stdout.txt';$err=Join-Path $dir 'stderr.txt'
 $p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',('"'+(Join-Path $dir 'Launcher.ps1')+'"'),'-Action','UiSmoke') -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden -Wait -PassThru
 [pscustomobject]@{code=$p.ExitCode;text=[IO.File]::ReadAllText($out)}
}
try{
 $expected=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'base-policy-sha256.json')))
 foreach($item in $expected.PSObject.Properties){
  $text=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $item.Name)).Replace("`r`n","`n")
  $sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  Check ($hash -ceq $item.Value)
 }
 $before=ReadPolicyInventory
 $null=[IO.Directory]::CreateDirectory($dir)
 foreach($f in Get-ChildItem $PSScriptRoot -Filter '*.ps1'){[IO.File]::Copy($f.FullName,(Join-Path $dir $f.Name))}
 $originalRun=[IO.File]::ReadAllText((Join-Path $dir 'Run.ps1'));$originalCore=[IO.File]::ReadAllText((Join-Path $dir 'ConfigCore.ps1'))
 $r=Launch;Check ($r.code -eq 0);Check ($r.text.Contains('overlay_ui_smoke_ok'));Check (-not [IO.File]::Exists((Join-Path $dir 'startup-error.json')))
 $receipt.ui_smoke_passed=$true;$receipt.spaced_unicode_path_tested=$true
 [IO.File]::Delete((Join-Path $dir 'Preflight.ps1'))
 $r=Launch;Check ($r.code -eq 1)
 $e=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $dir 'startup-error.json')))
 Check ($e.code -ceq 'startup_missing_Preflight_ps1');Check ($r.text.Contains('startup_missing_Preflight_ps1'))
 $receipt.missing_dependency_reported=$true
 [IO.File]::Copy((Join-Path $PSScriptRoot 'Preflight.ps1'),(Join-Path $dir 'Preflight.ps1'))
 [IO.File]::WriteAllText((Join-Path $dir 'Run.ps1'),'if (')
 $r=Launch;Check ($r.code -eq 1)
 $e=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $dir 'startup-error.json')))
 Check ($e.code -ceq 'startup_failed');Check ($e.exception_type -ceq 'ParseException')
 $receipt.syntax_error_reported=$true
 [IO.File]::WriteAllText((Join-Path $dir 'Run.ps1'),$originalRun,(New-Object Text.UTF8Encoding($false)))
 [IO.File]::WriteAllText((Join-Path $dir 'ConfigCore.ps1'),"throw 'startup_fixture_module_error'")
 $r=Launch;Check ($r.code -eq 1)
 $e=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $dir 'startup-error.json')))
 Check ($e.schema -ceq 'sstp-startup-error-1');Check ($e.code -ceq 'overlay_operation_failed');Check ($e.file -ceq 'ConfigCore.ps1');Check ($e.line -eq 1)
 Check ((@($e.PSObject.Properties.Name|Sort-Object)-join ',') -ceq 'apartment,code,exception_type,file,line,powershell,process_bits,schema')
 $receipt.module_error_reported=$true
 [IO.File]::WriteAllText((Join-Path $dir 'ConfigCore.ps1'),$originalCore,(New-Object Text.UTF8Encoding($false)))
 $r=Launch;Check ($r.code -eq 0)
 $cmp=ComparePolicyInventory $before (ReadPolicyInventory)
 Check $cmp.policy_equal;$receipt.unrelated_policy_equal=$cmp.policy_equal;$receipt.foreign_display_changes=$cmp.display_rule_changes
 $receipt.passed=$true
}catch{
 $receipt.error_code='startup_test_failed'
 if($_.Exception.Message -cmatch '^startup_[a-z_0-9]{1,80}$'){$receipt.error_code=$_.Exception.Message}
 [Console]::Error.WriteLine('startup_test_line_'+$_.InvocationInfo.ScriptLineNumber+'_type_'+$_.Exception.GetType().Name)
}finally{
 if([IO.Directory]::Exists($dir)){[IO.Directory]::Delete($dir,$true)}
 $receipt.checks=$script:checks
 if($OutputPath){[IO.File]::WriteAllText($OutputPath,($receipt|ConvertTo-Json -Depth 4),(New-Object Text.UTF8Encoding($false)))}
}
$receipt|ConvertTo-Json -Depth 4
if(-not $receipt.passed){exit 1};exit 0
