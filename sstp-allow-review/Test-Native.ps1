param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'AllowReview.ps1')
$script:checks=0
function Check($Value){if(-not $Value){throw 'audit_native_check'};$script:checks++}
function Ipv6RegistryToken {
 $p=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -ErrorAction Stop
 $prop=$p.PSObject.Properties['DisabledComponents'];if($null -eq $prop){return 'absent'};return [string]$prop.Value
}
$r=[ordered]@{schema='sstp-allow-native-test-1';passed=$false;checks=0;firewall_strict_equal=$false;hosts_equal=$false;ipv6_registry_equal=$false;overlay_directory_presence_equal=$false;launcher_admin_path_tested=$false;launcher_nonadmin_uac_tested=$false;user_device_tested=$false;error_code=$null;child_error=$null}
try{
 $before=ReadPolicyInventory;$hosts=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts';$h=(Get-FileHash -LiteralPath $hosts -Algorithm SHA256).Hash;$ipv6=Ipv6RegistryToken
 $overlay=Join-Path $env:ProgramData 'SstpDestinationOverlayTest';$existed=[IO.Directory]::Exists($overlay)
 $dir=Join-Path $env:RUNNER_TEMP ('audit spaced '+[char]0x3A9+' '+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($dir)
 foreach($n in @('Read-Allows.ps1','AllowReview.ps1','AllowModel.ps1','Ranges.ps1','Inventory.ps1')){[IO.File]::Copy((Join-Path $PSScriptRoot $n),(Join-Path $dir $n))}
 $p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',('"'+(Join-Path $dir 'Read-Allows.ps1')+'"')) -WindowStyle Hidden -Wait -PassThru
 $done=$p.HasExited
 if(-not $done -or $p.ExitCode -ne 0){$ep=Join-Path $dir 'allow-review-error.json';if([IO.File]::Exists($ep)){$r.child_error=([IO.File]::ReadAllText($ep)|ConvertFrom-Json)}}
 Check ($done -and $p.ExitCode -eq 0);$r.launcher_admin_path_tested=$true
 $path=Join-Path $dir 'outbound-allow-report.json';Check ([IO.File]::Exists($path));Check ((Get-Item -LiteralPath $path).Length -lt 2200000)
 $text=[IO.File]::ReadAllText($path);$report=$text|ConvertFrom-Json
 Check ($report.schema -ceq 'sstp-outbound-allow-review-1');Check ($report.activation_approved -eq $false);Check ($report.outside_vpn_protection_certified -eq $false);Check ($report.network_settings_changed_by_tool -eq $false)
 Check ($report.rule_headers_unchanged_during_read -eq $true)
 Check (@($report.rows).Count -eq $report.summary.rule_count)
 Check ($report.raw_names_paths_addresses_exported -eq $false)
 Check ($report.summary.rule_count -le 1000)
 foreach($row in $report.rows){if($row.rule_id_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $row.image_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $row.is_proven_safe -ne $false -or $row.is_proven_leak -ne $false){throw 'allow_native_row'}}
 Check ($report.block_rules_and_conflict_precedence_fully_reviewed -eq $false)
 Check ($report.third_party_wfp_and_packets_tested -eq $false)
 Check (-not $text.Contains($env:USERNAME));Check (-not $text.Contains($env:COMPUTERNAME));Check (-not $text.Contains($env:USERPROFILE))
 $comparison=ComparePolicyInventory $before (ReadPolicyInventory);$r.firewall_strict_equal=$comparison.strict_equal;Check $r.firewall_strict_equal
 $r.hosts_equal=$h -ceq (Get-FileHash -LiteralPath $hosts -Algorithm SHA256).Hash;Check $r.hosts_equal
 $r.ipv6_registry_equal=$ipv6 -ceq (Ipv6RegistryToken);Check $r.ipv6_registry_equal
 $r.overlay_directory_presence_equal=$existed -eq [IO.Directory]::Exists($overlay);Check $r.overlay_directory_presence_equal
 $r.passed=$true
}catch{$r.error_code='audit_native_failed';[Console]::Error.WriteLine('audit_test_line_'+$_.InvocationInfo.ScriptLineNumber+'_type_'+$_.Exception.GetType().Name)}finally{
 $r.checks=$script:checks;if($OutputPath){[IO.File]::WriteAllText($OutputPath,($r|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))}
}
$r|ConvertTo-Json
if(-not $r.passed){exit 1};exit 0
