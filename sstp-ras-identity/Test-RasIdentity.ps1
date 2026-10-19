param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. "$PSScriptRoot/Policy.ps1"
$script:checks=0;$passed=$false;$errorCode=$null;$enumAvailable=$false;$enumCode=$null;$enumCount=$null;$roundtrip=$false;$sdkVerified=$false
function Check([bool]$Ok) { if(-not $Ok) { throw 'binding_test_assertion' };$script:checks++ }
function GoodObservation {
 $o=NewRasIdentityObservation
 foreach($k in $o.PSObject.Properties.Name) { $o.$k=$true }
 foreach($k in @('active_sstp_count','ras_profile_guid_match_count','projection_ip_matching_interfaces')) { $o.$k=1 }
 return $o
}
try {
 $tokens=$null;$errors=$null
 foreach($f in @('Policy.ps1','Inspect-RasIdentity.ps1')) {
  [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $f),[ref]$tokens,[ref]$errors) | Out-Null
  Check ($errors.Count -eq 0)
 }
 Add-Type -Path "$PSScriptRoot/RasIdentity.cs" -ErrorAction Stop
 $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
 $vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
 if($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vs)) { throw 'binding_sdk_compiler_unavailable' }
 $sdkExe=Join-Path $env:RUNNER_TEMP 'sstp-abi-probe.exe';$sdkObj=Join-Path $env:RUNNER_TEMP 'sstp-abi-probe.obj';$sdkLog=Join-Path $env:RUNNER_TEMP 'sstp-abi-compile.log';$batch=Join-Path $env:RUNNER_TEMP 'sstp-abi-compile.cmd'
 $vc=Join-Path $vs 'Common7\Tools\VsDevCmd.bat';$source=Join-Path $PSScriptRoot 'AbiProbe.cpp'
 $commands="@echo off`r`ncall `"$vc`" -arch=x64 -host_arch=x64 >nul 2>&1`r`nif errorlevel 1 exit /b 1`r`ncl.exe /nologo /EHsc /W4 /WX /Fe:`"$sdkExe`" /Fo:`"$sdkObj`" `"$source`" >`"$sdkLog`" 2>&1`r`nexit /b %errorlevel%`r`n"
 [IO.File]::WriteAllText($batch,$commands,[Text.Encoding]::ASCII)
 & $batch
 if($LASTEXITCODE -ne 0) { throw 'binding_sdk_compile_failed' }
 $text=& $sdkExe
 if($LASTEXITCODE -ne 0) { throw 'binding_sdk_probe_failed' };$abi=$text | ConvertFrom-Json
 Write-Host ('binding_abi_ras_sdk_'+$abi.ras_size+'_managed_'+[SstpIdentityV1.Native]::RasSize)
 Check ($abi.ras_size -eq [SstpIdentityV1.Native]::RasSize)
 Check ($abi.projection_size -eq [SstpIdentityV1.Native]::ProjectionSize)
 Check ($abi.entry_name_offset -eq [SstpIdentityV1.Native]::Offset('EntryName'))
 Check ($abi.entry_guid_offset -eq [SstpIdentityV1.Native]::Offset('EntryGuid'))
 Check ($abi.logon_luid_offset -eq [SstpIdentityV1.Native]::Offset('LogonLuidLow'))
 Check ($abi.correlation_offset -eq [SstpIdentityV1.Native]::Offset('CorrelationGuid'))
 Check ($abi.all_users_mask -eq [SstpIdentityV1.Native]::AllUsersMask)
 Check ($abi.projection_kind -eq [SstpIdentityV1.Native]::ProjectionKind)
 Check ($abi.ppp_type -eq [SstpIdentityV1.Native]::PppIfType -and $abi.ppp_type -eq [int][Net.NetworkInformation.NetworkInterfaceType]::Ppp)
 $sdkVerified=$true
 Check ((GetRasIdentityDecision (GoodObservation)) -eq 'identity_chain_observed')
 $cases=@(
  @('profile_inventory_complete',$false,'profile_inventory_incomplete'),
  @('active_sstp_count',0,'no_unique_active_sstp'),@('active_sstp_count',2,'no_unique_active_sstp'),
  @('profile_guid_unique',$false,'profile_guid_unavailable_or_ambiguous'),
  @('ras_inventory_available',$false,'ras_inventory_unavailable'),
  @('ras_profile_guid_match_count',0,'ras_entry_guid_not_unique'),@('ras_profile_guid_match_count',2,'ras_entry_guid_not_unique'),
  @('ras_name_matches',$false,'ras_entry_metadata_conflict'),@('ras_scope_matches',$false,'ras_entry_metadata_conflict'),@('ras_device_is_vpn',$false,'ras_entry_metadata_conflict'),
  @('ras_session_marker_available',$false,'ras_session_marker_unavailable'),@('projection_ipv4_available',$false,'projection_ipv4_unavailable'),
  @('projection_ip_matching_interfaces',0,'projection_address_not_unique'),@('projection_ip_matching_interfaces',2,'projection_address_not_unique'),
  @('candidate_is_ppp',$false,'candidate_not_up_ppp'),@('candidate_operational_up',$false,'candidate_not_up_ppp'),
  @('interface_index_luid_guid_roundtrip',$false,'interface_identifier_mismatch'),@('connection_stable_on_recheck',$false,'connection_changed_during_read')
 )
 foreach($case in $cases) { $o=GoodObservation;$o.($case[0])=$case[1];Check ((GetRasIdentityDecision $o) -eq $case[2]) }
 $o=GoodObservation;$o.alias_equal_to_profile_name=$false
 Check ((GetRasIdentityDecision $o) -eq 'identity_chain_observed')
 $o=GoodObservation;$o.projection_ipv4_available='True'
 Check ((GetRasIdentityDecision $o) -eq 'invalid_observation_schema')
 $o=GoodObservation;$o.active_sstp_count='1'
 Check ((GetRasIdentityDecision $o) -eq 'invalid_observation_schema')
 $o=GoodObservation;$o | Add-Member extra $true
 Check ((GetRasIdentityDecision $o) -eq 'invalid_observation_schema')
 $zeroHandle=$false;try { [SstpIdentityV1.Native]::ProjectionIPv4([IntPtr]::Zero) | Out-Null } catch { $zeroHandle=$true };Check $zeroHandle
 $zeroIndex=$false;try { [SstpIdentityV1.Native]::InterfaceFromIndex(0) | Out-Null } catch { $zeroIndex=$true };Check $zeroIndex
 # Actual native metadata reads, no dial, DNS, credentials, policy or traffic probe.
 $nics=@([SstpIdentityV1.Native]::Adapters());Check ($nics.Count -gt 0)
 $id=[SstpIdentityV1.Native]::InterfaceFromIndex($nics[0].Index)
 Check ($id.Guid -eq $nics[0].Guid -and $id.NetLuid -ne 0);$roundtrip=$true
 try { $ras=@([SstpIdentityV1.Native]::Enumerate());$enumAvailable=$true;$enumCount=$ras.Count }
 catch {
  $m=$_.Exception.GetBaseException().Message
  if($m -match '^ras_enum_api_([0-9]+)$') { $enumCode=[int]$Matches[1] } else { throw }
 }
 # A runner with no usable RAS service is recorded as unavailable, never as zero live tunnels.
 Check ($enumAvailable -or $null -ne $enumCode)
 Check ($script:checks -eq 39)
 $passed=$true
} catch {
 $errorCode='binding_native_failure';Write-Host ('RAS identity test failed after '+$script:checks+' checks.')
 $m=$_.Exception.GetBaseException().Message
 if($m -match '^binding_[a-z_0-9]+$') { Write-Host $m } else { Write-Host ('binding_provider_failure_'+$_.Exception.GetType().Name.ToLowerInvariant()) }
} finally {
 $receipt=[ordered]@{schema='sstp-ras-identity-test-1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;passed=$passed;checks=$script:checks;error_code=$errorCode;sdk_abi_verified=$sdkVerified;native_iphelper_roundtrip_tested=$roundtrip;ras_enumeration_available=$enumAvailable;ras_enumeration_error_code=$enumCode;ras_enumerated_connection_count=$enumCount;live_sstp_projection_tested=$false;user_identity_chain_tested=$false;network_policy_changed=$false;dns_queried=$false;credentials_read=$false;resident_program_created=$false;firewall_filter_binding_qualified=$false;enforcement_tested=$false;ready_for_user_apply=$false}
 [IO.File]::WriteAllText($OutputPath,($receipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
}
if(-not $passed) { exit 1 };exit 0
