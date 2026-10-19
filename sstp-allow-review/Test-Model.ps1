param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'AllowModel.ps1')
$script:checks=0
function Check($Value){if(-not $Value){throw 'allow_model_check'};$script:checks++}
$r=[ordered]@{schema='sstp-allow-model-test-1';passed=$false;checks=0;network_settings_changed=$false}
try{
 Check ((AllowHash 'test').Length -eq 64);Check ((AllowHash 'test') -ceq (AllowHash 'test'))
 Check (AllowAny 'Any');Check (-not (AllowAny @('Any','other')));Check (-not (AllowAny $null))
 Check ((AllowEnum 'unknown_private' @('Local','GroupPolicy')) -ceq 'Unknown')
 $scope=AllowScope 'RemoteAccess' @('Any');Check $scope.remote_access_type_only;Check (-not $scope.candidate_for_non_vpn_review)
 $scope=AllowScope 'Any' @('secret_adapter');Check $scope.candidate_for_non_vpn_review;Check (-not (($scope|ConvertTo-Json -Depth 4).Contains('secret_adapter')))
 $scope=AllowScope 'Wired, Wireless' @('Any');Check (-not $scope.remote_access_type_only);Check ($scope.interface_types.Count -eq 2)
 $scope=AllowScope 'NewUnknownKind' @('Any');Check $scope.candidate_for_non_vpn_review;Check (($scope.interface_types -join ',') -ceq 'Unknown')
 Check ((AllowPorts @('53','443','1000-2000','Any','secret_value')) -join ',' -ceq '53,443,1000-2000,Any,Unknown')
 Check ((AllowBool $true) -eq $true);Check ((AllowBool $false) -eq $false);Check ($null -eq (AllowBool 0));Check ($null -eq (AllowBool 1));Check ($null -eq (AllowBool 'NotConfigured'))
 $p=AllowProgram ([pscustomobject]@{Program='Any';Package='Any'});Check ($p.kind -ceq 'any');Check (-not $p.package_restricted)
 $p=AllowProgram ([pscustomobject]@{Program='C:\PrivateUsername\secret.exe';Package='private_package_sid'});$text=$p|ConvertTo-Json;Check $p.package_restricted;Check (-not $text.Contains('PrivateUsername'));Check (-not $text.Contains('secret.exe'));Check (-not $text.Contains('private_package_sid'))
 $ctx=[pscustomobject]@{server=@{'32:16843009'=$true};dns=@{'32:134744072'=$true}}
 $a=AllowAddresses @('1.1.1.1','8.8.8.8','10.0.0.0/8','192.0.2.1-192.0.2.9','LocalSubnet','private.example','::1','Any') $ctx
 Check ($a.entry_count -eq 8);Check ($a.matching_saved_legacy_server_entries -eq 1);Check ($a.matching_current_dns_server_entries -eq 1);Check ($a.cidr_entries -eq 1);Check ($a.range_entries -eq 1);Check ($a.unparsed_entries -eq 1)
 $text=$a|ConvertTo-Json;Check (-not $text.Contains('1.1.1.1'));Check (-not $text.Contains('private.example'));Check ($a.addresses_sha256.Length -eq 64)
 $a=AllowAddresses @('Any') ([pscustomobject]@{server=$null;dns=$null});Check $a.any;Check ($a.unparsed_entries -eq 0)
 $r.passed=$true
}finally{$r.checks=$script:checks;if($OutputPath){[IO.File]::WriteAllText($OutputPath,($r|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))}}
$r|ConvertTo-Json
if(-not $r.passed){exit 1};exit 0
