param([string]$Helper)
$ErrorActionPreference='Stop';. $Helper
$cases=@(@('D:\Games\WoW\_retail_\Wow.exe','D:\WLabSnapshot'),@('e:\Wow.exe','E:\WLabSnapshot'),@('C:\Games\Wow.exe','C:\WLabSnapshot'),@('F:/Games/Wow.exe','F:\WLabSnapshot'))
foreach($case in $cases){if((Get-WLabGameOutputRoot $case[0]) -cne $case[1]){throw 'Wrong output drive'}}
foreach($bad in @('', 'Wow.exe','D:Wow.exe','\\server\share\Wow.exe')){
$rejected=$false;try{[void](Get-WLabGameOutputRoot $bad)}catch{$rejected=$true};if(!$rejected){throw 'Unsupported path accepted'}
}
# Compile real native declaration on this OS; do not call kernel32 on Linux.
Initialize-WLabDiskApi
if($null -eq ('WLab.DiskSpaceNative' -as [type])){throw 'Native declaration not compiled'}
$script:queried=''
function Invoke-WLabNativeDiskQuery([string]$queryPath){
$script:queried=$queryPath
return [pscustomobject]@{status='succeeded';available_bytes=[UInt64]17179869184;total_bytes=[UInt64]100000000000;total_free_bytes=[UInt64]20000000000;win32_error_code=0;error=$null}
}
$q=Get-WLabOutputSpace 'G:\WLabSnapshot\run'
if($script:queried -cne 'G:\WLabSnapshot\run\'){throw 'Did not query actual output directory'}
if((Get-WLabSpaceGate $q 8GB) -ne 'sufficient'){throw '16 GiB should pass'}
# Intentionally incorrect legacy provider result must not override native result.
function Get-PSDrive {param($Name,$ErrorAction) return [pscustomobject]@{Free=0}}
$d=Get-WLabLegacySpaceDiagnostics 'G:\WLabSnapshot\run'
if($d.psdrive_free_bytes -ne 0 -or (Get-WLabSpaceGate $q 8GB) -ne 'sufficient'){throw 'Provider zero affected native gate'}
$q.available_bytes=[UInt64]0
if((Get-WLabSpaceGate $q 8GB) -ne 'low'){throw 'Real zero was not low'}
$q.available_bytes=[UInt64](8GB)
if((Get-WLabSpaceGate $q 8GB) -ne 'sufficient'){throw '8 GiB boundary failed'}
$q.available_bytes=[UInt64]((8GB)-1)
if((Get-WLabSpaceGate $q 8GB) -ne 'low'){throw 'Below 8 GiB boundary failed'}
$q.available_bytes=[UInt64](1GB)
if((Get-WLabSpaceGate $q 1GB) -ne 'sufficient'){throw '1 GiB boundary failed'}
$q.available_bytes=[UInt64]((1GB)-1)
if((Get-WLabSpaceGate $q 1GB) -ne 'low'){throw 'Below 1 GiB boundary failed'}
foreach($bad in @($null,'0',[double]16,[long]-1)){
$q.available_bytes=$bad
if((Get-WLabSpaceGate $q 8GB) -ne 'unknown'){throw 'Invalid bytes were coerced'}
}
function Invoke-WLabNativeDiskQuery([string]$queryPath){return [pscustomobject]@{status='failed';available_bytes=$null;total_bytes=$null;total_free_bytes=$null;win32_error_code=5;error='mock access denied'}}
$q=Get-WLabOutputSpace 'G:\WLabSnapshot\run'
if($q.win32_error_code -ne 5 -or (Get-WLabSpaceGate $q 8GB) -ne 'unknown'){throw 'Win32 error lost or coerced'}
function Invoke-WLabNativeDiskQuery([string]$queryPath){throw 'mock native exception'}
$q=Get-WLabOutputSpace 'G:\WLabSnapshot\run'
if($q.status -ne 'query_error' -or $q.error -notmatch 'mock native exception' -or (Get-WLabSpaceGate $q 8GB) -ne 'unknown'){throw 'Native exception lost or coerced'}
[pscustomobject]@{drive_mapping_cases_passed=4;unsupported_paths_rejected=4;native_declaration_compiled=$true;actual_output_directory_passed_to_native_boundary=$true;native_16_GiB_not_overridden_by_legacy_zero=$true;real_zero_classified_low=$true;boundary_cases_passed=4;invalid_numeric_cases_rejected=4;win32_error_preserved_as_unknown=$true;native_exception_preserved_as_unknown=$true;native_Windows_API_executed=$false;windows_volume_write_tested=$false}|ConvertTo-Json
