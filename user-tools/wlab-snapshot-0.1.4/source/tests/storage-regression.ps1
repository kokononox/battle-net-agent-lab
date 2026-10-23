param([string]$Helper)
$ErrorActionPreference='Stop';. $Helper
$cases=@(
@('D:\Games\World of Warcraft\_retail_\Wow.exe','D:\WLabSnapshot'),
@('e:\Wow.exe','E:\WLabSnapshot'),
@('C:\Games\Wow.exe','C:\WLabSnapshot'),
@('F:/Games/Wow.exe','F:\WLabSnapshot'))
foreach($case in $cases){if((Get-WLabGameOutputRoot $case[0]) -cne $case[1]){throw ('Wrong output: '+$case[0])}}
foreach($bad in @('', 'Wow.exe','D:Wow.exe','\\server\share\Wow.exe')){
$rejected=$false;try{[void](Get-WLabGameOutputRoot $bad)}catch{$rejected=$true};if(!$rejected){throw 'Unsupported path did not fail closed'}
}
# Exercise the actual free-space helper with a mock provider; no disks changed.
function Get-PSDrive {param($Name,$ErrorAction) if($Name -ne 'D'){throw 'Wrong drive queried'};return [pscustomobject]@{Free=[long]17179869184}}
if((Get-WLabOutputFreeBytes 'D:\WLabSnapshot\run') -ne [long]17179869184){throw 'Wrong free byte value'}
function Get-PSDrive {param($Name,$ErrorAction) return [pscustomobject]@{Free=$null}}
$rejected=$false;try{[void](Get-WLabOutputFreeBytes 'D:\WLabSnapshot\run')}catch{$rejected=$true};if(!$rejected){throw 'Unknown free space accepted'}
[pscustomobject]@{drive_mapping_cases_passed=4;unsupported_paths_rejected=4;free_space_selected_drive_mock_passed=$true;unknown_free_space_rejected=$true;windows_volume_write_tested=$false}|ConvertTo-Json
