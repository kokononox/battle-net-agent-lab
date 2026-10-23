function Initialize-WLabDiskApi{
if($null -eq ('WLab.DiskSpaceNative' -as [type])){
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace WLab {
 public static class DiskSpaceNative {
  [DllImport("kernel32.dll", EntryPoint="GetDiskFreeSpaceExW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool GetDiskFreeSpaceEx(string path, out ulong availableToCaller, out ulong totalBytes, out ulong totalFreeBytes);
 }
}
'@
}
}
function Invoke-WLabNativeDiskQuery([string]$queryPath){
Initialize-WLabDiskApi
[UInt64]$available=0;[UInt64]$total=0;[UInt64]$totalFree=0
$ok=[WLab.DiskSpaceNative]::GetDiskFreeSpaceEx($queryPath,[ref]$available,[ref]$total,[ref]$totalFree)
if(!$ok){
$code=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
$message=(New-Object ComponentModel.Win32Exception($code)).Message
return [pscustomobject]@{status='failed';available_bytes=$null;total_bytes=$null;total_free_bytes=$null;win32_error_code=$code;error=$message}
}
return [pscustomobject]@{status='succeeded';available_bytes=$available;total_bytes=$total;total_free_bytes=$totalFree;win32_error_code=0;error=$null}
}
function Get-WLabOutputSpace([string]$runPath){
$queryPath=$runPath.TrimEnd([char[]]'\/')+'\'
try{
if($runPath -notmatch '^[A-Za-z]:[\\/]'){throw 'Output path has no absolute local drive letter.'}
$r=Invoke-WLabNativeDiskQuery $queryPath
return [pscustomobject]@{status=$r.status;path=$queryPath;source='Win32 GetDiskFreeSpaceExW on actual output directory';available_bytes=$r.available_bytes;total_bytes=$r.total_bytes;total_free_bytes=$r.total_free_bytes;win32_error_code=$r.win32_error_code;error=$r.error;queried_utc=[DateTime]::UtcNow.ToString('o')}
}catch{
return [pscustomobject]@{status='query_error';path=$queryPath;source='Win32 GetDiskFreeSpaceExW on actual output directory';available_bytes=$null;total_bytes=$null;total_free_bytes=$null;win32_error_code=$null;error=$_.Exception.Message;queried_utc=[DateTime]::UtcNow.ToString('o')}
}
}
function Get-WLabSpaceGate($query,[long]$minimum){
# Null, failed queries and noninteger output are not zero bytes or success.
if($null -eq $query -or $query.status -ne 'succeeded' -or $null -eq $query.available_bytes){return 'unknown'}
$value=$query.available_bytes
if(($value -isnot [UInt64]) -and ($value -isnot [long]) -and ($value -isnot [int])){return 'unknown'}
if($value -lt 0){return 'unknown'}
if($value -lt $minimum){return 'low'}
return 'sufficient'
}
function Get-WLabLegacySpaceDiagnostics([string]$runPath){
# Diagnostic-only: do not select a larger reading to override the native gate.
$d=[ordered]@{psdrive_free_bytes=$null;psdrive_error=$null;dotnet_available_bytes=$null;dotnet_total_free_bytes=$null;dotnet_error=$null}
try{$drive=Get-PSDrive -Name $runPath.Substring(0,1) -ErrorAction Stop;$d.psdrive_free_bytes=$drive.Free}catch{$d.psdrive_error=$_.Exception.Message}
try{$info=New-Object IO.DriveInfo($runPath.Substring(0,3));$d.dotnet_available_bytes=$info.AvailableFreeSpace;$d.dotnet_total_free_bytes=$info.TotalFreeSpace}catch{$d.dotnet_error=$_.Exception.Message}
return [pscustomobject]$d
}
