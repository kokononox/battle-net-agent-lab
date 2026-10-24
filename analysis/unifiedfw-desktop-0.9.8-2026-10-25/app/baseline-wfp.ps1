# Read-only WFP event attribution. Never infer an exited process from a reused PID.
function Get-WfpDevicePath([string]$Path){
 if(-not ('UnifiedAudit096.Native' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'audit-native.cs')}
 return [UnifiedAudit096.Native]::DevicePath($Path)
}
function Resolve-BaselineWfp([long]$ProcessId,[string]$Application,[DateTime]$EventTime){
 try{
  $proc=Get-Process -Id $ProcessId -ErrorAction Stop
  $path=[string]$proc.Path;$birth=$proc.StartTime.ToUniversalTime().Ticks.ToString()
  if(-not $path -or -not $Application){return $null}
  if($Application -ine $path){
   $device=Get-WfpDevicePath $path
   if(-not $device -or $Application -ine $device){return $null}
  }
  $row=Register-NewProcess $ProcessId $birth $path ($EventTime.ToUniversalTime().ToString('o')) 'WFP_event'
  if($null -eq $row){return $null}
  return [pscustomobject]@{program=$script:autoPrograms[$path.ToLowerInvariant()];birth=$birth}
 }catch{return $null}
}
