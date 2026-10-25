param([Parameter(Mandatory=$true)][string]$Config)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$c=Read-Context $Config
$since=[DateTime]::Parse([string]$c.observation_start_utc).ToUniversalTime()
$r=@{schema='windows_tls_events_v1';scope='vm_time_window_not_process_attribution';logging_changed=$false;logs=@()}
foreach($spec in @(@{log='System';provider='Schannel';label='schannel_system'},@{log='Microsoft-Windows-CAPI2/Operational';provider='Microsoft-Windows-CAPI2';label='capi2_operational'})){
 $entry=@{source=$spec.label;enabled=$false;query_complete=$false;status='unavailable';events=@();limited=$false}
 try{
  $info=Get-WinEvent -ListLog $spec.log -ErrorAction Stop
  $entry.enabled=[bool]$info.IsEnabled
  if(-not $entry.enabled){$entry.status='disabled';$r.logs+=@($entry);continue}
  $events=@()
  try{$events=@(Get-WinEvent -FilterHashtable @{LogName=$spec.log;ProviderName=$spec.provider;StartTime=$since} -MaxEvents 65 -ErrorAction Stop)}catch{
   if([string]$_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$events=@()}else{throw}
  }
  $entry.limited=($events.Count -gt 64)
  foreach($event in @($events | Select-Object -First 64)){
   $x=[xml]$event.ToXml();$codes=@();$alerts=@();$states=@()
   foreach($node in @($x.SelectNodes('//*'))){
    $label=[string]$node.LocalName
    if($label -eq 'Data' -and $node.HasAttribute('Name')){$label=[string]$node.GetAttribute('Name')}
    $value=if($node.HasAttribute('value')){[string]$node.GetAttribute('value')}else{[string]$node.InnerText}
    if($label -in @('ErrorCode','ErrorStatus','Status','Result','HRESULT') -and $value -match '^(?:0x)?[0-9a-fA-F]{8}$'){$codes+=('0x'+($value -replace '^0x','').ToLowerInvariant())}
    if($label -in @('AlertDesc','AlertDescription') -and $value -match '^[0-9]{1,3}$' -and [int]$value -le 255){$alerts+=[int]$value}
    if($label -in @('ErrorState','InternalErrorState') -and $value -match '^[0-9]{1,5}$' -and [int]$value -le 65535){$states+=[int]$value}
   }
   $entry.events+=@(@{event_id=[int]$event.Id;level=if($null -eq $event.Level){0}else{[int]$event.Level};codes=@($codes | Sort-Object -Unique | Select-Object -First 16);alert_descriptions=@($alerts | Sort-Object -Unique | Select-Object -First 8);internal_states=@($states | Sort-Object -Unique | Select-Object -First 8)})
  }
  $entry.query_complete=$true;$entry.status='queried'
 }catch{$entry.status='query_failed'}
 $r.logs+=@($entry)
}
Save-Private (Join-Path $c.root 'windows-tls-events.json') $r
